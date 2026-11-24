use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::abi;
use crate::boot;
use crate::buildguard;
use crate::gate;
use crate::merge_intel;
use crate::util::*;

// ------------------------------------------------------------ range helpers

fn parse_ver_tag(tag: &str) -> Option<(String, u64)> {
    let b = tag.as_bytes();
    let mut i = b.len();
    while i > 0 && b[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i == 0 || i == b.len() {
        return None;
    }
    let n = tag[i..].parse::<u64>().ok()?;
    Some((tag[..i].to_string(), n))
}

fn ref_exists(ctx: &Ctx, r: &str) -> bool {
    git_rc(ctx, &["rev-parse", "--verify", "--quiet", r]).0 == 0
}

fn is_ancestor(ctx: &Ctx, anc: &str, desc: &str) -> bool {
    git_rc(ctx, &["merge-base", "--is-ancestor", anc, desc]).0 == 0
}

/// Auto-detect the pre-merge commit on HEAD's first-parent line right before `<from>..<to>` started landing.
pub fn detect_pre_merge_base(ctx: &Ctx, from: &str, to: &str) -> Option<String> {
    let out = git(ctx, &["log", "--first-parent", "-n", "400", "--format=%H %P", "HEAD"]);
    let mut earliest_parent: Option<String> = None;
    for ln in out.lines() {
        let parts: Vec<&str> = ln.split_whitespace().collect();
        if parts.len() >= 3 {
            let p1 = parts[1];
            let p2 = parts[2];
            // Is p2 an upstream tag/commit inside (from..to] ?
            if is_ancestor(ctx, p2, to) && !is_ancestor(ctx, p2, from) {
                earliest_parent = Some(p1.to_string());
            } else if earliest_parent.is_some() {
                break;
            }
        }
    }
    earliest_parent
}

// ------------------------------------------------------ 1. merge-chain & hygiene

struct ChainReport {
    ok: bool,
    summary: String,
}

fn check_merge_chain(ctx: &Ctx, from: Option<&str>, to: Option<&str>, base: &str) -> ChainReport {
    println!("=== merge-chain & hygiene ({base}..HEAD) ===");
    let mut issues = 0usize;

    // 1a. Verify intermediate version tags if from/to share prefix (e.g. v6.6.152 -> v6.6.162)
    let mut tag_info = String::new();
    if let (Some(f), Some(t)) = (from, to) {
        let head_mk_ver = fs::read_to_string(ctx.repo.join("Makefile"))
            .ok()
            .and_then(|txt| {
                let (mut v, mut p, mut s) = (String::new(), String::new(), String::new());
                for ln in txt.lines().take(15) {
                    let tr = ln.trim();
                    if let Some(x) = tr.strip_prefix("VERSION =") { v = x.trim().to_string(); }
                    else if let Some(x) = tr.strip_prefix("PATCHLEVEL =") { p = x.trim().to_string(); }
                    else if let Some(x) = tr.strip_prefix("SUBLEVEL =") { s = x.trim().to_string(); }
                }
                if !v.is_empty() && !p.is_empty() && !s.is_empty() {
                    Some(format!("v{v}.{p}.{s}"))
                } else {
                    None
                }
            });
        let single_parent_merge3 = !is_ancestor(ctx, t, "HEAD")
            && head_mk_ver.as_deref() == Some(t);
        if single_parent_merge3 {
            println!("  merge3: HEAD Makefile matches {t} (single-parent 3-way merge)");
            tag_info = format!("merge3={t}");
        } else {
            if !is_ancestor(ctx, t, "HEAD") {
                println!("  !! TARGET NOT MERGED: {t} is NOT an ancestor of HEAD");
                issues += 1;
            }
            if let (Some((pf, nf)), Some((pt, nt))) = (parse_ver_tag(f), parse_ver_tag(t)) {
                if pf == pt && nt > nf && nt - nf <= 200 {
                    let mut total = 0usize;
                    let mut merged = 0usize;
                    let mut missing = Vec::new();
                    for n in (nf + 1)..=nt {
                        let tg = format!("{pf}{n}");
                        if ref_exists(ctx, &tg) {
                            total += 1;
                            if is_ancestor(ctx, &tg, "HEAD") {
                                merged += 1;
                            } else {
                                missing.push(tg);
                            }
                        }
                    }
                    if !missing.is_empty() {
                        println!("  !! MISSING INTERMEDIATE TAGS: {}", missing.join(", "));
                        issues += missing.len();
                    } else if total > 0 {
                        println!("  tags: {merged}/{total} intermediate tags ({pf}{}..{pf}{nt}) are ancestors of HEAD", nf + 1);
                    }
                    tag_info = format!("{merged}/{total} tags");
                }
            }
        }
    }

    // 1b. Walk first-parent commits in base..HEAD: GPG sigs + merge conflict counts
    let rng = format!("{base}..HEAD");
    let log = git(
        ctx,
        &["log", "--first-parent", "--reverse", "--format=%H%x1f%h%x1f%G?%x1f%P%x1f%s", &rng],
    );
    let mut total_commits = 0usize;
    let mut signed_ok = 0usize;
    let mut unsigned_list = Vec::new();
    let mut merge_commits = Vec::new();

    for ln in log.lines() {
        let p: Vec<&str> = ln.splitn(5, '\x1f').collect();
        if p.len() < 5 {
            continue;
        }
        total_commits += 1;
        let (full, short, sig, parents, subj) = (p[0], p[1], p[2], p[3], p[4]);
        if sig == "G" || sig == "U" {
            signed_ok += 1;
        } else {
            unsigned_list.push(format!("{short} ({sig}) {subj}"));
        }
        if parents.split_whitespace().count() >= 2 {
            merge_commits.push((full.to_string(), short.to_string(), subj.to_string()));
        }
    }

    if !merge_commits.is_empty() {
        // Compute --cc conflict-resolution file counts in parallel
        let cc_counts: Vec<(usize, usize)> = par_map(&merge_commits, ctx.threads.min(8), |(sha, _, _)| {
            let out = git(ctx, &["diff-tree", "--cc", "--name-only", "-r", "--no-commit-id", sha]);
            let mut total_f = 0usize;
            let mut built_f = 0usize;
            for f in out.lines().filter(|s| !s.trim().is_empty()) {
                total_f += 1;
                if is_built_file(ctx, f) {
                    built_f += 1;
                }
            }
            (total_f, built_f)
        });
        println!("  merge commits ({}):", merge_commits.len());
        for ((_, short, subj), (tot, blt)) in merge_commits.iter().zip(cc_counts.iter()) {
            println!("    {short}  cc:{tot:<2} ({blt} built)  {subj}");
        }
    }

    if !unsigned_list.is_empty() {
        println!("  !! UNSIGNED/BAD GPG ({}/{}):", unsigned_list.len(), total_commits);
        for u in unsigned_list.iter().take(10) {
            println!("    {u}");
        }
        issues += unsigned_list.len();
    } else {
        println!("  commits: {signed_ok}/{total_commits} first-parent commits GPG-signed (G)");
    }

    // 1c. Hygiene: stray .orig/.rej, dirty state, bindings symlink
    let st = git(ctx, &["status", "--porcelain"]);
    let mut junk = Vec::new();
    for ln in st.lines() {
        let path = ln.get(3..).unwrap_or("").trim();
        if path.ends_with(".orig") || path.ends_with(".rej") {
            junk.push(path.to_string());
        }
    }
    if !junk.is_empty() {
        println!("  !! LEFTOVER .orig/.rej: {}", junk.join(", "));
        issues += junk.len();
    }
    if ctx.is_default_kernel {
        let base_bindings = git(ctx, &["ls-tree", base, BINDINGS]);
        if base_bindings.starts_with("120000 ") {
            let bp = ctx.repo.join(BINDINGS);
            let ok_link = fs::symlink_metadata(&bp)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if !ok_link {
                println!("  !! BROKEN SYMLINK: {BINDINGS} is not a symlink");
                issues += 1;
            }
        }
    }

    let summary = if tag_info.is_empty() {
        format!("{signed_ok}/{total_commits} signed, {} merges", merge_commits.len())
    } else {
        format!("{tag_info}, {signed_ok}/{total_commits} signed, {} merges", merge_commits.len())
    };
    ChainReport { ok: issues == 0, summary }
}

// ------------------------------------ 2. dup-scan (macros, dup stmts, lock balance)

pub(crate) fn parse_added_lines_by_file(diff: &str) -> HashMap<String, HashSet<usize>> {
    let mut map: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut cur_file: Option<String> = None;
    let mut new_line = 0usize;

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur_file = Some(p.trim().to_string());
        } else if ln.starts_with("@@ ") {
            // @@ -a,b +c,d @@
            if let Some(plus_idx) = ln.find('+') {
                let after = &ln[plus_idx + 1..];
                let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                new_line = num_str.parse().unwrap_or(0);
            }
        } else if ln.starts_with('+') && !ln.starts_with("+++") {
            if let Some(ref f) = cur_file {
                map.entry(f.clone()).or_default().insert(new_line);
            }
            new_line += 1;
        } else if !ln.starts_with('-') && !ln.starts_with('\\') && !ln.starts_with("diff ") && !ln.starts_with("index ") {
            if cur_file.is_some() && new_line > 0 {
                new_line += 1;
            }
        }
    }
    map
}

fn parse_define_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let after_hash = t.strip_prefix('#')?.trim_start();
    let rest = after_hash.strip_prefix("define")?;
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let name_part = rest.trim_start();
    let b = name_part.as_bytes();
    if b.is_empty() || !is_ident_start(b[0]) {
        return None;
    }
    let mut i = 0;
    while i < b.len() && is_ident_char(b[i]) {
        i += 1;
    }
    Some(name_part[..i].to_string())
}

fn parse_undef_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let after_hash = t.strip_prefix('#')?.trim_start();
    let rest = after_hash.strip_prefix("undef")?;
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let name_part = rest.trim_start();
    let b = name_part.as_bytes();
    if b.is_empty() || !is_ident_start(b[0]) {
        return None;
    }
    let mut i = 0;
    while i < b.len() && is_ident_char(b[i]) {
        i += 1;
    }
    Some(name_part[..i].to_string())
}

fn is_candidate_dup_stmt(trim: &str) -> bool {
    if trim.len() < 16 || !trim.ends_with(';') {
        return false;
    }
    if !(trim.contains('(') || trim.contains('=')) {
        return false;
    }
    if trim.starts_with("//")
        || trim.starts_with("/*")
        || trim.starts_with('*')
        || trim.starts_with('#')
        || trim.starts_with("case ")
        || trim.starts_with("default:")
        || trim.starts_with("return ")
        || trim.starts_with("goto ")
        || trim.starts_with("break")
        || trim.starts_with("continue")
        || trim.starts_with("pr_")
        || trim.starts_with("dev_")
        || trim.starts_with("printk")
        || trim.starts_with("seq_")
        || trim.starts_with("trace_")
        || trim.starts_with("WARN_")
        || trim.starts_with("BUG_")
        || trim.starts_with("MODULE_")
        || trim.starts_with("EXPORT_")
        || trim.starts_with("static ")
        || trim.starts_with("const ")
        || trim.starts_with("struct ")
        || trim.starts_with("enum ")
        || trim.starts_with("typedef ")
        || trim.starts_with("extern ")
        || trim.starts_with("udelay")
        || trim.starts_with("ndelay")
        || trim.starts_with("mdelay")
        || trim.starts_with("msleep")
        || trim.starts_with("barrier")
        || trim.starts_with("smp_")
        || trim.starts_with("mb(")
        || trim.starts_with("rmb(")
        || trim.starts_with("wmb(")
        || trim.starts_with("writel")
        || trim.starts_with("readl")
        || trim.starts_with("iowrite")
        || trim.starts_with("ioread")
        || trim.starts_with("regmap_write")
        || trim.starts_with("regmap_update")
        || trim.starts_with("outb")
        || trim.starts_with("inb")
        || trim.starts_with("put_user")
        || trim.starts_with("get_user")
        || trim.starts_with("skb_put")
        || trim.starts_with("nla_put")
        || trim.starts_with("buf[")
        || trim.starts_with("data[")
        || trim.contains("++")
        || trim.contains("--")
        || trim.contains("+=")
        || trim.contains("-=")
        || trim.contains("<<")
        || trim.contains(">>")
    {
        return false;
    }
    // Skip pop/consume/next style calls where repeating twice is intentional
    for ok_rep in [
        "_next(", "_pop(", "_pop_", "consume_", "advance_", "skip_", "read_", "write_",
        "put_", "_put(", "get_", "kfree(", "fput(", "dput(", "iput(", "kref_put(", "pop_",
        "push_", "emit_", "append_", "add_tail", "add_head", "wait_for_", "schedule(",
        "cond_resched(", "yield(", "flush_", "drain_", "sync_",
    ] {
        if trim.contains(ok_rep) {
            return false;
        }
    }
    true
}

struct DupScanFileHit {
    dup_macros: Vec<String>,
    dup_funcs: Vec<String>,
    dup_stmts: Vec<String>,
    dup_labels: Vec<String>,
    dup_locals: Vec<String>,
    macro_shadows: Vec<String>,
    added_structs: Vec<(String, String, usize)>,
    lock_regressions: Vec<String>,
}

/// Detect fallthrough error-cleanup labels executing the exact same cleanup statement twice!
/// Catches silent merge bugs like:
///   err_del_dev:
///       device_del(&mhi_cntrl->mhi_dev->dev);
///   err_release_dev:
///       device_del(&mhi_cntrl->mhi_dev->dev);
fn is_c_goto_label(trim: &str) -> bool {
    let Some(name) = trim.strip_suffix(':') else {
        return false;
    };
    if name.is_empty()
        || name == "default"
        || name.starts_with("case ")
        || name.contains(' ')
        || name.contains('\t')
        || name.contains('(')
        || name.contains('?')
    {
        return false;
    }
    let b = name.as_bytes();
    is_ident_start(b[0]) && b.iter().all(|&c| is_ident_char(c))
}

pub(crate) fn scan_dup_fallthrough_labels(
    path: &str,
    lines: &[&str],
    added: &HashSet<usize>,
) -> Vec<String> {
    let mut hits = Vec::new();
    let mut idx = 0usize;
    while idx < lines.len() {
        let trim = strip_c_comments(lines[idx]).trim();
        if !is_c_goto_label(trim) {
            idx += 1;
            continue;
        }
        let lbl1 = trim;
        // Collect first non-empty cleanup statements under lbl1 (up to 4 lines) until next label or control transfer
        let mut stmts1: Vec<(usize, String)> = Vec::new();
        let mut next_lbl_idx: Option<usize> = None;
        let mut broke = false;
        let mut j = idx + 1;
        while j < lines.len() && j <= idx + 6 {
            let t = strip_c_comments(lines[j]).trim();
            if t.is_empty() || t.starts_with('#') {
                j += 1;
                continue;
            }
            if is_c_goto_label(t) {
                next_lbl_idx = Some(j);
                break;
            }
            if t.starts_with("return")
                || t.starts_with("goto ")
                || t.starts_with("break;")
                || t.starts_with("continue;")
                || t.starts_with('}')
            {
                broke = true;
                break;
            }
            if t.ends_with(';') && t.len() >= 10 && t.contains('(') {
                stmts1.push((j + 1, t.to_string()));
            }
            j += 1;
        }
        if !broke && !stmts1.is_empty() {
            if let Some(l2_idx) = next_lbl_idx {
                let lbl2 = strip_c_comments(lines[l2_idx]).trim();
                let mut k = l2_idx + 1;
                while k < lines.len() && k <= l2_idx + 5 {
                    let t2 = strip_c_comments(lines[k]).trim();
                    if t2.is_empty() || t2.starts_with('#') {
                        k += 1;
                        continue;
                    }
                    if is_c_goto_label(t2)
                        || t2.starts_with("return")
                        || t2.starts_with("goto ")
                        || t2.starts_with('}')
                    {
                        break;
                    }
                    let lno2 = k + 1;
                    if let Some((lno1, _)) = stmts1.iter().find(|(_, s)| s == t2) {
                        if added.contains(lno1) || added.contains(&lno2) {
                            hits.push(format!(
                                "{path}:L{lno1}/L{lno2}: fallthrough {lbl1} -> {lbl2} repeats `{}`",
                                truncate_str(t2, 72)
                            ));
                        }
                    }
                    k += 1;
                }
            }
        }
        idx += 1;
    }
    hits
}

/// Parse a simple local variable declaration at function top level (`\tint i;`, `\tu32 val = 0;`, `\tstruct foo *p;`).
fn parse_simple_local_var(raw: &str) -> Option<String> {
    // Only single-tab indented top-level function locals
    if !raw.starts_with('\t') || raw.starts_with("\t\t") {
        return None;
    }
    let code = strip_c_comments(raw).trim();
    if !code.ends_with(';') || code.contains('(') || code.contains(',') || code.starts_with("static ") || code.starts_with("extern ") || code.starts_with("typedef ") {
        return None;
    }
    // Strip `= init` if present
    let lhs = code.trim_end_matches(';').split('=').next()?.trim();
    let toks: Vec<&str> = lhs.split_whitespace().collect();
    if toks.len() < 2 {
        return None;
    }
    let first = toks[0];
    let is_type_start = matches!(
        first,
        "int"
            | "unsigned"
            | "signed"
            | "long"
            | "short"
            | "char"
            | "bool"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "s8"
            | "s16"
            | "s32"
            | "s64"
            | "size_t"
            | "ssize_t"
            | "loff_t"
            | "phys_addr_t"
            | "dma_addr_t"
            | "gfp_t"
            | "irqreturn_t"
            | "struct"
            | "enum"
            | "const"
    );
    if !is_type_start {
        return None;
    }
    let last = toks.last()?.trim_start_matches('*');
    if last.is_empty() || last.contains('[') || last.contains(']') {
        return None;
    }
    let b = last.as_bytes();
    if !is_ident_start(b[0]) || !b.iter().all(|&c| is_ident_char(c)) {
        return None;
    }
    if C_KEYWORDS.contains(&last) {
        return None;
    }
    Some(last.to_string())
}

/// Detect duplicate local variable declarations in the same function & preprocessor branch (e.g. `int i; ... int i;`).
pub(crate) fn scan_dup_local_decls(
    path: &str,
    lines: &[&str],
    added: &HashSet<usize>,
) -> Vec<String> {
    let mut hits = Vec::new();
    let mut brace_depth = 0i32;
    let mut bstack: Vec<(usize, usize)> = Vec::new();
    let mut ng = 1usize;
    let mut seen: HashMap<(String, Vec<(usize, usize)>), usize> = HashMap::new();
    let mut in_blk = false;

    for (idx, raw) in lines.iter().enumerate() {
        let lno = idx + 1;
        let t = raw.trim();
        if in_blk {
            if t.contains("*/") {
                in_blk = false;
            }
            continue;
        }
        if t.starts_with("/*") && !t.contains("*/") {
            in_blk = true;
            continue;
        }
        if let Some(ah) = t.strip_prefix('#') {
            let d = ah.trim_start();
            if d.starts_with("if ") || d.starts_with("if(") || d.starts_with("ifdef") || d.starts_with("ifndef") {
                bstack.push((ng, 0));
                ng += 1;
            } else if d.starts_with("elif") || d.starts_with("else") {
                if let Some(top) = bstack.last_mut() {
                    top.1 += 1;
                }
            } else if d.starts_with("endif") {
                bstack.pop();
            }
            continue;
        }

        let code = strip_c_comments(raw);
        let opens = code.bytes().filter(|&c| c == b'{').count() as i32;
        let closes = code.bytes().filter(|&c| c == b'}').count() as i32;

        if brace_depth == 1 && opens == 0 && closes == 0 {
            if let Some(vname) = parse_simple_local_var(raw) {
                let key = (vname.clone(), bstack.clone());
                if let Some(&prev) = seen.get(&key) {
                    if added.contains(&lno) || added.contains(&prev) {
                        hits.push(format!(
                            "{path}:L{prev} & L{lno}: duplicate local declaration `{vname}`"
                        ));
                    }
                } else {
                    seen.insert(key, lno);
                }
            }
        }

        let prev_depth = brace_depth;
        brace_depth = (brace_depth + opens - closes).max(0);
        if (prev_depth == 0 && brace_depth == 1) || brace_depth == 0 {
            seen.clear();
        }
    }
    hits
}

/// Extract col-0 `struct <name> {` definition name from a `.c` line.
fn parse_col0_struct_def(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix("struct ")?;
    let mut i = 0;
    let b = rest.as_bytes();
    while i < b.len() && is_ident_char(b[i]) {
        i += 1;
    }
    if i < 5 {
        return None;
    }
    let after = strip_c_comments(&rest[i..]).trim();
    if after == "{" {
        Some(rest[..i].to_string())
    } else {
        None
    }
}

const LOCK_PAIRS: &[(&str, &str, &str)] = &[
    ("preempt", "preempt_disable", "preempt_enable"),
    ("rcu", "rcu_read_lock", "rcu_read_unlock"),
    ("srcu", "srcu_read_lock", "srcu_read_unlock"),
    ("irq_disable", "local_irq_disable", "local_irq_enable"),
];

fn count_word_calls(text: &str, prefix: &str) -> usize {
    let mut n = 0usize;
    for ln in text.lines() {
        let code = strip_c_comments(ln);
        let mut pos = 0;
        while let Some(rel) = code[pos..].find(prefix) {
            let idx = pos + rel;
            let left_ok = idx == 0 || !is_ident_char(code.as_bytes()[idx - 1]);
            if left_ok {
                // Ensure it's a call (identifier followed by '(')
                let mut end = idx + prefix.len();
                let b = code.as_bytes();
                while end < b.len() && is_ident_char(b[end]) {
                    end += 1;
                }
                let ident = &code[idx..end];
                // Skip *_held, *_notrace_*, *_count, etc. unless exact or _notrace/_bh/_sched
                let valid_suffix = ident == prefix
                    || ident == format!("{prefix}_notrace")
                    || ident == format!("{prefix}_bh")
                    || ident == format!("{prefix}_sched");
                if valid_suffix {
                    let mut j = end;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b'(' {
                        n += 1;
                    }
                }
            }
            pos = idx + prefix.len();
        }
    }
    n
}

pub fn cmd_dup_scan(ctx: &Ctx, base: &str, head: &str, all_files: bool) -> i32 {
    let (rc, _) = run_dup_scan(ctx, base, head, None, all_files);
    rc
}

fn run_dup_scan(
    ctx: &Ctx,
    base: &str,
    head: &str,
    up_to: Option<&str>,
    all_files: bool,
) -> (i32, String) {
    println!("=== dup-scan: duplicate macros, dup statements & lock balance ({base}..{head}) ===");
    let diff = git(ctx, &["diff", "-U0", base, head, "--", "*.c", "*.h"]);
    let added_map = parse_added_lines_by_file(&diff);

    // If upstream target ref is known, files byte-identical to upstream cannot have merge bugs
    let diff_vs_up: Option<HashSet<String>> = up_to.map(|t| {
        git(ctx, &["diff", "--name-only", t, head])
            .lines()
            .map(|s| s.to_string())
            .collect()
    });

    // Collect conflict-resolved (--cc) files in base..head for lock-balance checking
    let cc_out = git(ctx, &["log", "--first-parent", "--merges", "--cc", "--name-only", "--format=", &format!("{base}..{head}")]);
    let cc_files: HashSet<String> = cc_out
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && is_c_source(s))
        .collect();

    let mut files: Vec<String> = added_map
        .keys()
        .filter(|f| {
            is_c_source(f)
                && (all_files || is_built_file(ctx, f))
                && diff_vs_up.as_ref().map_or(true, |set| set.contains(*f))
        })
        .cloned()
        .collect();
    files.sort();

    let results: Vec<DupScanFileHit> = par_map(&files, ctx.threads, |path| {
        let mut hit = DupScanFileHit {
            dup_macros: Vec::new(),
            dup_funcs: Vec::new(),
            dup_stmts: Vec::new(),
            dup_labels: Vec::new(),
            dup_locals: Vec::new(),
            macro_shadows: Vec::new(),
            added_structs: Vec::new(),
            lock_regressions: Vec::new(),
        };
        let full = ctx.repo.join(path);
        let Ok(text) = fs::read_to_string(&full) else {
            return hit;
        };
        let added = match added_map.get(path) {
            Some(s) => s,
            None => return hit,
        };
        let lines: Vec<&str> = text.lines().collect();

        // Collect sibling header macro aliases for `.c` files (catches CLO macro-aliased functions!)
        let mut sibling_macro_aliases: HashMap<String, String> = HashMap::new();
        if path.ends_with(".c") {
            if let Some(dir) = full.parent() {
                if let Ok(rd) = fs::read_dir(dir) {
                    for ent in rd.flatten() {
                        let p = ent.path();
                        if p.extension().and_then(|e| e.to_str()) == Some("h") {
                            if let Ok(htxt) = fs::read_to_string(&p) {
                                let hname = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                                for hln in htxt.lines() {
                                    let t = hln.trim();
                                    if let Some(ah) = t.strip_prefix('#') {
                                        if let Some(rest) = ah.trim_start().strip_prefix("define") {
                                            if rest.starts_with(|c: char| c.is_ascii_whitespace()) {
                                                let parts: Vec<&str> = rest.split_whitespace().collect();
                                                // Object-like alias `#define foo bar` (no `(` attached to foo)
                                                if parts.len() == 2
                                                    && !parts[0].contains('(')
                                                    && parts[0].len() >= 8
                                                    && parts[0].bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                                                    && parts[1].bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                                                {
                                                    sibling_macro_aliases.insert(parts[0].to_string(), format!("{hname} -> {}", parts[1]));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2a. Duplicate #define in same preprocessor branch (where >=1 was added in base..head)
        let mut branch_stack: Vec<(usize, usize)> = Vec::new();
        let mut next_group = 1usize;
        // key: (macro_name, branch_path) -> first 1-based line
        let mut seen_defs: HashMap<(String, Vec<(usize, usize)>), usize> = HashMap::new();
        let mut in_block_comment = false;

        for (idx, raw) in lines.iter().enumerate() {
            let lno = idx + 1;
            let t = raw.trim();
            if in_block_comment {
                if t.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }
            if t.starts_with("/*") && !t.contains("*/") {
                in_block_comment = true;
                continue;
            }
            if let Some(after_hash) = t.strip_prefix('#') {
                let d = after_hash.trim_start();
                if d.starts_with("if ") || d.starts_with("if(") || d.starts_with("ifdef") || d.starts_with("ifndef") {
                    branch_stack.push((next_group, 0));
                    next_group += 1;
                } else if d.starts_with("elif") || d.starts_with("else") {
                    if let Some(top) = branch_stack.last_mut() {
                        top.1 += 1;
                    }
                } else if d.starts_with("endif") {
                    branch_stack.pop();
                } else if let Some(u) = parse_undef_name(raw) {
                    seen_defs.remove(&(u, branch_stack.clone()));
                } else if let Some(name) = parse_define_name(raw) {
                    // Ignore include guards (*_H, _LINUX_*, etc. with empty body)
                    let key = (name.clone(), branch_stack.clone());
                    if let Some(&prev_lno) = seen_defs.get(&key) {
                        if added.contains(&lno) || added.contains(&prev_lno) {
                            hit.dup_macros.push(format!("{path}:{prev_lno} & L{lno}: duplicate #define {name}"));
                        }
                    } else {
                        seen_defs.insert(key, lno);
                    }
                }
            }
        }

        // 2a-bis. Duplicate top-level C function definitions in same preprocessor branch (.c files)
        if path.ends_with(".c") {
            let mut bstack: Vec<(usize, usize)> = Vec::new();
            let mut ng = 1usize;
            let mut seen_fns: HashMap<(String, Vec<(usize, usize)>), usize> = HashMap::new();
            let mut in_blk = false;
            for (idx, raw) in lines.iter().enumerate() {
                let lno = idx + 1;
                let t = raw.trim();
                if in_blk {
                    if t.contains("*/") { in_blk = false; }
                    continue;
                }
                if t.starts_with("/*") && !t.contains("*/") { in_blk = true; continue; }
                if let Some(ah) = t.strip_prefix('#') {
                    let d = ah.trim_start();
                    if d.starts_with("if ") || d.starts_with("if(") || d.starts_with("ifdef") || d.starts_with("ifndef") {
                        bstack.push((ng, 0));
                        ng += 1;
                    } else if d.starts_with("elif") || d.starts_with("else") {
                        if let Some(top) = bstack.last_mut() { top.1 += 1; }
                    } else if d.starts_with("endif") {
                        bstack.pop();
                    }
                    continue;
                }
                // Column-0 C function definition followed by '{' on same or next 2 lines
                if raw.is_empty() || raw.as_bytes()[0].is_ascii_whitespace()
                    || matches!(raw.as_bytes()[0], b'/' | b'*' | b'{' | b'}')
                    || raw.starts_with("EXPORT_") || raw.starts_with("MODULE_")
                    || raw.starts_with("DEFINE_") || raw.starts_with("DECLARE_")
                    || raw.starts_with("TRACE_") || raw.starts_with("SYSCALL_")
                    || raw.starts_with("COMPAT_SYSCALL_")
                {
                    continue;
                }
                let code = strip_c_comments(raw).trim_end();
                if code.ends_with(';') || code.contains('=') {
                    continue;
                }
                let has_brace = code.ends_with('{')
                    || (idx + 1 < lines.len() && lines[idx + 1].trim_start().starts_with('{'))
                    || (idx + 2 < lines.len() && !lines[idx + 1].trim_end().ends_with(';') && lines[idx + 2].trim_start().starts_with('{'));
                if !has_brace {
                    continue;
                }
                if let Some(par) = code.find('(') {
                    let before = code[..par].trim_end();
                    let b = before.as_bytes();
                    let mut i = b.len();
                    while i > 0 && is_ident_char(b[i - 1]) { i -= 1; }
                    let fname = &before[i..];
                    let left = before[..i].trim();
                    if !left.is_empty() && fname.len() >= 4 && !C_KEYWORDS.contains(&fname) && !NOT_A_CALL.contains(&fname) {
                        if added.contains(&lno) {
                            if let Some(alias_info) = sibling_macro_aliases.get(fname) {
                                hit.macro_shadows.push(format!(
                                    "{path}:L{lno}: new function `{fname}()` is macro-aliased in sibling header ({alias_info})"
                                ));
                            }
                        }
                        let key = (fname.to_string(), bstack.clone());
                        if let Some(&prev) = seen_fns.get(&key) {
                            if added.contains(&lno) || added.contains(&prev) {
                                hit.dup_funcs.push(format!("{path}:L{prev} & L{lno}: duplicate function `{fname}()`"));
                            }
                        } else {
                            seen_fns.insert(key, lno);
                        }
                    }
                }
            }

            // 2d. Fallthrough duplicate error-cleanup labels (catches double device_del/kfree/unlock)
            hit.dup_labels = scan_dup_fallthrough_labels(path, &lines, added);

            // 2e. Duplicate top-level local variable declarations in function body (`int i; ... int i;`)
            hit.dup_locals = scan_dup_local_decls(path, &lines, added);

            // 2f. Collect newly added col-0 `struct foo {` in .c for batched include/ redefinition check
            for (idx, raw) in lines.iter().enumerate() {
                let lno = idx + 1;
                if added.contains(&lno) {
                    if let Some(sname) = parse_col0_struct_def(raw) {
                        hit.added_structs.push((sname, path.clone(), lno));
                    }
                }
            }
        }

        // 2b. Duplicate identical statements within 1..=3 lines at same indentation (when >=1 added in range)
        for (idx, raw) in lines.iter().enumerate() {
            let lno = idx + 1;
            let indent = raw.len() - raw.trim_start().len();
            let trim = strip_c_comments(raw).trim();
            if !is_candidate_dup_stmt(trim) {
                continue;
            }
            // Look ahead 1..=3 lines in same block
            let mut broke_block = false;
            for delta in 1..=3 {
                if idx + delta >= lines.len() {
                    break;
                }
                let next_raw = lines[idx + delta];
                let next_trim = strip_c_comments(next_raw).trim();
                if next_trim.is_empty() {
                    continue;
                }
                if next_trim.starts_with('}')
                    || next_trim.starts_with("else")
                    || next_trim.starts_with("case ")
                    || next_trim.starts_with("default:")
                    || next_trim.starts_with('#')
                    || next_trim.ends_with(':')
                {
                    broke_block = true;
                    break;
                }
                let next_indent = next_raw.len() - next_raw.trim_start().len();
                if next_indent == indent && next_trim == trim {
                    let next_lno = lno + delta;
                    if added.contains(&lno) || added.contains(&next_lno) {
                        hit.dup_stmts.push(format!(
                            "{path}:L{lno}/L{next_lno}: `{}`",
                            truncate_str(trim, 80)
                        ));
                    }
                    break;
                }
            }
            let _ = broke_block;
        }

        // 2c. Lock/preempt/rcu balance regression on --cc conflict-resolved .c files
        //     Compare against upstream target (when available) so legitimate upstream lock
        //     refactors don't false-positive, while mis-resolved merges still fire immediately!
        if path.ends_with(".c") && cc_files.contains(path) {
            let old_text = git(ctx, &["show", &format!("{base}:{path}")]);
            let up_text = up_to.map(|t| git(ctx, &["show", &format!("{t}:{path}")]));
            if !old_text.is_empty() {
                for &(label, acq, rel) in LOCK_PAIRS {
                    let old_diff = count_word_calls(&old_text, acq) as isize - count_word_calls(&old_text, rel) as isize;
                    let new_diff = count_word_calls(&text, acq) as isize - count_word_calls(&text, rel) as isize;
                    if new_diff.abs() > old_diff.abs() && new_diff != 0 {
                        let matches_up = up_text.as_ref().is_some_and(|ut| {
                            !ut.is_empty()
                                && (count_word_calls(ut, acq) as isize - count_word_calls(ut, rel) as isize)
                                    == new_diff
                        });
                        if !matches_up {
                            hit.lock_regressions.push(format!(
                                "{path}: {label} balance shifted ({acq}-{rel}: {old_diff:+} -> {new_diff:+})"
                            ));
                        }
                    }
                }
            }
        }

        hit
    });

    let mut macros = Vec::new();
    let mut funcs = Vec::new();
    let mut stmts = Vec::new();
    let mut labels = Vec::new();
    let mut locals = Vec::new();
    let mut shadows = Vec::new();
    let mut added_structs: Vec<(String, String, usize)> = Vec::new();
    let mut locks = Vec::new();
    for r in results {
        macros.extend(r.dup_macros);
        funcs.extend(r.dup_funcs);
        stmts.extend(r.dup_stmts);
        labels.extend(r.dup_labels);
        locals.extend(r.dup_locals);
        shadows.extend(r.macro_shadows);
        added_structs.extend(r.added_structs);
        locks.extend(r.lock_regressions);
    }

    // Batched cross-header check for `struct foo {` added in a .c file that already exists in include/
    let mut dup_structs = Vec::new();
    if !added_structs.is_empty() {
        let mut names: Vec<String> = added_structs.iter().map(|(n, _, _)| n.clone()).collect();
        names.sort();
        names.dedup();
        let mut hdr_map: HashMap<String, Vec<String>> = HashMap::new();
        for chunk in names.chunks(60) {
            let pat = format!(r"^struct\s+({})\s*\{{", chunk.join("|"));
            let (_, out) = rg(&ctx.repo, &["-n", "-g", "*.h", &pat, "include", "arch/arm64/include"]);
            for ln in out.lines() {
                let p: Vec<&str> = ln.splitn(3, ':').collect();
                if p.len() == 3 {
                    if let Some(sname) = parse_col0_struct_def(p[2]) {
                        hdr_map.entry(sname).or_default().push(format!("{}:{}", p[0], p[1]));
                    }
                }
            }
        }
        for (sname, cpath, lno) in &added_structs {
            if let Some(hlocs) = hdr_map.get(sname) {
                if let Ok(ctxt) = fs::read_to_string(ctx.repo.join(cpath)) {
                    for hloc in hlocs {
                        let hfile = hloc.split(':').next().unwrap_or("");
                        let hbase = Path::new(hfile)
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if !hbase.is_empty() && ctxt.contains(&hbase) {
                            dup_structs.push(format!(
                                "{cpath}:L{lno}: `struct {sname} {{` already defined in included header {hloc}"
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    println!(
        "    scanned {} modified files ({} --cc conflict-resolved)",
        files.len(),
        cc_files.len()
    );
    let total = macros.len()
        + funcs.len()
        + stmts.len()
        + labels.len()
        + locals.len()
        + shadows.len()
        + dup_structs.len()
        + locks.len();
    if total == 0 {
        println!("  clean: 0 dup macros/funcs/locals/structs/labels, 0 dup stmts, 0 lock-balance regressions");
        return (0, "0 dup macros/funcs/locals/structs/labels, 0 dup stmts, 0 lock regressions".into());
    }
    for m in &macros {
        println!("  DUP MACRO    {m}");
    }
    for f in &funcs {
        println!("  DUP FUNC     {f}");
    }
    for l in &labels {
        println!("  DUP LABEL    {l}");
    }
    for v in &locals {
        println!("  DUP LOCAL    {v}");
    }
    for s in &dup_structs {
        println!("  DUP STRUCT   {s}");
    }
    for ms in &shadows {
        println!("  MACRO SHADOW {ms}");
    }
    for s in &stmts {
        println!("  DUP STMT     {s}");
    }
    for l in &locks {
        println!("  LOCK DRIFT   {l}");
    }
    let hard_cnt = macros.len()
        + funcs.len()
        + labels.len()
        + locals.len()
        + dup_structs.len()
        + shadows.len()
        + locks.len();
    let msg = format!(
        "{} macro, {} func, {} label, {} local, {} struct, {} shadow, {} stmt, {} lock",
        macros.len(),
        funcs.len(),
        labels.len(),
        locals.len(),
        dup_structs.len(),
        shadows.len(),
        stmts.len(),
        locks.len()
    );
    (if hard_cnt == 0 { 0 } else { 1 }, msg)
}

// ------------------------------------ 3. struct-loss (vanished fields still used)

pub fn cmd_struct_loss(ctx: &Ctx, base: &str, head: &str, all_files: bool) -> i32 {
    let (rc, _) = run_struct_loss(ctx, base, head, all_files);
    rc
}

fn run_struct_loss(ctx: &Ctx, base: &str, head: &str, all_files: bool) -> (i32, String) {
    println!("=== struct-loss: vanished struct fields still referenced ({base}..{head}) ===");
    let diff = git(ctx, &["diff", "-U0", base, head, "--", "*.h", "*.c"]);

    // Collect every field declaration removed in base..head (ignoring generic names),
    // PLUS detect pointer-to-embedded conversions (`struct T *foo;` -> `struct T foo;`)!
    let mut removed_fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut ptr_removed: HashSet<String> = HashSet::new();
    let mut val_added: HashSet<String> = HashSet::new();
    let mut cur_file: Option<String> = None;

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur_file = Some(p.trim().to_string());
            continue;
        }
        let Some(ref path) = cur_file else { continue };
        if !is_c_source(path) || (!all_files && !is_built_file(ctx, path)) {
            continue;
        }
        // Only treat lines indented with tabs/spaces (struct members, not top-level globals)
        if let Some(rest) = ln.strip_prefix('-') {
            if rest.starts_with("--") || !rest.starts_with(|c: char| c == '\t' || c == ' ') || rest.contains('=') {
                continue;
            }
            if let Some(name) = gate::parse_removed_header_decl(ln) {
                if name.len() >= 5 && !GENERIC_MEMBERS.contains(&name.as_str()) {
                    if strip_c_comments(rest).contains(&format!("*{name}")) {
                        ptr_removed.insert(name.clone());
                    }
                    removed_fields.entry(name).or_default().insert(path.clone());
                }
            }
        } else if let Some(rest) = ln.strip_prefix('+') {
            if rest.starts_with("++") || !rest.starts_with(|c: char| c == '\t' || c == ' ') || rest.contains('=') {
                continue;
            }
            let fake_minus = format!("-{rest}");
            if let Some(name) = gate::parse_removed_header_decl(&fake_minus) {
                if name.len() >= 5 && !strip_c_comments(rest).contains('*') {
                    val_added.insert(name);
                }
            }
        }
    }

    // Check pointer-to-value conversions (`*foo;` -> `foo;`): any remaining `->foo->` is a compile error!
    let ptr_to_val: Vec<String> = ptr_removed.intersection(&val_added).cloned().collect();
    let mut ptr_broken: Vec<(String, Vec<String>)> = Vec::new();
    if !ptr_to_val.is_empty() {
        let pat = format!(r"->\s*({})\s*->", ptr_to_val.join("|"));
        let (_, out) = rg(&ctx.repo, &["-n", "-g", "*.c", "-g", "*.h", &pat]);
        let mut by_f: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for ln in out.lines() {
            let p: Vec<&str> = ln.splitn(3, ':').collect();
            if p.len() == 3 && is_c_source(p[0]) && (all_files || is_built_file(ctx, p[0])) {
                for f in &ptr_to_val {
                    if strip_c_comments(p[2]).contains(&format!("->{f}->")) {
                        by_f.entry(f.clone()).or_default().push(format!("{}:{}", p[0], p[1]));
                    }
                }
            }
        }
        for (f, locs) in by_f {
            ptr_broken.push((f, locs));
        }
    }

    if removed_fields.is_empty() {
        println!("  clean: no removed struct field declarations in range");
        return (0, "0 vanished fields".into());
    }

    // 1. Filter out fields that are STILL declared somewhere in-tree (e.g. moved to another header!)
    let all_names: Vec<String> = removed_fields.keys().cloned().collect();
    let still_declared = gate::batch_check_decls(ctx, &all_names, true);
    let vanished: Vec<String> = all_names
        .into_iter()
        .filter(|n| !still_declared.contains(n))
        .collect();

    if vanished.is_empty() {
        println!(
            "    checked {} removed decls: all still declared in-tree (moved/redeclared safely)",
            removed_fields.len()
        );
        return (0, "0 vanished fields".into());
    }

    // 2. Check via batched rg if ANY file in-tree or sm8735-modules STILL accesses `->field`!
    let mut broken: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    for chunk in vanished.chunks(80) {
        let alt = chunk.join("|");
        let pat = format!(r"->\s*({alt})\b");
        let mut refs_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();

        let (_, out) = rg(&ctx.repo, &["-n", "-g", "*.c", "-g", "*.h", &pat]);
        for ln in out.lines() {
            let p: Vec<&str> = ln.splitn(3, ':').collect();
            if p.len() == 3 && is_c_source(p[0]) && (all_files || is_built_file(ctx, p[0])) {
                let code = strip_c_comments(p[2]);
                for m in extract_members(code) {
                    if chunk.iter().any(|c| c == &m) {
                        refs_by_name.entry(m).or_default().push(format!("{}:{}", p[0], p[1]));
                    }
                }
            }
        }
        if ctx.is_default_kernel && ctx.modules.is_dir() {
            let (_, mout) = rg(&ctx.modules, &["-n", "-g", "*.c", "-g", "*.h", &pat]);
            for ln in mout.lines() {
                let p: Vec<&str> = ln.splitn(3, ':').collect();
                if p.len() == 3 {
                    let code = strip_c_comments(p[2]);
                    for m in extract_members(code) {
                        if chunk.iter().any(|c| c == &m) {
                            refs_by_name
                                .entry(m)
                                .or_default()
                                .push(format!("modules/{}:{}", p[0], p[1]));
                        }
                    }
                }
            }
        }
        for (name, locs) in refs_by_name {
            let from_files: Vec<String> = removed_fields
                .get(&name)
                .map(|s| s.iter().take(3).cloned().collect())
                .unwrap_or_default();
            broken.push((name, from_files, locs));
        }
    }

    println!(
        "    checked {} removed decls ({} truly vanished from tree)",
        removed_fields.len(),
        vanished.len()
    );
    if broken.is_empty() && ptr_broken.is_empty() {
        println!("  clean: 0 vanished struct fields still referenced, 0 ptr->val deref bugs");
        return (0, format!("0 broken ({} vanished, {} ptr->val checked)", vanished.len(), ptr_to_val.len()));
    }
    for (name, from_files, locs) in &broken {
        println!("  LOST FIELD  ->{name}  (removed from: {})", from_files.join(", "));
        for l in locs.iter().take(5) {
            println!("      still used at: {l}");
        }
    }
    for (name, locs) in &ptr_broken {
        println!("  PTR->VAL    ->{name}->  (field changed from pointer to embedded struct!)");
        for l in locs.iter().take(8) {
            println!("      invalid deref at: {l}");
        }
    }
    (1, format!("{} vanished + {} ptr->val broken!", broken.len(), ptr_broken.len()))
}

// ------------------------------------ 4. All-in-one `ktool verify` command

pub fn cmd_verify(
    ctx: &Ctx,
    from: &str,
    to: Option<&str>,
    base_override: Option<&str>,
    all_files: bool,
) -> i32 {
    // Support both:
    //   ktool verify v6.6.152 v6.6.162 [--base ref]
    //   ktool verify backup/pre-clo-20261121..HEAD
    //   ktool verify backup/pre-clo-20261121
    let (up_from, up_to, base) = if let Some(t) = to {
        let b = match base_override {
            Some(ov) => ov.to_string(),
            None => detect_pre_merge_base(ctx, from, t).unwrap_or_else(|| from.to_string()),
        };
        (Some(from), Some(t), b)
    } else if let Some((lhs, _rhs)) = from.split_once("..") {
        (None, None, lhs.to_string())
    } else {
        (None, None, from.to_string())
    };

    let header = match (up_from, up_to) {
        (Some(f), Some(t)) => format!("{f} -> {t} (local base={base}..HEAD)"),
        _ => format!("{base}..HEAD"),
    };
    println!("========================================================================");
    println!("kawal verify: {header}");
    println!("========================================================================\n");

    let mut rows: Vec<(&'static str, &'static str, String)> = Vec::new();
    let mut hard_fail = false;

    // 1. Merge chain & hygiene
    let chain = check_merge_chain(ctx, up_from, up_to, &base);
    rows.push(("merge-chain", if chain.ok { "PASS" } else { "FAIL" }, chain.summary));
    if !chain.ok {
        hard_fail = true;
    }
    println!();

    // 2. Markers
    let rc_m = gate::cmd_markers(ctx);
    rows.push(("markers", if rc_m == 0 { "PASS" } else { "FAIL" }, if rc_m == 0 { "clean".into() } else { "stray conflict markers found".into() }));
    if rc_m != 0 {
        hard_fail = true;
    }
    println!();

    // 3. Dup-scan (macros, dup statements, lock-balance drift)
    let (rc_dup, dup_msg) = run_dup_scan(ctx, &base, "HEAD", up_to, all_files);
    let dup_status = if rc_dup != 0 {
        hard_fail = true;
        "FAIL"
    } else if dup_msg.starts_with("0 dup macros/funcs/locals") {
        "PASS"
    } else {
        "WARN"
    };
    rows.push(("dup-scan", dup_status, dup_msg));
    println!();

    // 4. Struct-loss (moved/vanished fields still referenced)
    let (rc_sl, sl_msg) = run_struct_loss(ctx, &base, "HEAD", all_files);
    rows.push(("struct-loss", if rc_sl == 0 { "PASS" } else { "FAIL" }, sl_msg));
    if rc_sl != 0 {
        hard_fail = true;
    }
    println!();

    // 5. Dangling symbols across entire base..HEAD range
    let rc_d = gate::cmd_dangle(ctx, Some((&base, "HEAD")), !all_files);
    rows.push(("dangle", if rc_d == 0 { "PASS" } else { "WARN" }, if rc_d == 0 { "0 undeclared members/calls".into() } else { "review undeclared hits above".into() }));
    println!();

    // 6-8. Upstream-range gates (when upstream from..to provided)
    if let (Some(f), Some(t)) = (up_from, up_to) {
        let rc_lm = gate::cmd_landmines(ctx, f, t);
        rows.push(("landmines", if rc_lm == 0 { "PASS" } else { "FAIL" }, if rc_lm == 0 { "0 KABI landmines".into() } else { "KABI landmines hit!".into() }));
        if rc_lm != 0 {
            hard_fail = true;
        }
        println!();

        let rc_va = gate::cmd_vendorapi(ctx, f, t);
        rows.push(("vendorapi", if rc_va == 0 { "PASS" } else { "WARN" }, if rc_va == 0 { "0 vendor/module proto mismatches".into() } else { "review CHECK ARITY above".into() }));
        println!();

        let (rc_p, p_msg) = gate::run_partial_detailed(ctx, f, t, !all_files);
        let p_st = if rc_p == 2 {
            hard_fail = true;
            "FAIL"
        } else if rc_p == 1 {
            "WARN"
        } else {
            "PASS"
        };
        rows.push(("partial", p_st, p_msg));
        println!();
    }

    // 9. Boot-risk: splash-hang tiers, moved-block double-exec, DT string mismatches, removed exports/hooks
    let (rc_br, br_msg) = boot::run_boot_risk(ctx, up_from, up_to, &base);
    rows.push(("boot-risk", if rc_br == 0 { "PASS" } else { "FAIL" }, br_msg));
    if rc_br != 0 {
        hard_fail = true;
    }
    println!();

    // 10. ABI audit: UAPI struct/ioctl stability, include/ KABI layout & sm8735-modules version guards
    let (rc_abi, abi_msg) = abi::run_abi_audit(ctx, &base, "HEAD");
    rows.push(("abi-audit", if rc_abi == 0 { "PASS" } else { "WARN" }, abi_msg));
    println!();

    // 11. Per-function semantic runtime-bug audit (lock-imbalance, early-return lock leak, post-free UAF)
    let (rc_sem, sem_msg) = abi::run_sem_audit(ctx, &base, "HEAD", up_to);
    rows.push(("sem-audit", if rc_sem == 0 { "PASS" } else { "WARN" }, sem_msg));
    println!();

    // 12. Build-system & Android RO-sandbox hygiene guard
    let rc_bg = buildguard::cmd_build_guard(ctx, Some(&base), "HEAD");
    rows.push((
        "build-guard",
        if rc_bg == 0 { "PASS" } else { "FAIL" },
        if rc_bg == 0 {
            "RO-sandbox, Bazel/Kbuild, UAPI & Android.bp clean".into()
        } else {
            "build-system / sandbox issue detected!".into()
        },
    ));
    if rc_bg != 0 {
        hard_fail = true;
    }
    println!();

    // 13. ACK vs upstream semantic & KMI invariants (Per-VMA lock, rust_binder exports, KMI arity)
    let (rc_ac, ac_msg) = merge_intel::run_semantic_clashes(ctx);
    rows.push(("ack-clash", if rc_ac == 0 { "PASS" } else { "FAIL" }, ac_msg));
    if rc_ac != 0 {
        hard_fail = true;
    }
    println!();

    // 14. Upstream header-drop guard (catches `--ours` on headers dropping needed +defs)
    if let (Some(f), Some(t)) = (up_from, up_to) {
        let (rc_hd, hd_msg) = merge_intel::run_header_drop(ctx, f, t, all_files);
        rows.push(("header-drop", if rc_hd == 0 { "PASS" } else { "FAIL" }, hd_msg));
        if rc_hd != 0 {
            hard_fail = true;
        }
        println!();
    }

    println!("========================================================================");
    println!("VERIFY SUMMARY: {header}");
    println!("========================================================================");
    for (name, st, msg) in &rows {
        println!("  [{st:<4}] {name:<12} {msg}");
    }
    if hard_fail { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_dup_fallthrough_labels_catches_mhi_double_del() {
        let lines = vec![
            "\tif (ret)",
            "\t\tgoto err_del_dev;",
            "\treturn 0;",
            "err_del_dev:",
            "\tdevice_del(&mhi_cntrl->mhi_dev->dev);",
            "err_release_dev:",
            "\tdevice_del(&mhi_cntrl->mhi_dev->dev);",
            "\tput_device(&mhi_cntrl->mhi_dev->dev);",
            "\treturn ret;",
        ];
        let mut added = HashSet::new();
        added.insert(5);
        let hits = scan_dup_fallthrough_labels("drivers/bus/mhi/host/init.c", &lines, &added);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].contains("err_del_dev:") && hits[0].contains("err_release_dev:"));

        // Safe version with return between labels must NOT trigger
        let safe_lines = vec![
            "err_a:",
            "\tdevice_del(&dev);",
            "\treturn -EINVAL;",
            "err_b:",
            "\tdevice_del(&dev);",
            "\treturn -ENOMEM;",
        ];
        let mut added2 = HashSet::new();
        added2.insert(2);
        assert!(scan_dup_fallthrough_labels("safe.c", &safe_lines, &added2).is_empty());
    }

    #[test]
    fn test_scan_dup_local_decls_catches_gdsc_dup_int_i() {
        let lines = vec![
            "void gdsc_unregister(struct gdsc_desc *desc)",
            "{",
            "\tstruct gdsc **scs = desc->scs;",
            "\tint i;",
            "\tsize_t num = desc->num;",
            "\tint i;",
            "\tfor (i = 0; i < num; i++) {",
            "\t\tint i;",
            "\t}",
            "}",
        ];
        let mut added = HashSet::new();
        added.insert(6);
        let hits = scan_dup_local_decls("drivers/clk/qcom/gdsc.c", &lines, &added);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].contains("L4 & L6") && hits[0].contains("`i`"));
    }
}
