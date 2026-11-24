use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::util::*;

// ---------------------------------------------------------------- merge step

pub fn fix_bindings(ctx: &Ctx) {
    let pref = format!("{BINDINGS}/");
    let staged = git(ctx, &["ls-files", "-s", &pref]);
    let mut to_rm: Vec<String> = staged
        .lines()
        .filter_map(|ln| ln.split_once('\t').map(|(_, p)| p.to_string()))
        .collect();
    to_rm.sort();
    to_rm.dedup();
    if !to_rm.is_empty() {
        let mut args = vec!["rm", "-r", "--cached", "-q", "--ignore-unmatch", "--"];
        args.extend(to_rm.iter().map(|s| s.as_str()));
        let _ = git_rc(ctx, &args);
    }
    let b_tilde = format!("{BINDINGS}~HEAD");
    let _ = git_rc(ctx, &["rm", "-q", "--cached", "--ignore-unmatch", "--", &b_tilde]);
    for suffix in ["", "~HEAD", "~"] {
        let p = ctx.repo.join(format!("{BINDINGS}{suffix}"));
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if meta.is_dir() && !meta.file_type().is_symlink() {
                let _ = fs::remove_dir_all(&p);
            } else if meta.file_type().is_symlink() && !suffix.is_empty() {
                let _ = fs::remove_file(&p);
            }
        }
    }
    let _ = git_rc(ctx, &["checkout", "HEAD", "--", BINDINGS]);
    let _ = git_rc(ctx, &["add", BINDINGS]);
}

pub fn cmd_merge(ctx: &Ctx, tag: &str) -> i32 {
    let branch = git(ctx, &["rev-parse", "--abbrev-ref", "HEAD"]).trim().to_string();
    println!("=== merging {tag} into {branch} ===");
    let (rc, _, stderr) = git_rc(
        ctx,
        &["-c", "rerere.enabled=false", "merge", "-S", "--no-edit", "--no-ff", tag],
    );
    if is_mid_merge(ctx) {
        if ctx.is_default_kernel {
            fix_bindings(ctx);
        }
    } else if rc != 0 {
        println!("{}", stderr.trim());
        return rc;
    }
    cmd_status(ctx)
}

pub fn cmd_status(ctx: &Ctx) -> i32 {
    let left = unmerged_with_status(ctx);
    if left.is_empty() {
        println!("RESOLVED: no unmerged paths left");
        return 0;
    }
    let nb = left.iter().filter(|(_, p)| is_built_file(ctx, p)).count();
    println!("UNMERGED ({}: {nb} [BUILT], {} [unbuilt]):", left.len(), left.len() - nb);
    for (code, p) in &left {
        let b = if is_built_file(ctx, p) { "[BUILT]" } else { "[unbuilt]" };
        let c = if code == "UU" { "" } else { code.as_str() };
        if c.is_empty() {
            println!("  {b:<9} {p}");
        } else {
            println!("  {b:<9} ({c}) {p}");
        }
    }
    1
}

// ------------------------------------------------------------------- markers

pub fn cmd_markers(ctx: &Ctx) -> i32 {
    let (rc, out) = rg(&ctx.repo, &["-n", r"^(<{7}|>{7}) "]);
    if rc == 0 && !out.trim().is_empty() {
        println!("STRAY CONFLICT MARKERS:");
        print!("{out}");
        return 1;
    }
    println!("=== markers: clean ===");
    0
}

// ------------------------------------------------------------ numstat audit

pub fn cmd_audit(ctx: &Ctx, tag: &str) -> i32 {
    // Decrement trailing integer in tag (e.g. v6.6.160 -> v6.6.159)
    let prev = decrement_tag(tag);
    println!("=== {prev} -> {tag} : per-file audit ===");
    let mut ours: HashMap<String, (String, String)> = HashMap::new();
    for ln in git(ctx, &["diff", "--numstat", "HEAD^1", "HEAD"]).lines() {
        let p: Vec<&str> = ln.split('\t').collect();
        if p.len() >= 3 {
            ours.insert(p[2].to_string(), (p[0].to_string(), p[1].to_string()));
        }
    }
    let mut rows = Vec::new();
    for ln in git(ctx, &["diff", "--numstat", &prev, tag]).lines() {
        let p: Vec<&str> = ln.split('\t').collect();
        if p.len() < 3 || p[2].starts_with("Documentation/devicetree/bindings/") {
            continue;
        }
        let (a, d, f) = (p[0], p[1], p[2]);
        let (oa, od) = ours.get(f).map(|(x, y)| (x.as_str(), y.as_str())).unwrap_or(("0", "0"));
        if oa == "0" && od == "0" {
            rows.push(("SKIPPED", format!("+{a}/-{d}"), format!("+{oa}/-{od}"), f.to_string()));
        } else if a != oa || d != od {
            rows.push(("PARTIAL", format!("+{a}/-{d}"), format!("+{oa}/-{od}"), f.to_string()));
        }
    }
    if rows.is_empty() {
        println!("  all files match upstream exactly");
    } else {
        for (v, u, o, f) in rows {
            let b = if is_built_file(ctx, &f) { "[BUILT]" } else { "[unbuilt]" };
            println!("  {v:<8} {b:<9} up {u:<10} app {o:<10} {f}");
        }
    }
    println!();
    cmd_dangle(ctx, None, false)
}

fn decrement_tag(tag: &str) -> String {
    let b = tag.as_bytes();
    let mut i = b.len();
    while i > 0 && b[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i < b.len() {
        if let Ok(n) = tag[i..].parse::<u64>() {
            return format!("{}{}", &tag[..i], n.saturating_sub(1));
        }
    }
    tag.to_string()
}

// -------------------------------------------- ultra-fast rg dangling scanner

pub fn cmd_dangle(ctx: &Ctx, rev_range: Option<(&str, &str)>, built_only: bool) -> i32 {
    let owned: Vec<String> = match rev_range {
        Some((a, b)) => vec![a.to_string(), b.to_string()],
        None => {
            if is_mid_merge(ctx) {
                vec!["HEAD".into(), "--".into()]
            } else {
                vec!["HEAD^1".into(), "HEAD".into()]
            }
        }
    };
    println!("=== dangling-symbol scan ({}) ===", owned.join(" "));
    let mut args = vec!["diff", "--unified=0"];
    args.extend(owned.iter().map(|s| s.as_str()));
    let diff = git(ctx, &args);

    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut calls: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut cur: Option<String> = None;

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur = Some(p.to_string());
        } else if let (Some(path), Some(code)) = (&cur, ln.strip_prefix('+')) {
            if ln.starts_with("+++") || !is_c_source(path) {
                continue;
            }
            if built_only && !is_built_file(ctx, path) {
                continue;
            }
            let trim = code.trim_start();
            if trim.starts_with('*') || trim.starts_with("//") || trim.starts_with("/*") {
                continue;
            }
            for m in extract_members(code) {
                members.entry(m).or_default().insert(path.clone());
            }
            for c in extract_calls(code, 4) {
                calls.entry(c).or_default().insert(path.clone());
            }
        }
    }

    // Batched rg declaration check ONLY for the introduced candidate symbols (~0.2s total!)
    let mut bad_m = Vec::new();
    if !members.is_empty() {
        let names: Vec<String> = members.keys().cloned().collect();
        let found = batch_check_decls(ctx, &names, true);
        for (name, files) in &members {
            if !found.contains(name) {
                bad_m.push((name.clone(), files.iter().take(4).cloned().collect::<Vec<_>>()));
            }
        }
    }
    let mut bad_c = Vec::new();
    if !calls.is_empty() {
        let names: Vec<String> = calls.keys().cloned().collect();
        let found = batch_check_decls(ctx, &names, false);
        for (name, files) in &calls {
            if !found.contains(name) {
                bad_c.push((name.clone(), files.iter().take(4).cloned().collect::<Vec<_>>()));
            }
        }
    }

    println!(
        "    scanned {} members, {} calls via batched rg",
        members.len(),
        calls.len()
    );
    if bad_m.is_empty() && bad_c.is_empty() {
        println!("  clean: every introduced identifier resolves in-tree");
        return 0;
    }
    for (name, files) in &bad_m {
        println!("  UNDECLARED MEMBER  ->{name}  ({})", files.join(", "));
    }
    for (name, files) in &bad_c {
        println!("  UNDEFINED CALL     {name}()  ({})", files.join(", "));
    }
    1
}

pub(crate) fn batch_check_decls(ctx: &Ctx, names: &[String], is_member: bool) -> HashSet<String> {
    let mut found = HashSet::new();
    // Chunk by 120 names so regex stays compact and blazing fast in rg
    let chunks: Vec<&[String]> = names.chunks(120).collect();
    let per_chunk: Vec<HashSet<String>> = par_map(&chunks, ctx.threads.min(4), |chunk| {
        let alt = chunk.join("|");
        let pat = if is_member {
            // Struct member decl (`foo;`, `foo[`, `foo : 1,`, `(*foo)(`, `#define foo`, `, foo;`, `} __packed foo`)
            format!(
                r"(\b({alt})\s*(;|\[|:\s*\d+\s*[;,]|,)|\(\s*\*\s*({alt})\s*\)\s*\(|^\s*#\s*define\s+({alt})\b)"
            )
        } else {
            // Function def/proto (allowing __alloc_size(...) attrs), function pointer, union/struct, or macro
            format!(
                r"(^([A-Za-z_][A-Za-z0-9_ \t\*\(\),]*[ \t\*])?({alt})[ \t]*\(|\(\s*\*\s*({alt})\s*\)\s*\(|^\s*#\s*define\s+({alt})\b|\b(union|struct)\s+({alt})\b)"
            )
        };
        let (_, out) = rg(&ctx.repo, &["-o", "--no-filename", "-g", "*.c", "-g", "*.h", &pat]);
        let mut local = HashSet::new();
        let wanted: HashSet<&str> = chunk.iter().map(|s| s.as_str()).collect();
        for tok in extract_bare_idents(&out) {
            if wanted.contains(tok.as_str()) {
                local.insert(tok);
            }
        }
        local
    });
    for set in per_chunk {
        found.extend(set);
    }
    found
}

// ------------------------------------------------- reverts & KABI landmines

fn kabi_reverts_stream(ctx: &Ctx) -> Vec<(String, String, Vec<String>)> {
    let mut args = vec![
        "log", "--full-history", "--all-match", "-i",
        "--grep=^Revert ", "--grep=android kernel abi",
        "--format=@@@COMMIT@@@%H%x09%s", "-p",
    ];
    if let Some(since) = ctx.history_since() {
        args.push(since);
    }
    args.extend(["HEAD", "--", "."]);
    let out = git(ctx, &args);
    let mut res = Vec::new();
    let mut cur: Option<(String, String, Vec<String>)> = None;
    for ln in out.lines() {
        if let Some(rest) = ln.strip_prefix("@@@COMMIT@@@") {
            if let Some(prev) = cur.take() {
                res.push(prev);
            }
            if let Some((sha, subj)) = rest.split_once('\t') {
                cur = Some((sha.to_string(), subj.to_string(), Vec::new()));
            }
        } else if let Some((_, _, ref mut buf)) = cur {
            buf.push(ln.to_string());
        }
    }
    if let Some(last) = cur {
        res.push(last);
    }
    res
}

pub fn cmd_reverts(ctx: &Ctx, pattern: &str) -> i32 {
    let mut a1 = vec!["log", "--full-history", "--format=%H%x09%s", "--grep", "^Revert ", "-i"];
    let mut a2 = vec!["log", "--full-history", "--all-match", "-i", "--grep=^Revert ", "--grep=android kernel abi", "--format=%H"];
    if let Some(since) = ctx.history_since() {
        a1.push(since);
        a2.push(since);
    }
    a1.extend(["HEAD", "--", "."]);
    a2.extend(["HEAD", "--", "."]);
    let out = git(ctx, &a1);
    let kabi: HashSet<String> = git(ctx, &a2)
    .lines()
    .map(|s| s.trim().to_string())
    .collect();
    let pat_low = pattern.to_ascii_lowercase();
    let hits: Vec<(&str, &str)> = out
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .filter(|(_, s)| pat_low.is_empty() || s.to_ascii_lowercase().contains(&pat_low))
        .collect();
    if pattern.is_empty() {
        println!("{} revert commits", hits.len());
    } else {
        println!("{} revert commits matching '{pattern}'", hits.len());
    }
    for (sha, subj) in hits.iter().take(80) {
        let tag = if kabi.contains(*sha) { "KABI" } else { "    " };
        println!("  {} {tag} {subj}", &sha[..12.min(sha.len())]);
    }
    0
}

pub(crate) fn parse_removed_header_decl(line: &str) -> Option<String> {
    let rest = line.strip_prefix('-')?;
    if rest.starts_with("--") {
        return None;
    }
    let s = strip_c_comments(rest).trim();
    if !s.ends_with(';') || s.contains('(') || s.starts_with('#') || s.starts_with("return ") {
        return None;
    }
    let before_semi = s[..s.len() - 1].trim_end();
    // Strip trailing [array] or : bits
    let before_suffix = if let Some(bi) = before_semi.rfind('[') {
        before_semi[..bi].trim_end()
    } else if let Some(ci) = before_semi.rfind(':') {
        before_semi[..ci].trim_end()
    } else {
        before_semi
    };
    let b = before_suffix.as_bytes();
    let mut i = b.len();
    while i > 0 && is_ident_char(b[i - 1]) {
        i -= 1;
    }
    let name = &before_suffix[i..];
    let left = before_suffix[..i].trim();
    if left.is_empty()
        || name.len() < 3
        || !name.as_bytes()[0].is_ascii_lowercase()
        || C_KEYWORDS.contains(&name)
    {
        return None;
    }
    Some(name.to_string())
}

pub fn cmd_landmines(ctx: &Ctx, base: &str, tag: &str) -> i32 {
    println!("=== {base} -> {tag}: landmines (new code vs still-active KABI reverts) ===");
    let mut missing: BTreeMap<String, (String, String, String, BTreeSet<String>)> = BTreeMap::new();
    let mut fcache: HashMap<String, Option<String>> = HashMap::new();

    for (sha, subj, lines) in kabi_reverts_stream(ctx) {
        let scope: BTreeSet<String> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("+++ b/"))
            .filter(|f| !f.starts_with("include/"))
            .map(|f| Path::new(f).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default())
            .collect();
        let mut cur: Option<String> = None;
        for line in &lines {
            if let Some(p) = line.strip_prefix("+++ b/") {
                cur = Some(p.to_string());
                continue;
            }
            let Some(ref path) = cur else { continue };
            if !path.ends_with(".h") {
                continue;
            }
            let Some(name) = parse_removed_header_decl(line) else {
                continue;
            };
            let content = fcache
                .entry(path.clone())
                .or_insert_with(|| fs::read_to_string(ctx.repo.join(path)).ok());
            if let Some(text) = content {
                if word_in_text(text, &name) {
                    continue;
                }
            } else {
                continue;
            }
            let mut full_scope = scope.clone();
            full_scope.insert(Path::new(path).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default());
            missing.insert(name, (sha.clone(), subj.clone(), path.clone(), full_scope));
        }
    }

    if missing.is_empty() {
        println!("  no KABI revert currently removes a header declaration");
        return 0;
    }
    println!("    {} declaration(s) still absent due to KABI reverts", missing.len());

    let mut added: HashMap<String, Vec<String>> = HashMap::new();
    let mut cur_dir: Option<String> = None;
    for l in git(ctx, &["diff", base, tag]).lines() {
        if let Some(p) = l.strip_prefix("+++ b/") {
            cur_dir = Some(Path::new(p).parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default());
        } else if l.starts_with('+') && !l.starts_with("+++") {
            if let Some(ref d) = cur_dir {
                added.entry(d.clone()).or_default().push(l.to_string());
            }
        }
    }

    let mut bad = Vec::new();
    for (name, (sha, subj, path, scope)) in &missing {
        let mut hits = Vec::new();
        // Core headers under include/linux/ or include/net/ can be referenced from ANY subsystem
        // (e.g. skbuff.h::tstamp_type used in drivers/net/wireguard/!), so scan all built dirs
        // for distinctive member names (len >= 7, not generic).
        let global_core = (path.starts_with("include/linux/") || path.starts_with("include/net/"))
            && name.len() >= 7
            && !GENERIC_MEMBERS.contains(&name.as_str());
        let dirs_to_check: Vec<&String> = if global_core {
            added.keys().collect()
        } else {
            scope.iter().collect()
        };
        for d in dirs_to_check {
            if let Some(lns) = added.get(d) {
                let matched = lns.iter().any(|l| {
                    let code = strip_c_comments(l);
                    word_in_text(code, name)
                        && (code.contains(&format!("->{name}"))
                            || code.contains(&format!(".{name}"))
                            || code.contains(&format!("{name}(")))
                });
                if matched {
                    hits.push(d.clone());
                }
            }
        }
        if !hits.is_empty() {
            hits.sort();
            bad.push((name, sha, subj, path, hits));
        }
    }
    if bad.is_empty() {
        println!("  clean -- nothing added in range touches them");
        return 0;
    }
    for (name, sha, subj, path, where_dirs) in bad {
        println!("  LANDMINE  {name}  (removed from {path} by {}: {subj})", &sha[..12.min(sha.len())]);
        println!("      touched under: {}", where_dirs.join(", "));
    }
    1
}

// ------------------------------------------- vendorapi (in-tree + modules!)

fn parse_proto_name(line: &str) -> Option<(String, String)> {
    let rest = line.get(1..)?;
    if line.starts_with("---") || line.starts_with("+++") {
        return None;
    }
    let trim = rest.trim_start();
    // Skip comments, statements inside function bodies, and non-declarations
    if trim.starts_with('*')
        || trim.starts_with("//")
        || trim.starts_with("/*")
        || trim.starts_with("return ")
        || trim.starts_with("if ")
        || trim.starts_with("if(")
        || trim.starts_with("else")
        || trim.starts_with("for ")
        || trim.starts_with("while ")
        || trim.contains(" = ")
    {
        return None;
    }
    // Real header declarations sit at column 0 (extern/static/#define/return-type)
    if rest.starts_with('\t') || rest.starts_with("    ") {
        return None;
    }
    let s = strip_c_comments(rest).trim();
    let paren = s.find('(')?;
    let before = s[..paren].trim_end();
    let b = before.as_bytes();
    let mut i = b.len();
    while i > 0 && is_ident_char(b[i - 1]) {
        i -= 1;
    }
    let name = &before[i..];
    let left = before[..i].trim();
    if left.is_empty()
        || name.len() < 4
        || !name.as_bytes()[0].is_ascii_lowercase()
        || NOT_A_CALL.contains(&name)
        || C_KEYWORDS.contains(&name)
    {
        return None;
    }
    // Extract canonical signature text for comparison (normalize whitespace)
    let sig: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    Some((name.to_string(), sig))
}

pub fn cmd_vendorapi(ctx: &Ctx, base: &str, tag: &str) -> i32 {
    println!("=== {base} -> {tag}: changed include/ prototypes vs vendor & modules ===");
    let mut removed: HashMap<String, String> = HashMap::new();
    let mut added: HashMap<String, String> = HashMap::new();
    for ln in git(ctx, &["diff", base, tag, "--", "include/"]).lines() {
        if let Some((name, sig)) = parse_proto_name(ln) {
            if ln.starts_with('-') {
                removed.insert(name, sig);
            } else if ln.starts_with('+') {
                added.insert(name, sig);
            }
        }
    }
    // Only keep prototypes whose signature actually changed (ignore identical re-indents/moves)
    let names: Vec<String> = removed
        .iter()
        .filter(|(k, old_sig)| added.get(*k).is_some_and(|new_sig| new_sig != *old_sig))
        .map(|(k, _)| k.clone())
        .collect();
    if names.is_empty() {
        println!("  no prototype churn in include/");
        return 0;
    }

    let upstream: HashSet<String> = git(ctx, &["ls-tree", "-r", "--name-only", tag])
        .lines()
        .map(|s| s.to_string())
        .collect();
    let vendor_files: Vec<String> = git(ctx, &["ls-files"])
        .lines()
        .filter(|f| !upstream.contains(*f) && (f.ends_with(".c") || f.ends_with(".h")))
        .map(|s| s.to_string())
        .collect();
    let mod_files: Vec<String> = if ctx.is_default_kernel && ctx.modules.is_dir() {
        git_in(&ctx.modules, &["ls-files"])
            .lines()
            .filter(|f| f.ends_with(".c") || f.ends_with(".h"))
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    };
    println!(
        "    {} changed prototypes vs {} vendor-only + {} module files",
        names.len(),
        vendor_files.len(),
        mod_files.len()
    );

    let pat = format!(r"\b({})\s*\(", names.join("|"));
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Scan vendor-only files in parallel in Rust (fast & zero arg-limit issue!)
    let v_hits: Vec<Vec<(String, String)>> = par_map(&vendor_files, ctx.threads, |f| {
        let mut local = Vec::new();
        if let Ok(text) = fs::read_to_string(ctx.repo.join(f)) {
            for (i, ln) in text.lines().enumerate() {
                for c in extract_calls(ln, 4) {
                    if names.iter().any(|n| n == &c) {
                        local.push((c, format!("{f}:{}", i + 1)));
                    }
                }
            }
        }
        local
    });
    for vec in v_hits {
        for (fn_name, loc) in vec {
            hits.entry(fn_name).or_default().push(loc);
        }
    }

    // Scan out-of-tree sm8735-modules in one rg pass
    if !mod_files.is_empty() {
        let (_, mout) = rg(&ctx.modules, &["-n", "-g", "*.c", "-g", "*.h", &pat]);
        for ln in mout.lines() {
            let p: Vec<&str> = ln.splitn(3, ':').collect();
            if p.len() == 3 {
                for c in extract_calls(p[2], 4) {
                    if names.iter().any(|n| n == &c) {
                        hits.entry(c).or_default().push(format!("modules/{}:{}", p[0], p[1]));
                    }
                }
            }
        }
    }

    if hits.is_empty() {
        println!("  clean -- no vendor or module file calls a changed prototype");
        return 0;
    }
    for (fn_name, locs) in hits {
        println!("  CHECK ARITY  {fn_name}()");
        for loc in locs.iter().take(6) {
            println!("      {loc}");
        }
    }
    1
}

// ---------------------------------- 16-core parallel per-commit partial check

fn classify_partial(ctx: &Ctx, path: &str, diff: &str) -> &'static str {
    let Ok(text) = fs::read_to_string(ctx.repo.join(path)) else {
        return "SPLIT";
    };
    let mut adds = Vec::new();
    let mut dels = Vec::new();
    for ln in diff.lines() {
        if let Some(r) = ln.strip_prefix('+') {
            if !ln.starts_with("+++") && ln.trim().len() >= 16 {
                let t = r.trim();
                if !t.starts_with('*') && !t.starts_with("//") && !t.starts_with("/*") {
                    adds.push(t);
                }
            }
        } else if let Some(r) = ln.strip_prefix('-') {
            if !ln.starts_with("---") && ln.trim().len() >= 16 {
                let t = r.trim();
                if !t.starts_with('*') && !t.starts_with("//") && !t.starts_with("/*") {
                    dels.push(t);
                }
            }
        }
    }
    if !adds.is_empty() && !dels.is_empty() {
        let add_hit = adds.iter().any(|a| text.contains(a));
        let del_still = dels.iter().any(|d| !adds.contains(d) && text.contains(d));
        if add_hit && del_still {
            return "BOTH!";
        }
    }
    "SPLIT"
}

pub fn cmd_partial(ctx: &Ctx, base: &str, tag: &str, built_only: bool) -> i32 {
    let (rc, _) = run_partial_detailed(ctx, base, tag, built_only);
    if rc == 0 { 0 } else { 1 }
}

/// Returns (status, summary) where status is: 0=clean, 1=SPLIT/ABSENT review needed, 2=BOTH! danger.
pub(crate) fn run_partial_detailed(ctx: &Ctx, base: &str, tag: &str, built_only: bool) -> (i32, String) {
    println!("=== {base} -> {tag}: per-commit application check (built_only={built_only}) ===");

    // 1. Single git diff --name-only <tag> tells us EVERY file differing from <tag>!
    let diff_files: HashSet<String> = git(ctx, &["diff", "--name-only", tag])
        .lines()
        .map(|s| s.to_string())
        .collect();

    // 2. Single git log -p stream (1 git spawn instead of N!)
    let rng = format!("{base}..{tag}");
    let stream = git(
        ctx,
        &["log", "--reverse", "--no-renames", "--format=@@@COMMIT@@@%H%x1f%s", "-p", &rng],
    );

    struct WorkItem {
        sha: String,
        subj: String,
        path: String,
        diff: String,
    }

    let mut items = Vec::new();
    let mut total_commits = 0usize;
    let mut skipped_ident = 0usize;
    let mut cur_sha = String::new();
    let mut cur_subj = String::new();
    let mut cur_path: Option<String> = None;
    let mut cur_buf = String::new();

    let flush = |sha: &str,
                 subj: &str,
                 path_opt: &mut Option<String>,
                 buf: &mut String,
                 items: &mut Vec<WorkItem>,
                 skipped_ident: &mut usize| {
        if let Some(p) = path_opt.take() {
            if is_c_source(&p)
                && ctx.repo.join(&p).exists()
                && (!built_only || is_built_file(ctx, &p))
            {
                if !diff_files.contains(&p) {
                    *skipped_ident += 1;
                } else {
                    items.push(WorkItem {
                        sha: sha.to_string(),
                        subj: subj.to_string(),
                        path: p,
                        diff: std::mem::take(buf),
                    });
                }
            }
        }
        buf.clear();
    };

    for ln in stream.lines() {
        if let Some(rest) = ln.strip_prefix("@@@COMMIT@@@") {
            flush(&cur_sha, &cur_subj, &mut cur_path, &mut cur_buf, &mut items, &mut skipped_ident);
            total_commits += 1;
            if let Some((h, s)) = rest.split_once('\x1f') {
                cur_sha = h.to_string();
                cur_subj = s.to_string();
            }
        } else if ln.starts_with("diff --git ") {
            flush(&cur_sha, &cur_subj, &mut cur_path, &mut cur_buf, &mut items, &mut skipped_ident);
            cur_buf.push_str(ln);
            cur_buf.push('\n');
        } else if let Some(p) = ln.strip_prefix("+++ b/") {
            cur_path = Some(p.trim().to_string());
            cur_buf.push_str(ln);
            cur_buf.push('\n');
        } else if !cur_buf.is_empty() {
            cur_buf.push_str(ln);
            cur_buf.push('\n');
        }
    }
    flush(&cur_sha, &cur_subj, &mut cur_path, &mut cur_buf, &mut items, &mut skipped_ident);

    // 3. Run `git apply --check -C1` in parallel across all 16 cores!
    //    When a commit was later overwritten by a subsequent commit in base..tag, `-R` fails
    //    even though HEAD matches `tag` on every changed line of this commit. Check against
    //    `tag` to distinguish true half-merges from superseded earlier commits in the range!
    let up_texts: HashMap<String, String> = {
        let mut uniq: Vec<String> = items.iter().map(|it| it.path.clone()).collect();
        uniq.sort();
        uniq.dedup();
        let fetched = par_map(&uniq, ctx.threads, |p| {
            (p.clone(), git(ctx, &["show", &format!("{tag}:{p}")]))
        });
        fetched.into_iter().collect()
    };

    enum State {
        Applied,
        Absent,
        Flagged(&'static str),
    }

    let states = par_map(&items, ctx.threads, |it| {
        if git_stdin(ctx, &["apply", "--check", "-C1", "--reverse"], it.diff.as_bytes()).0 == 0 {
            return State::Applied;
        }
        // Check if every surviving '+' line of this commit (present in `tag`) is present in HEAD,
        // and every deleted '-' line (gone from `tag`) is also gone in HEAD (or commit's lines match `tag`)!
        if let (Ok(head_txt), Some(up_txt)) = (fs::read_to_string(ctx.repo.join(&it.path)), up_texts.get(&it.path)) {
            let mut surviving_adds = Vec::new();
            let mut surviving_dels = Vec::new();
            for ln in it.diff.lines() {
                if let Some(r) = ln.strip_prefix('+') {
                    if !ln.starts_with("+++") {
                        let t = r.trim();
                        if t.len() >= 10 && !t.starts_with('*') && !t.starts_with("//") && !t.starts_with("/*") {
                            if up_txt.contains(t) {
                                surviving_adds.push(t);
                            }
                        }
                    }
                } else if let Some(r) = ln.strip_prefix('-') {
                    if !ln.starts_with("---") {
                        let t = r.trim();
                        if t.len() >= 10 && !t.starts_with('*') && !t.starts_with("//") && !t.starts_with("/*") {
                            if !up_txt.contains(t) {
                                surviving_dels.push(t);
                            }
                        }
                    }
                }
            }
            if (!surviving_adds.is_empty() || !surviving_dels.is_empty())
                && surviving_adds.iter().all(|a| head_txt.contains(a))
                && surviving_dels.iter().all(|d| !head_txt.contains(d))
            {
                return State::Applied;
            }
        }
        if git_stdin(ctx, &["apply", "--check", "-C1"], it.diff.as_bytes()).0 == 0 {
            State::Absent
        } else {
            State::Flagged(classify_partial(ctx, &it.path, &it.diff))
        }
    });

    let mut applied = skipped_ident;
    let mut absent_list = Vec::new();
    let mut flagged = Vec::new();
    for (it, st) in items.iter().zip(states.into_iter()) {
        match st {
            State::Applied => applied += 1,
            State::Absent => absent_list.push((&it.sha, &it.path, &it.subj)),
            State::Flagged(kind) => flagged.push((kind, &it.sha, &it.path, &it.subj)),
        }
    }
    let checked = skipped_ident + items.len();
    let both_cnt = flagged.iter().filter(|x| x.0 == "BOTH!").count();
    let split_cnt = flagged.len() - both_cnt;
    println!(
        "    {total_commits} commits, {checked} pairs: {applied} applied ({skipped_ident} byte-identical), {} absent, {} flagged ({both_cnt} BOTH!, {split_cnt} SPLIT)",
        absent_list.len(),
        flagged.len()
    );
    if flagged.is_empty() && absent_list.is_empty() {
        println!("  clean -- every upstream commit landed cleanly");
        return (0, format!("{applied}/{checked} applied, 0 absent, 0 flagged"));
    }
    flagged.sort_by(|a, b| (a.0 != "BOTH!").cmp(&(b.0 != "BOTH!")).then(a.2.cmp(b.2)).then(a.1.cmp(b.1)));
    for (kind, sha, path, subj) in &flagged {
        let b = if is_built_file(ctx, path) { "[BUILT]" } else { "[unbuilt]" };
        println!("  {kind:<5} {b:<9} {}  {path}  -- {subj}", &sha[..12.min(sha.len())]);
    }
    if !absent_list.is_empty() {
        println!("  --- ABSENT (upstream commit did not apply in HEAD — verify intentional drop!) ---");
        for (sha, path, subj) in absent_list.iter().take(40) {
            let b = if is_built_file(ctx, path) { "[BUILT]" } else { "[unbuilt]" };
            println!("  ABSENT {b:<9} {}  {path}  -- {subj}", &sha[..12.min(sha.len())]);
        }
        if absent_list.len() > 40 {
            println!("  ... (+{} more absent)", absent_list.len() - 40);
        }
    }
    let msg = format!("{applied}/{checked} applied, {both_cnt} BOTH!, {split_cnt} SPLIT, {} absent", absent_list.len());
    let rc = if both_cnt > 0 { 2 } else { 1 };
    (rc, msg)
}

// ----------------------------------------------------------- config checker

const HARDENING_PATTERNS: &[&str] = &[
    "KASAN", "KFENCE", "UBSAN", "KCSAN", "CFI_", "SHADOW_CALL", "STACKPROTECTOR",
    "INIT_STACK", "INIT_ON_ALLOC", "INIT_ON_FREE", "HARDENED_USERCOPY",
    "LIST_HARDENED", "BUG_ON_DATA_CORRUPTION", "STACKLEAK", "ZERO_CALL_USED",
    "SLAB_FREELIST", "PAGE_POISONING", "DEBUG_PAGEALLOC", "PTR_AUTH",
    "DYNAMIC_SCS", "UNWIND_PATCH_PAC", "ARM64_MTE", "KCOV", "GCOV", "LOCKDEP",
    "PROVE_LOCKING", "DEBUG_ATOMIC_SLEEP", "DEBUG_OBJECTS", "TRACE_MMIO",
];

fn parse_config(path: &Path) -> BTreeMap<String, String> {
    let mut cfg = BTreeMap::new();
    let Ok(text) = fs::read_to_string(path) else { return cfg };
    for ln in text.lines() {
        if let Some(rest) = ln.strip_prefix("CONFIG_") {
            if let Some((k, v)) = rest.split_once('=') {
                cfg.insert(format!("CONFIG_{k}"), v.to_string());
            }
        } else if let Some(rest) = ln.strip_prefix("# CONFIG_") {
            if let Some(k) = rest.strip_suffix(" is not set") {
                cfg.insert(format!("CONFIG_{k}"), "n".to_string());
            }
        }
    }
    cfg
}

pub fn cmd_config(baseline: &Path, current: &Path) -> i32 {
    let base = parse_config(baseline);
    let cur = parse_config(current);
    let is_on = |v: &str| !v.is_empty() && v != "n";
    let is_hardening = |name: &str| {
        if ["CONFIG_CC_HAS_", "CONFIG_HAVE_ARCH_", "CONFIG_ARCH_HAS_", "CONFIG_ARCH_SUPPORTS_"]
            .iter()
            .any(|p| name.starts_with(p))
            || name.ends_with("_NONE")
            || name.ends_with("_OFF")
        {
            return false;
        }
        HARDENING_PATTERNS.iter().any(|p| name.contains(p))
    };

    let mut bad = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    for (name, val) in &cur {
        match base.get(name) {
            None => {
                if is_on(val) {
                    if is_hardening(name) {
                        bad.push((name.as_str(), "(new)", val.as_str()));
                    } else {
                        changed.push((name.as_str(), "(new)", val.as_str()));
                    }
                }
            }
            Some(old) if old != val => {
                if is_hardening(name) && is_on(val) && !is_on(old) {
                    bad.push((name.as_str(), old.as_str(), val.as_str()));
                } else {
                    changed.push((name.as_str(), old.as_str(), val.as_str()));
                }
            }
            _ => {}
        }
    }
    for name in base.keys() {
        if !cur.contains_key(name) {
            removed.push(name.as_str());
        }
    }
    println!(
        "baseline {}: {} symbols | current {}: {} symbols",
        baseline.display(),
        base.len(),
        current.display(),
        cur.len()
    );
    if !bad.is_empty() {
        println!("!! {} hardening/debug symbol(s) turned ON:", bad.len());
        for (n, w, now) in &bad {
            println!("   {n}: {w} -> {now}");
        }
    } else {
        println!("ok: no hardening/debug symbol newly enabled");
    }
    if !changed.is_empty() {
        let s: Vec<String> = changed.iter().take(15).map(|(n, w, v)| format!("{n}:{w}->{v}")).collect();
        println!("{} other change(s): {}", changed.len(), s.join(", "));
    }
    if !removed.is_empty() {
        println!("{} removed: {}", removed.len(), removed.iter().take(10).copied().collect::<Vec<_>>().join(", "));
    }
    if bad.is_empty() { 0 } else { 1 }
}

// ---------------------------------------------------------- CLO delta helper

pub fn cmd_clo_delta(ctx: &Ctx, clo_ref: &str, stable_ref: Option<&str>) -> i32 {
    let head_log = git(ctx, &["log", "--no-merges", "-n", "12000", "--format=%s", "HEAD"]);
    let already: HashSet<String> = head_log.lines().map(norm_subj).collect();

    let rng = format!("HEAD..{clo_ref}");
    let not_st = stable_ref.map(|s| format!("^{s}"));
    let mut args = vec!["log", "--no-merges", "--reverse", "--format=%h\t%ad\t%s", "--date=short", &rng];
    if let Some(ref ns) = not_st {
        args.push(ns);
    }
    let noise = [
        "abi_gki", "symbol list", "protected exports", "kmi", "kleaf", "bazel",
        "build:", "monaco", "parrot", "canoe", "anorak", "blair", "kera", "pitti",
        "ravelin", "montague", "sm4450", "wear_config", "selftests", "utsrelease.h",
        "[dnm]", "pixel", "galaxy", "realtek phy", "qca81xx", "sunp iot",
    ];
    let out = git(ctx, &args);
    let mut hits = Vec::new();
    for ln in out.lines() {
        let p: Vec<&str> = ln.splitn(3, '\t').collect();
        if p.len() < 3 {
            continue;
        }
        let (h, d, s) = (p[0], p[1], p[2]);
        let sl = s.to_ascii_lowercase();
        if already.contains(&norm_subj(s)) || s.starts_with("Revert ") || noise.iter().any(|k| sl.contains(k)) {
            continue;
        }
        hits.push((h, d, s));
    }
    println!("=== CLO delta ({clo_ref}): {} candidate commits ===", hits.len());
    for (h, d, s) in hits {
        println!("  {h} {d} {s}");
    }
    0
}

// ----------------------------------------------------------- all-in-one check

pub fn cmd_check(ctx: &Ctx, base: &str, tag: &str, all_files: bool) -> i32 {
    let mut rc = 0;
    rc |= cmd_markers(ctx);
    rc |= cmd_dangle(ctx, Some((base, "HEAD")), !all_files);
    rc |= cmd_landmines(ctx, base, tag);
    rc |= cmd_vendorapi(ctx, base, tag);
    rc |= cmd_partial(ctx, base, tag, !all_files);
    rc
}
