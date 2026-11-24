use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;

use crate::gate;
use crate::util::*;
use crate::verify;

// ====================================================== 1. UAPI & KABI AUDIT

/// Check `include/uapi/` & `arch/arm64/include/uapi/` for ABI-breaking mutations that
/// would crash prebuilt userspace vendor HALs (`/vendor/lib64/*.so`, camera/display/audio/RIL).
pub fn audit_uapi_diff(diff: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let mut cur_file: Option<String> = None;
    let mut cur_hunk = String::new();
    let mut in_uapi = false;

    // Track per-hunk removed vs added lines to distinguish safe additions from breaking mutations
    let mut hunk_dels: Vec<String> = Vec::new();
    let mut hunk_adds: Vec<String> = Vec::new();

    let flush_hunk = |file: &Option<String>,
                      hunk_hdr: &str,
                      dels: &mut Vec<String>,
                      adds: &mut Vec<String>,
                      out: &mut Vec<String>| {
        let Some(f) = file else {
            dels.clear();
            adds.clear();
            return;
        };
        // 1. Removed or mutated UAPI struct/union field declarations
        for d in dels.iter() {
            let clean = strip_c_comments(d).trim();
            if clean.is_empty() {
                continue;
            }
            // Changed #define value or _IO* ioctl number
            if clean.starts_with("#define ") || clean.starts_with("# define ") {
                if let Some(name) = extract_uapi_macro(clean) {
                    // Check if re-defined with a different value
                    let matching_add = adds
                        .iter()
                        .map(|a| strip_c_comments(a).trim())
                        .find(|a| extract_uapi_macro(a).as_deref() == Some(name.as_str()));
                    match matching_add {
                        None => {
                            out.push(format!("{f}: UAPI macro REMOVED `#define {name}`"));
                        }
                        Some(a) if normalize_ws(a) != normalize_ws(clean) => {
                            out.push(format!(
                                "{f}: UAPI macro VALUE CHANGED `{}` -> `{}`",
                                truncate_str(clean, 55),
                                truncate_str(a, 55)
                            ));
                        }
                        _ => {}
                    }
                }
                continue;
            }
            // Removed/retyped struct field (`type name;` or `type name[N];`) inside a UAPI struct
            if d.starts_with('\t') && clean.ends_with(';') && !clean.contains('(') {
                let exact_still_present = adds.iter().any(|a| normalize_ws(strip_c_comments(a).trim()) == normalize_ws(clean));
                if !exact_still_present {
                    // Safe if it's purely renaming a reserved/padding field of same type (e.g. __u32 reserved -> __u32 flags)
                    let is_pad = clean.contains("reserved") || clean.contains("resvd") || clean.contains("pad");
                    if !is_pad {
                        out.push(format!(
                            "{f} ({}): UAPI struct field REMOVED/MODIFIED: `{}`",
                            truncate_str(hunk_hdr, 45),
                            truncate_str(clean, 65)
                        ));
                    }
                }
            }
        }
        dels.clear();
        adds.clear();
    };

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            flush_hunk(&cur_file, &cur_hunk, &mut hunk_dels, &mut hunk_adds, &mut findings);
            let f = p.trim();
            in_uapi = f.starts_with("include/uapi/") || f.starts_with("arch/arm64/include/uapi/");
            cur_file = if in_uapi { Some(f.to_string()) } else { None };
            cur_hunk.clear();
            continue;
        }
        if !in_uapi {
            continue;
        }
        if ln.starts_with("@@ ") {
            flush_hunk(&cur_file, &cur_hunk, &mut hunk_dels, &mut hunk_adds, &mut findings);
            cur_hunk = ln.split("@@").nth(2).unwrap_or("").trim().to_string();
        } else if let Some(r) = ln.strip_prefix('-') {
            if !ln.starts_with("---") {
                hunk_dels.push(r.to_string());
            }
        } else if let Some(r) = ln.strip_prefix('+') {
            if !ln.starts_with("+++") {
                hunk_adds.push(r.to_string());
            }
        }
    }
    flush_hunk(&cur_file, &cur_hunk, &mut hunk_dels, &mut hunk_adds, &mut findings);
    findings
}

fn extract_uapi_macro(s: &str) -> Option<String> {
    let rest = s.trim_start().strip_prefix('#')?.trim_start().strip_prefix("define")?.trim_start();
    let b = rest.as_bytes();
    if b.is_empty() || !is_ident_start(b[0]) {
        return None;
    }
    let mut i = 0;
    while i < b.len() && is_ident_char(b[i]) {
        i += 1;
    }
    Some(rest[..i].to_string())
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Detect structs in `include/` whose layout (fields) changed in `base..head` + check
/// `ANDROID_KABI_RESERVE` drops + `sm8735-modules` `KERNEL_VERSION(6, 7..19)` traps!
pub fn run_abi_audit(ctx: &Ctx, base: &str, head: &str) -> (i32, String) {
    println!("=== abi-audit: UAPI stability, include/ struct layout & module version traps ({base}..{head}) ===");

    // 1. UAPI ABI check
    let uapi_diff = git(
        ctx,
        &["diff", "-U3", base, head, "--", "include/uapi/", "arch/arm64/include/uapi/"],
    );
    let uapi_hits = audit_uapi_diff(&uapi_diff);
    if uapi_hits.is_empty() {
        println!("  uapi      : clean (0 breaking UAPI struct/ioctl/macro mutations)");
    } else {
        println!("  !! UAPI ABI DRIFT ({} finding(s) — verify prebuilt vendor HALs!):", uapi_hits.len());
        for h in uapi_hits.iter().take(20) {
            println!("     {h}");
        }
    }

    // 2. Kernel `include/` struct layout changes (useful when auditing KABI / modules ABI)
    let inc_diff = git(ctx, &["diff", "-U0", base, head, "--", "include/linux/", "include/net/", "include/scsi/", "include/sound/"]);
    let mut changed_structs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut dropped_kabi = Vec::new();
    let mut cur_file: Option<String> = None;
    let mut cur_struct = String::new();

    for ln in inc_diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur_file = Some(p.trim().to_string());
            cur_struct.clear();
            continue;
        }
        let Some(ref f) = cur_file else { continue };
        if ln.starts_with("@@ ") {
            let hdr = ln.split("@@").nth(2).unwrap_or("").trim();
            if let Some(idx) = hdr.find("struct ") {
                let sname: String = hdr[idx + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                cur_struct = sname;
            } else {
                cur_struct.clear();
            }
            continue;
        }
        if let Some(r) = ln.strip_prefix('-') {
            if !ln.starts_with("---") {
                if r.contains("ANDROID_KABI_RESERVE") || r.contains("ANDROID_OEM_DATA") {
                    dropped_kabi.push(format!("{f} (struct {cur_struct}): removed `{}`", r.trim()));
                }
                if !cur_struct.is_empty() && r.starts_with('\t') && gate::parse_removed_header_decl(ln).is_some() {
                    changed_structs.entry(cur_struct.clone()).or_default().insert(f.clone());
                }
            }
        } else if let Some(r) = ln.strip_prefix('+') {
            if !ln.starts_with("+++") && !cur_struct.is_empty() && r.starts_with('\t') {
                let fake = format!("-{r}");
                if gate::parse_removed_header_decl(&fake).is_some() {
                    changed_structs.entry(cur_struct.clone()).or_default().insert(f.clone());
                }
            }
        }
    }

    // Cross-check which layout-changed kernel structs are referenced by sm8735-modules
    let mut mod_touched_structs = Vec::new();
    if !changed_structs.is_empty() && ctx.is_default_kernel && ctx.modules.is_dir() {
        let names: Vec<String> = changed_structs.keys().cloned().collect();
        for chunk in names.chunks(40) {
            let pat = format!(r"\bstruct\s+({})\b", chunk.join("|"));
            let (_, out) = rg(&ctx.modules, &["-o", "--no-filename", "-g", "*.c", "-g", "*.h", &pat]);
            let hits = extract_bare_idents(&out);
            for n in chunk {
                if hits.contains(n) {
                    let hdrs: Vec<String> = changed_structs[n].iter().cloned().collect();
                    mod_touched_structs.push(format!("struct {n} ({})", hdrs.join(", ")));
                }
            }
        }
    }
    println!(
        "  kabi-layout: {} kernel structs changed layout ({} referenced by sm8735-modules — rebuild all .ko together!)",
        changed_structs.len(),
        mod_touched_structs.len()
    );
    if !mod_touched_structs.is_empty() {
        for s in mod_touched_structs.iter().take(12) {
            println!("     {s}");
        }
        if mod_touched_structs.len() > 12 {
            println!("     ... (+{} more)", mod_touched_structs.len() - 12);
        }
    }
    if !dropped_kabi.is_empty() {
        println!("  INFO dropped KABI/OEM reserve slots ({}):", dropped_kabi.len());
        for d in dropped_kabi.iter().take(8) {
            println!("     {d}");
        }
    }

    // 3. `sm8735-modules` LINUX_VERSION_CODE(6, 7..19) guards vs changed include/ symbols
    let mut ver_traps = Vec::new();
    if ctx.is_default_kernel && ctx.modules.is_dir() {
        // Extract identifiers whose signatures changed in include/
        let mut changed_apis: HashSet<String> = HashSet::new();
        for ln in inc_diff.lines() {
            if (ln.starts_with('+') && !ln.starts_with("+++")) || (ln.starts_with('-') && !ln.starts_with("---")) {
                for c in extract_calls(&ln[1..], 6) {
                    changed_apis.insert(c);
                }
            }
        }
        if !changed_apis.is_empty() {
            let (_, vout) = rg(
                &ctx.modules,
                &["-n", "-C", "5", "-g", "*.c", "-g", "*.h", r"KERNEL_VERSION\(\s*6,\s*([7-9]|1[0-9]),"],
            );
            let mut seen_trap: BTreeSet<String> = BTreeSet::new();
            let mut cur_guard = String::new();
            for ln in vout.lines() {
                if ln == "--" {
                    cur_guard.clear();
                    continue;
                }
                if ln.contains("KERNEL_VERSION(") {
                    cur_guard = ln.to_string();
                    continue;
                }
                if !cur_guard.is_empty() {
                    for c in extract_calls(ln, 6) {
                        if changed_apis.contains(&c) {
                            seen_trap.insert(format!("{c}() near `{}`", truncate_str(cur_guard.trim(), 90)));
                        }
                    }
                }
            }
            ver_traps.extend(seen_trap);
        }
    }
    if ver_traps.is_empty() {
        println!("  ver-guards: clean (0 sm8735-modules KERNEL_VERSION(6,7..19) traps hit changed kernel APIs)");
    } else {
        println!("  WARN ver-guards ({} sm8735-modules version-guarded APIs also changed in kernel!):", ver_traps.len());
        for t in ver_traps.iter().take(15) {
            println!("     {t}");
        }
    }

    let summary = format!(
        "uapi={} structs={}({} in modules) ver-traps={}",
        uapi_hits.len(),
        changed_structs.len(),
        mod_touched_structs.len(),
        ver_traps.len()
    );
    (if uapi_hits.is_empty() { 0 } else { 1 }, summary)
}

pub fn cmd_abi_audit(ctx: &Ctx, base: &str, head: &str) -> i32 {
    run_abi_audit(ctx, base, head).0
}

// ====================================================== 2. PER-FUNCTION SEMANTIC RUNTIME-BUG AUDIT

#[derive(Debug)]
pub struct CFunc<'a> {
    pub name: String,
    pub start_1b: usize,
    pub lines: &'a [&'a str],
}

/// Split a C source file into top-level functions by tracking brace depth.
pub fn split_c_functions<'a>(lines: &'a [&'a str]) -> Vec<CFunc<'a>> {
    let mut funcs = Vec::new();
    let mut i = 0;
    let n = lines.len();
    while i < n {
        let ln = lines[i];
        // Column-0 function header heuristic
        if !ln.is_empty()
            && !ln.as_bytes()[0].is_ascii_whitespace()
            && !matches!(ln.as_bytes()[0], b'#' | b'/' | b'*' | b'{' | b'}')
            && !ln.starts_with("struct ")
            && !ln.starts_with("enum ")
            && !ln.starts_with("union ")
            && !ln.starts_with("typedef ")
            && !ln.starts_with("EXPORT_")
            && !ln.starts_with("MODULE_")
            && ln.contains('(')
            && !strip_c_comments(ln).trim_end().ends_with(';')
        {
            // Look for opening '{' within next 5 lines
            let mut brace_line = None;
            for j in i..=(i + 5).min(n - 1) {
                let c = strip_c_comments(lines[j]);
                if c.contains(';') && !c.contains('{') {
                    break;
                }
                if c.contains('{') {
                    brace_line = Some(j);
                    break;
                }
            }
            if let Some(bl) = brace_line {
                // Extract function name
                let par = ln.find('(').unwrap();
                let before = ln[..par].trim_end();
                let b = before.as_bytes();
                let mut k = b.len();
                while k > 0 && is_ident_char(b[k - 1]) {
                    k -= 1;
                }
                let fname = &before[k..];
                if !fname.is_empty() && is_ident_start(fname.as_bytes()[0]) && !C_KEYWORDS.contains(&fname) {
                    // Walk until matching closing '}' at depth 0
                    let mut depth = 0i32;
                    let mut end = bl;
                    let mut in_blk = false;
                    for j in bl..n {
                        let raw = lines[j];
                        let t = raw.trim();
                        if in_blk {
                            if t.contains("*/") { in_blk = false; }
                            continue;
                        }
                        if t.starts_with("/*") && !t.contains("*/") { in_blk = true; continue; }
                        let c = strip_c_comments(raw);
                        for ch in c.bytes() {
                            if ch == b'{' { depth += 1; }
                            else if ch == b'}' { depth -= 1; }
                        }
                        end = j;
                        if depth <= 0 {
                            break;
                        }
                    }
                    funcs.push(CFunc {
                        name: fname.to_string(),
                        start_1b: i + 1,
                        lines: &lines[i..=end],
                    });
                    i = end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    funcs
}

const FUNC_LOCK_PAIRS: &[(&str, &str, &str)] = &[
    ("preempt", "preempt_disable", "preempt_enable"),
    ("rcu", "rcu_read_lock", "rcu_read_unlock"),
    ("srcu", "srcu_read_lock", "srcu_read_unlock"),
    ("irq", "local_irq_disable", "local_irq_enable"),
    ("spin_irq", "spin_lock_irqsave", "spin_unlock_irqrestore"),
    ("spin_lock", "spin_lock", "spin_unlock"),
    ("mutex", "mutex_lock", "mutex_unlock"),
    ("clk", "clk_prepare_enable", "clk_disable_unprepare"),
];

fn count_exact_call(lines: &[&str], ident: &str) -> usize {
    let mut n = 0usize;
    for ln in lines {
        let c = strip_c_comments(ln);
        for call in extract_calls(c, 5) {
            if call == ident || call == format!("{ident}_notrace") || call == format!("{ident}_nested") {
                n += 1;
            }
        }
    }
    n
}

/// Detect potential Use-After-Free in a C function: `kfree(X)` or `kref_put(&X->...)`
/// followed in the same indentation/block by `X->` without reassigning `X` or exiting.
pub fn scan_func_uaf(path: &str, func: &CFunc<'_>, added_lines: &HashSet<usize>) -> Vec<String> {
    let mut hits = Vec::new();
    let mut freed: Option<(String, usize, usize)> = None; // (var_name, line_1b, indent)

    for (idx, raw) in func.lines.iter().enumerate() {
        let lno = func.start_1b + idx;
        let code = strip_c_comments(raw);
        let trim = code.trim();
        let indent = raw.len() - raw.trim_start().len();

        if trim.is_empty() || trim.starts_with('#') {
            continue;
        }
        // Reset freed tracking at control-flow boundaries or outer scopes
        if trim.starts_with("return")
            || trim.starts_with("goto ")
            || trim.starts_with("break;")
            || trim.starts_with("continue;")
            || trim.starts_with("else")
            || trim.starts_with("case ")
            || trim.starts_with("default:")
            || trim.ends_with(':')
        {
            freed = None;
            continue;
        }
        if let Some((ref var, free_lno, free_indent)) = freed {
            if trim.starts_with('}') && indent < free_indent {
                // Only clear if exiting the enclosing block (keep tracking if an `if` closed above and outer code follows!)
                // Actually: if `kref_put` was inside `if (...) { ... kref_put(X); }`, code AFTER `}` at LOWER indent
                // CAN still hit UAF (literally the qcom_glink_native.c bug!!).
                // So only clear if we hit an `else` or `return`/`goto` or reassignment!
            }
            // Check reassignment (`var = ...`)
            if trim.starts_with(&format!("{var} =")) || trim.starts_with(&format!("{var}=")) {
                freed = None;
                continue;
            }
            // Check dereference `var->`!
            if code.contains(&format!("{var}->")) && (added_lines.contains(&lno) || added_lines.contains(&free_lno)) {
                hits.push(format!(
                    "{path}:L{lno} in `{}`: dereferences `{var}->` after free/kref_put at L{free_lno}",
                    func.name
                ));
                freed = None;
                continue;
            }
        }

        // Detect `kfree(var);` or `kref_put(&var->..., ...)`
        if let Some(arg) = extract_freed_var(trim) {
            if arg.len() >= 2 && arg != "NULL" {
                freed = Some((arg, lno, indent));
            }
        }
    }
    hits
}

fn extract_freed_var(trim: &str) -> Option<String> {
    if let Some(rest) = trim.strip_prefix("kfree(") {
        let var = rest.split(')').next()?.trim();
        if var.bytes().all(is_ident_char) && !var.is_empty() {
            return Some(var.to_string());
        }
    }
    if let Some(rest) = trim.strip_prefix("kref_put(&") {
        let var = rest.split("->").next()?.trim();
        if var.bytes().all(is_ident_char) && !var.is_empty() {
            return Some(var.to_string());
        }
    }
    None
}

/// Detect newly added early `return` inside a function while a lock (srcu/rcu/spin/mutex)
/// was acquired at outer scope and is only unlocked at the end of the function!
pub fn scan_func_early_return_under_lock(path: &str, func: &CFunc<'_>, added_lines: &HashSet<usize>) -> Vec<String> {
    let mut hits = Vec::new();
    for &(label, acq, rel) in &[
        ("srcu", "srcu_read_lock", "srcu_read_unlock"),
        ("rcu", "rcu_read_lock", "rcu_read_unlock"),
        ("mutex", "mutex_lock", "mutex_unlock"),
        ("spin_irq", "spin_lock_irqsave", "spin_unlock_irqrestore"),
    ] {
        // Find first acquire and last release line index inside func
        let first_acq = func.lines.iter().position(|l| {
            let c = strip_c_comments(l);
            extract_calls(c, 5).iter().any(|x| x == acq)
        });
        let last_rel = func.lines.iter().rposition(|l| {
            let c = strip_c_comments(l);
            extract_calls(c, 5).iter().any(|x| x == rel)
        });
        let (Some(a_idx), Some(r_idx)) = (first_acq, last_rel) else { continue };
        if a_idx >= r_idx {
            continue;
        }
        // Only apply when there is exactly 1 acquire & 1 release (clear single lock region)
        if count_exact_call(func.lines, acq) != 1 || count_exact_call(func.lines, rel) != 1 {
            continue;
        }
        for idx in (a_idx + 1)..r_idx {
            let lno = func.start_1b + idx;
            if !added_lines.contains(&lno) {
                continue;
            }
            let trim = strip_c_comments(func.lines[idx]).trim();
            if trim.starts_with("return ") || trim == "return;" {
                // Check previous 2 lines didn't unlock
                let prev_unlocked = func.lines[a_idx.max(idx.saturating_sub(2))..idx]
                    .iter()
                    .any(|p| p.contains(rel));
                if !prev_unlocked {
                    hits.push(format!(
                        "{path}:L{lno} in `{}`: added `{}` while `{label}` lock (L{}) not yet unlocked (unlock at L{})",
                        func.name,
                        truncate_str(trim, 30),
                        func.start_1b + a_idx,
                        func.start_1b + r_idx
                    ));
                }
            }
        }
    }
    hits
}

pub fn run_sem_audit(
    ctx: &Ctx,
    base: &str,
    head: &str,
    up_to: Option<&str>,
) -> (i32, String) {
    println!("=== sem-audit: per-function lock-balance, early-return-under-lock & UAF ({base}..{head}) ===");
    let diff = git(ctx, &["diff", "-U0", base, head, "--", "*.c"]);
    let added_map = verify::parse_added_lines_by_file(&diff);

    // Focus on conflict-resolved (--cc) OR non-upstream-identical built `.c` files
    let diff_vs_up: Option<HashSet<String>> = up_to.map(|t| {
        git(ctx, &["diff", "--name-only", t, head])
            .lines()
            .map(|s| s.to_string())
            .collect()
    });
    let cc_files: HashSet<String> = git(
        ctx,
        &["log", "--first-parent", "--merges", "--cc", "--name-only", "--format=", &format!("{base}..{head}")],
    )
    .lines()
    .map(|s| s.trim().to_string())
    .filter(|s| s.ends_with(".c"))
    .collect();

    let mut files: Vec<String> = added_map
        .keys()
        .filter(|f| {
            f.ends_with(".c")
                && is_built_file(ctx, f)
                && diff_vs_up.as_ref().map_or(true, |set| set.contains(*f))
        })
        .cloned()
        .collect();
    files.sort();

    let per_file: Vec<(Vec<String>, Vec<String>, Vec<String>)> = par_map(&files, ctx.threads, |path| {
        let mut lock_hits = Vec::new();
        let mut ret_hits = Vec::new();
        let mut uaf_hits = Vec::new();

        let Ok(head_txt) = fs::read_to_string(ctx.repo.join(path)) else {
            return (lock_hits, ret_hits, uaf_hits);
        };
        let added = match added_map.get(path) {
            Some(s) => s,
            None => return (lock_hits, ret_hits, uaf_hits),
        };
        let h_lines: Vec<&str> = head_txt.lines().collect();
        let h_funcs = split_c_functions(&h_lines);

        // Per-function UAF & early-return-under-lock on every touched function
        for f in &h_funcs {
            let f_end = f.start_1b + f.lines.len();
            if !(f.start_1b..f_end).any(|l| added.contains(&l)) {
                continue;
            }
            ret_hits.extend(scan_func_early_return_under_lock(path, f, added));
            uaf_hits.extend(scan_func_uaf(path, f, added));
        }

        // Per-function lock-balance comparison on --cc conflict-resolved files
        if cc_files.contains(path) {
            let base_txt = git(ctx, &["show", &format!("{base}:{path}")]);
            let up_txt = up_to.map(|t| git(ctx, &["show", &format!("{t}:{path}")]));
            if !base_txt.is_empty() {
                let b_lines: Vec<&str> = base_txt.lines().collect();
                let b_map: HashMap<String, CFunc<'_>> = split_c_functions(&b_lines)
                    .into_iter()
                    .map(|f| (f.name.clone(), f))
                    .collect();
                let u_lines: Vec<&str> = up_txt.as_deref().unwrap_or("").lines().collect();
                let u_map: HashMap<String, CFunc<'_>> = split_c_functions(&u_lines)
                    .into_iter()
                    .map(|f| (f.name.clone(), f))
                    .collect();

                for f in &h_funcs {
                    let f_end = f.start_1b + f.lines.len();
                    if !(f.start_1b..f_end).any(|l| added.contains(&l)) {
                        continue;
                    }
                    let Some(bf) = b_map.get(&f.name) else { continue };
                    for &(label, acq, rel) in FUNC_LOCK_PAIRS {
                        // Only check lock pairs that were actually touched on an added line in this function
                        let lock_touched = f.lines.iter().enumerate().any(|(idx, ln)| {
                            added.contains(&(f.start_1b + idx)) && (ln.contains(acq) || ln.contains(rel))
                        });
                        if !lock_touched {
                            continue;
                        }
                        let old_d = count_exact_call(bf.lines, acq) as isize - count_exact_call(bf.lines, rel) as isize;
                        let new_d = count_exact_call(f.lines, acq) as isize - count_exact_call(f.lines, rel) as isize;
                        if new_d.abs() > old_d.abs() && new_d != 0 {
                            let matches_up = u_map.get(&f.name).is_some_and(|uf| {
                                (count_exact_call(uf.lines, acq) as isize - count_exact_call(uf.lines, rel) as isize) == new_d
                            });
                            if !matches_up {
                                lock_hits.push(format!(
                                    "{path}:L{} `{}`: {label} imbalance shifted ({old_d:+} -> {new_d:+})",
                                    f.start_1b, f.name
                                ));
                            }
                        }
                    }
                }
            }
        }

        (lock_hits, ret_hits, uaf_hits)
    });

    let mut locks = Vec::new();
    let mut rets = Vec::new();
    let mut uafs = Vec::new();
    for (l, r, u) in per_file {
        locks.extend(l);
        rets.extend(r);
        uafs.extend(u);
    }

    println!("    analyzed {} non-upstream-identical built .c files", files.len());
    if locks.is_empty() && rets.is_empty() && uafs.is_empty() {
        println!("  clean: 0 per-func lock imbalances, 0 early-return lock leaks, 0 post-free UAF patterns");
        return (0, "0 lock-imbal, 0 ret-leak, 0 uaf".into());
    }
    for x in &locks {
        println!("  FUNC LOCK  {x}");
    }
    for x in &rets {
        println!("  RET LEAK   {x}");
    }
    for x in &uafs {
        println!("  POST-FREE  {x}");
    }
    let summary = format!("{} lock-imbal, {} ret-leak, {} uaf", locks.len(), rets.len(), uafs.len());
    (1, summary)
}

pub fn cmd_sem_audit(ctx: &Ctx, base: &str, head: &str, up_to: Option<&str>) -> i32 {
    run_sem_audit(ctx, base, head, up_to).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uapi_struct_and_macro_drift() {
        let diff = r#"diff --git a/include/uapi/linux/test.h b/include/uapi/linux/test.h
--- a/include/uapi/linux/test.h
+++ b/include/uapi/linux/test.h
@@ -10,3 +10,3 @@ struct foo_ioctl {
-	__u32 old_field;
+	__u64 old_field;
-#define FOO_IOCTL_CMD _IOW('f', 1, struct foo_ioctl)
+#define FOO_IOCTL_CMD _IOW('f', 2, struct foo_ioctl)
"#;
        let hits = audit_uapi_diff(diff);
        assert_eq!(hits.len(), 2, "expected both field & macro drift: {hits:?}");
    }

    #[test]
    fn test_uaf_after_kref_put_catches_glink_bug() {
        let src = r#"static void qcom_glink_rx_close_ack(struct qcom_glink *glink)
{
	if (is_fully_closed) {
		kref_put(&channel->refcount, release);
	}
	reinit_completion(&channel->open_ack);
}
"#;
        let lines: Vec<&str> = src.lines().collect();
        let funcs = split_c_functions(&lines);
        assert_eq!(funcs.len(), 1);
        let added: HashSet<usize> = [4, 6].into_iter().collect();
        let hits = scan_func_uaf("glink.c", &funcs[0], &added);
        assert_eq!(hits.len(), 1, "expected UAF hit: {hits:?}");
    }

    #[test]
    fn test_early_return_under_srcu_lock_catches_eventfs_bug() {
        let src = r#"static int eventfs_iterate(struct file *f)
{
	idx = srcu_read_lock(&eventfs_srcu);
	if (ei->is_freed)
		return -EINVAL;
	srcu_read_unlock(&eventfs_srcu, idx);
	return 0;
}
"#;
        let lines: Vec<&str> = src.lines().collect();
        let funcs = split_c_functions(&lines);
        let added: HashSet<usize> = [5].into_iter().collect();
        let hits = scan_func_early_return_under_lock("event_inode.c", &funcs[0], &added);
        assert_eq!(hits.len(), 1, "expected early-return lock leak: {hits:?}");
    }
}
