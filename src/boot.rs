use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::device;
use crate::elf;
use crate::gate;
use crate::util::*;
use crate::verify;

// ------------------------------------------------------ 1. Boot blast-radius tiers

const TIER0_PREFIXES: &[&str] = &[
    "arch/arm64/mm/",
    "arch/arm64/kernel/",
    "arch/arm64/include/asm/",
    "init/",
    "drivers/ufs/",
    "drivers/soc/qcom/rpmh",
    "drivers/soc/qcom/cmd-db",
    "drivers/soc/qcom/smem",
    "drivers/soc/qcom/smp2p",
    "drivers/soc/qcom/ice",
    "drivers/soc/qcom/qcom_aoss",
    "drivers/soc/qcom/memshare",
    "drivers/rpmsg/qcom_glink",
    "drivers/clk/qcom/",
    "drivers/regulator/",
    "drivers/spmi/",
    "drivers/firmware/qcom_scm",
    "drivers/iommu/",
    "drivers/thermal/qcom/tsens",
    "drivers/base/power/",
    "drivers/cpuidle/",
    "drivers/cpufreq/qcom",
];

const TIER1_PREFIXES: &[&str] = &[
    "mm/",
    "fs/f2fs/",
    "fs/erofs/",
    "fs/ext4/",
    "fs/fuse/",
    "fs/crypto/",
    "kernel/sched/",
    "kernel/cgroup/",
    "kernel/rcu/",
    "kernel/locking/",
    "kernel/irq/",
    "kernel/time/",
    "kernel/fork.c",
    "kernel/exit.c",
    "kernel/signal.c",
    "kernel/softirq.c",
    "drivers/android/binder",
    "drivers/dma-buf/",
    "block/",
    "drivers/md/",
    "net/qrtr/",
];

const TIER2_PREFIXES: &[&str] = &[
    "drivers/gpu/",
    "drivers/usb/",
    "drivers/pci/",
    "drivers/tty/serial/msm",
    "drivers/input/",
    "drivers/power/",
    "drivers/remoteproc/",
    "drivers/nvmem/",
    "sound/",
    "net/bluetooth/",
    "net/wireless/",
    "net/ipv4/",
    "net/ipv6/",
];

fn boot_tier(path: &str) -> Option<(u8, &'static str)> {
    if TIER0_PREFIXES.iter().any(|p| path.starts_with(p)) {
        Some((0, "TIER-0 EARLY-BOOT"))
    } else if TIER1_PREFIXES.iter().any(|p| path.starts_with(p)) {
        Some((1, "TIER-1 CORE/FS/MM"))
    } else if TIER2_PREFIXES.iter().any(|p| path.starts_with(p)) {
        Some((2, "TIER-2 SUBSYSTEM "))
    } else {
        None
    }
}

fn diff_touched_funcs(diff: &str) -> HashMap<String, BTreeSet<String>> {
    let mut map: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut cur: Option<String> = None;
    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur = Some(p.trim().to_string());
        } else if ln.starts_with("@@ ") {
            if let Some(ref f) = cur {
                if let Some(idx) = ln.rfind("@@") {
                    let tail = ln[idx + 2..].trim();
                    if !tail.is_empty() && tail.contains('(') {
                        // Extract just function name
                        if let Some(par) = tail.find('(') {
                            let before = tail[..par].trim_end();
                            let b = before.as_bytes();
                            let mut i = b.len();
                            while i > 0 && is_ident_char(b[i - 1]) {
                                i -= 1;
                            }
                            let name = &before[i..];
                            if !name.is_empty() && !C_KEYWORDS.contains(&name) {
                                map.entry(f.clone()).or_default().insert(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

// ------------------------------------------------------ 2. Moved-block double execution

fn check_moved_dups(ctx: &Ctx, from: &str, to: &str, base: &str, cc_files: &HashSet<String>) -> Vec<String> {
    if cc_files.is_empty() {
        return Vec::new();
    }
    let up_diff = git(ctx, &["diff", "-U0", from, to, "--", "*.c"]);
    let mut per_file_adds: HashMap<String, HashSet<String>> = HashMap::new();
    let mut per_file_dels: HashMap<String, HashSet<String>> = HashMap::new();
    let mut cur: Option<String> = None;

    for ln in up_diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur = Some(p.trim().to_string());
            continue;
        }
        let Some(ref f) = cur else { continue };
        if !cc_files.contains(f) {
            continue;
        }
        let (is_add, body) = if let Some(r) = ln.strip_prefix('+') {
            if ln.starts_with("+++") { continue; }
            (true, r)
        } else if let Some(r) = ln.strip_prefix('-') {
            if ln.starts_with("---") { continue; }
            (false, r)
        } else {
            continue;
        };
        let t = strip_c_comments(body).trim();
        // Look for distinctive non-trivial moved statements (calls/assignments >= 22 chars)
        if t.len() < 22 || !t.ends_with(';') || !(t.contains('(') || t.contains('=')) {
            continue;
        }
        if t.starts_with("return ")
            || t.starts_with("goto ")
            || t.starts_with("struct ")
            || t.starts_with("const ")
            || t.starts_with("unsigned ")
            || t.starts_with("int ")
            || t.starts_with("u8 ")
            || t.starts_with("u16 ")
            || t.starts_with("u32 ")
            || t.starts_with("u64 ")
            || t.starts_with("bool ")
            || t.starts_with("pr_")
            || t.starts_with("dev_")
            || t.starts_with("trace_")
            || t.starts_with("WARN_")
            || t.starts_with("BUG_")
            || t.starts_with("kfree(")
            || t.starts_with("mutex_unlock(")
            || t.starts_with("spin_unlock")
            || t.starts_with("rcu_read_unlock")
            || t.starts_with("put_")
            || t.starts_with("fput(")
            || t.starts_with("dput(")
        {
            continue;
        }
        if is_add {
            per_file_adds.entry(f.clone()).or_default().insert(t.to_string());
        } else {
            per_file_dels.entry(f.clone()).or_default().insert(t.to_string());
        }
    }

    let mut moved_by_file: Vec<(String, Vec<String>)> = Vec::new();
    for (f, adds) in &per_file_adds {
        if let Some(dels) = per_file_dels.get(f) {
            let moved: Vec<String> = adds.intersection(dels).cloned().collect();
            if !moved.is_empty() {
                moved_by_file.push((f.clone(), moved));
            }
        }
    }
    moved_by_file.sort_by(|a, b| a.0.cmp(&b.0));

    let hits_nested: Vec<Vec<String>> = par_map(&moved_by_file, ctx.threads, |(f, stmts)| {
        let mut out = Vec::new();
        let Ok(head_txt) = fs::read_to_string(ctx.repo.join(f)) else { return out };
        let base_txt = git(ctx, &["show", &format!("{base}:{f}")]);
        let up_txt = git(ctx, &["show", &format!("{to}:{f}")]);
        if base_txt.is_empty() || up_txt.is_empty() {
            return out;
        }
        let count_stmt = |txt: &str, needle: &str| -> usize {
            txt.lines()
                .filter(|ln| strip_c_comments(ln).trim() == needle)
                .count()
        };
        for st in stmts {
            let c_head = count_stmt(&head_txt, st);
            let c_base = count_stmt(&base_txt, st);
            let c_up = count_stmt(&up_txt, st);
            // If HEAD now has MORE copies than BOTH base and upstream target, the moved block was duplicated!
            if c_head > c_base && c_head > c_up {
                out.push(format!(
                    "{f}: moved stmt duplicated (base={c_base}, up={c_up}, HEAD={c_head}): `{}`",
                    truncate_str(st, 72)
                ));
            }
        }
        out
    });
    hits_nested.into_iter().flatten().collect()
}

// ------------------------------------------------------ 3. DT string binding check

const DT_APIS: &[&str] = &[
    "of_property_read_",
    "device_property_read_",
    "of_get_property(",
    "of_find_property(",
    "clk_get(",
    "devm_clk_get(",
    "devm_clk_get_optional(",
    "regulator_get(",
    "devm_regulator_get(",
    "devm_regulator_get_optional(",
    "reset_control_get",
    "devm_reset_control_get",
    "platform_get_irq_byname",
    "of_find_compatible_node(",
    "of_device_is_compatible(",
    ".compatible",
];

fn extract_quoted_dt_strings(line: &str) -> Vec<String> {
    let code = strip_c_comments(line);
    if !DT_APIS.iter().any(|api| code.contains(api)) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let b = code.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i < b.len() {
                let s = &code[start..i];
                if s.len() >= 3
                    && !s.contains('%')
                    && !s.contains(' ')
                    && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b',' | b'.'))
                {
                    out.push(s.to_string());
                }
            }
        }
        i += 1;
    }
    out
}

fn check_dt_strings(ctx: &Ctx, base: &str, head: &str) -> Vec<String> {
    if !ctx.is_default_kernel || !ctx.devicetrees.is_dir() {
        return Vec::new();
    }
    let diff = git(ctx, &["diff", "-U0", base, head, "--", "drivers/"]);
    let mut per_file_old: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut per_file_new: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut cur: Option<String> = None;

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur = Some(p.trim().to_string());
            continue;
        }
        let Some(ref f) = cur else { continue };
        if !is_built_file(ctx, f) {
            continue;
        }
        if let Some(r) = ln.strip_prefix('-') {
            if !ln.starts_with("---") {
                for s in extract_quoted_dt_strings(r) {
                    per_file_old.entry(f.clone()).or_default().insert(s);
                }
            }
        } else if let Some(r) = ln.strip_prefix('+') {
            if !ln.starts_with("+++") {
                for s in extract_quoted_dt_strings(r) {
                    per_file_new.entry(f.clone()).or_default().insert(s);
                }
            }
        }
    }

    // Focus on strings that CHANGED (old removed, new added in the same built driver file)
    let mut candidates: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    let mut all_strings: BTreeSet<String> = BTreeSet::new();
    for (f, old_set) in &per_file_old {
        let Some(new_set) = per_file_new.get(f) else { continue };
        let removed: Vec<String> = old_set.difference(new_set).cloned().collect();
        let added: Vec<String> = new_set.difference(old_set).cloned().collect();
        if !removed.is_empty() && !added.is_empty() {
            for s in removed.iter().chain(added.iter()) {
                all_strings.insert(s.clone());
            }
            candidates.push((f.clone(), removed, added));
        }
    }
    if all_strings.is_empty() {
        return Vec::new();
    }

    // Batch check which of these strings exist in sm8735-devicetrees/
    let mut in_dt: HashSet<String> = HashSet::new();
    let list: Vec<String> = all_strings.into_iter().collect();
    for chunk in list.chunks(40) {
        let escaped: Vec<String> = chunk.iter().map(|s| s.replace('.', r"\.")).collect();
        let pat = format!(r#""({})""#, escaped.join("|"));
        let (_, out) = rg(&ctx.devicetrees, &["-o", "--no-filename", &pat]);
        for ln in out.lines() {
            let trimmed = ln.trim().trim_matches('"');
            in_dt.insert(trimmed.to_string());
        }
        // Also check bare property names (e.g. `qcom,foo = <...>;`)
        let pat2 = format!(r"\b({})\s*[=;]", escaped.join("|"));
        let (_, out2) = rg(&ctx.devicetrees, &["-o", "--no-filename", &pat2]);
        for ln in out2.lines() {
            let trimmed = ln.trim().trim_end_matches(|c| c == '=' || c == ';' || c == ' ');
            in_dt.insert(trimmed.to_string());
        }
    }

    let mut findings = Vec::new();
    for (f, removed, added) in candidates {
        let old_in_dt: Vec<&String> = removed.iter().filter(|s| in_dt.contains(*s)).collect();
        let new_missing: Vec<&String> = added.iter().filter(|s| !in_dt.contains(*s)).collect();
        if !old_in_dt.is_empty() && !new_missing.is_empty() {
            findings.push(format!(
                "{f}: DT string changed! old IN sm8735-devicetrees {:?} -> new ABSENT {:?}",
                old_in_dt, new_missing
            ));
        }
    }
    findings
}

// ------------------------------------------------------ 4. Removed EXPORT_SYMBOL & vendor hooks

fn extract_paren_arg(line: &str, macro_prefix: &str) -> Option<String> {
    let idx = line.find(macro_prefix)?;
    let rest = &line[idx + macro_prefix.len()..];
    let end = rest.find(')')?;
    let sym = rest[..end].trim();
    if sym.len() >= 3 && sym.bytes().all(is_ident_char) {
        Some(sym.to_string())
    } else {
        None
    }
}

fn check_exports_and_hooks(ctx: &Ctx, base: &str, head: &str) -> (Vec<String>, Vec<String>) {
    let diff = git(ctx, &["diff", "-U0", base, head, "--", "*.c", "*.h"]);
    let mut rm_exports: BTreeMap<String, String> = BTreeMap::new();
    let mut add_exports: HashSet<String> = HashSet::new();
    let mut rm_hooks: BTreeMap<String, String> = BTreeMap::new();
    let mut add_hooks: HashSet<String> = HashSet::new();
    let mut cur: Option<String> = None;

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur = Some(p.trim().to_string());
            continue;
        }
        let Some(ref f) = cur else { continue };
        let is_del = ln.starts_with('-') && !ln.starts_with("---");
        let is_add = ln.starts_with('+') && !ln.starts_with("+++");
        if !is_del && !is_add {
            continue;
        }
        let code = strip_c_comments(&ln[1..]);

        // EXPORT_SYMBOL / EXPORT_SYMBOL_GPL / EXPORT_SYMBOL_NS_GPL
        for pfx in ["EXPORT_SYMBOL_GPL(", "EXPORT_SYMBOL(", "EXPORT_SYMBOL_NS_GPL(", "EXPORT_SYMBOL_NS("] {
            if let Some(arg) = extract_paren_arg(code, pfx) {
                let sym = arg.split(',').next().unwrap_or(&arg).trim().to_string();
                if is_del {
                    rm_exports.insert(sym, f.clone());
                } else {
                    add_exports.insert(sym);
                }
            }
        }

        // Android vendor hooks: trace_android_vh_* / trace_android_rvh_*
        for call in extract_calls(code, 16) {
            if call.starts_with("trace_android_vh_") || call.starts_with("trace_android_rvh_") {
                if is_del {
                    rm_hooks.insert(call, f.clone());
                } else {
                    add_hooks.insert(call);
                }
            }
        }
    }

    // Keep only truly removed exports (not re-added elsewhere in diff and not still exported in repo)
    let mut export_hits = Vec::new();
    let lost_exports: Vec<String> = rm_exports
        .keys()
        .filter(|s| !add_exports.contains(*s))
        .cloned()
        .collect();
    if !lost_exports.is_empty() && ctx.is_default_kernel && ctx.modules.is_dir() {
        // Verify they aren't still exported elsewhere in kernel
        let pat_exp = format!(r"EXPORT_SYMBOL[A-Z_]*\(\s*({})\b", lost_exports.join("|"));
        let (_, still_out) = rg(&ctx.repo, &["-o", "--no-filename", "-g", "*.c", "-g", "*.h", &pat_exp]);
        let still_set = extract_bare_idents(&still_out);
        let gone: Vec<String> = lost_exports.into_iter().filter(|s| !still_set.contains(s)).collect();

        if !gone.is_empty() {
            let pat_use = format!(r"\b({})\s*\(", gone.join("|"));
            let (_, mout) = rg(&ctx.modules, &["-n", "-g", "*.c", "-g", "*.h", &pat_use]);
            let mut by_sym: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for ln in mout.lines() {
                let p: Vec<&str> = ln.splitn(3, ':').collect();
                if p.len() == 3 {
                    for c in extract_calls(strip_c_comments(p[2]), 3) {
                        if gone.iter().any(|g| g == &c) {
                            by_sym.entry(c).or_default().push(format!("modules/{}:{}", p[0], p[1]));
                        }
                    }
                }
            }
            for (sym, locs) in by_sym {
                let from_f = rm_exports.get(&sym).map(|s| s.as_str()).unwrap_or("?");
                export_hits.push(format!(
                    "REMOVED EXPORT `{sym}` (from {from_f}) still called by: {}",
                    locs.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }

    // Check dropped vendor hooks still registered by modules or vendor drivers
    let mut hook_hits = Vec::new();
    let lost_hooks: Vec<String> = rm_hooks
        .keys()
        .filter(|h| !add_hooks.contains(*h))
        .cloned()
        .collect();
    if !lost_hooks.is_empty() {
        // Filter out hooks still called elsewhere in kernel
        let pat_call = format!(r"\b({})\s*\(", lost_hooks.join("|"));
        let (_, still_out) = rg(&ctx.repo, &["-o", "--no-filename", "-g", "*.c", "-g", "*.h", &pat_call]);
        let still_set = extract_bare_idents(&still_out);
        let gone: Vec<String> = lost_hooks.into_iter().filter(|h| !still_set.contains(h)).collect();

        if !gone.is_empty() {
            let regs: Vec<String> = gone
                .iter()
                .map(|h| format!("register_{}", h.trim_start_matches("trace_")))
                .collect();
            let pat_reg = format!(r"\b({})\s*\(", regs.join("|"));
            let mut check_dirs: Vec<(&str, &Path)> = vec![("kernel", &ctx.repo)];
            if ctx.is_default_kernel && ctx.modules.is_dir() {
                check_dirs.push(("modules", &ctx.modules));
            }
            for (label, dir) in check_dirs {
                let (_, out) = rg(dir, &["-n", "-g", "*.c", "-g", "*.h", &pat_reg]);
                for ln in out.lines().take(20) {
                    hook_hits.push(format!("DROPPED HOOK still registered in {label}: {ln}"));
                }
            }
        }
    }

    (export_hits, hook_hits)
}

// ------------------------------------------------------ Public: `ktool boot-risk`

pub fn run_boot_risk(
    ctx: &Ctx,
    from: Option<&str>,
    to: Option<&str>,
    base: &str,
) -> (i32, String) {
    println!("=== boot-risk: splash-hang / bootloop / DT-mismatch / ABI-guard ({base}..HEAD) ===");

    let diff_vs_up: Option<HashSet<String>> = to.map(|t| {
        git(ctx, &["diff", "--name-only", t, "HEAD"])
            .lines()
            .map(|s| s.to_string())
            .collect()
    });
    let cc_files: HashSet<String> = git(
        ctx,
        &["log", "--first-parent", "--merges", "--cc", "--name-only", "--format=", &format!("{base}..HEAD")],
    )
    .lines()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty() && is_c_source(s))
    .collect();

    let range_diff = git(ctx, &["diff", "--unified=0", base, "HEAD", "--", "*.c", "*.h"]);
    let funcs_map = diff_touched_funcs(&range_diff);

    // Collect non-upstream-identical built files touched in base..HEAD grouped by boot tier
    let mut tiered: BTreeMap<u8, Vec<(String, bool, String)>> = BTreeMap::new();
    for ln in git(ctx, &["diff", "--name-only", base, "HEAD"]).lines() {
        let f = ln.trim();
        if !is_c_source(f) || !is_built_file(ctx, f) {
            continue;
        }
        // Only highlight files that DIVERGE from upstream target (or all if no `to`)
        if let Some(ref set) = diff_vs_up {
            if !set.contains(f) {
                continue;
            }
        }
        if let Some((tier, _)) = boot_tier(f) {
            let is_cc = cc_files.contains(f);
            let fns = funcs_map
                .get(f)
                .map(|s| s.iter().take(4).cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            tiered.entry(tier).or_default().push((f.to_string(), is_cc, fns));
        }
    }

    let t0 = tiered.get(&0).map(|v| v.len()).unwrap_or(0);
    let t1 = tiered.get(&1).map(|v| v.len()).unwrap_or(0);
    let t2 = tiered.get(&2).map(|v| v.len()).unwrap_or(0);
    println!("  non-upstream-identical boot-path files: TIER-0={t0}, TIER-1={t1}, TIER-2={t2}");
    for (tier, label) in [(0u8, "TIER-0 EARLY-BOOT"), (1, "TIER-1 CORE/FS/MM")] {
        if let Some(list) = tiered.get(&tier) {
            for (f, is_cc, fns) in list.iter().take(20) {
                let tag = if *is_cc { "[--cc]" } else { "[auto]" };
                if fns.is_empty() {
                    println!("    {label} {tag} {f}");
                } else {
                    println!("    {label} {tag} {f}  ({fns})");
                }
            }
            if list.len() > 20 {
                println!("    ... (+{} more {label} files)", list.len() - 20);
            }
        }
    }

    let mut hard_issues = 0usize;

    // Moved-block double-execution check
    let moved_hits = match (from, to) {
        (Some(f), Some(t)) => check_moved_dups(ctx, f, t, base, &cc_files),
        _ => Vec::new(),
    };
    if moved_hits.is_empty() {
        println!("  moved-dup : clean (0 duplicated moved statements across --cc files)");
    } else {
        hard_issues += moved_hits.len();
        for h in &moved_hits {
            println!("  !! MOVED-DUP  {h}");
        }
    }

    // DT binding string mismatch check
    let dt_hits = check_dt_strings(ctx, base, "HEAD");
    if dt_hits.is_empty() {
        println!("  dt-strings: clean (0 driver clock/prop/IRQ string mismatches vs sm8735-devicetrees)");
    } else {
        hard_issues += dt_hits.len();
        for h in &dt_hits {
            println!("  !! DT-MISMATCH {h}");
        }
    }

    // Removed EXPORT_SYMBOL & dropped Android vendor hook check
    let (exp_hits, hook_hits) = check_exports_and_hooks(ctx, base, "HEAD");
    if exp_hits.is_empty() && hook_hits.is_empty() {
        println!("  abi-guard : clean (0 broken EXPORT_SYMBOLs, 0 dropped vendor hooks)");
    } else {
        hard_issues += exp_hits.len() + hook_hits.len();
        for h in &exp_hits {
            println!("  !! {h}");
        }
        for h in &hook_hits {
            println!("  !! {h}");
        }
    }

    let summary = format!(
        "T0={t0} T1={t1} T2={t2} | moved-dup={} dt-mismatch={} abi-breaks={}",
        moved_hits.len(),
        dt_hits.len(),
        exp_hits.len() + hook_hits.len()
    );
    (if hard_issues == 0 { 0 } else { 1 }, summary)
}

pub fn cmd_boot_risk(ctx: &Ctx, from: &str, to: Option<&str>, base_override: Option<&str>) -> i32 {
    let (up_from, up_to, base) = if let Some(t) = to {
        let b = match base_override {
            Some(ov) => ov.to_string(),
            None => verify::detect_pre_merge_base(ctx, from, t).unwrap_or_else(|| from.to_string()),
        };
        (Some(from), Some(t), b)
    } else if let Some((lhs, _)) = from.split_once("..") {
        (None, None, lhs.to_string())
    } else {
        (None, None, from.to_string())
    };
    run_boot_risk(ctx, up_from, up_to, &base).0
}

// ------------------------------------------------------ 5. Post-build `ktool img-audit`

fn collect_ko_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_ko_files(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("ko") {
            out.push(p);
        }
    }
}

fn find_latest_build_log(ws_root: &Path) -> Option<PathBuf> {
    let log_dir = ws_root.join("log");
    let rd = fs::read_dir(&log_dir).ok()?;
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for ent in rd.flatten() {
        let p = ent.path();
        let name = ent.file_name().to_string_lossy().into_owned();
        if name.starts_with("build-onyx-") && name.ends_with(".log") {
            if let Ok(mtime) = ent.metadata().and_then(|m| m.modified()) {
                if best.as_ref().is_none_or(|(bt, _)| mtime > *bt) {
                    best = Some((mtime, p));
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

fn read_utsrelease(kernel_obj: &Path) -> Option<String> {
    let txt = fs::read_to_string(kernel_obj.join("include/generated/utsrelease.h")).ok()?;
    let start = txt.find('"')? + 1;
    let end = txt[start..].find('"')? + start;
    Some(txt[start..end].to_string())
}

pub(crate) fn read_makefile_version(repo: &Path) -> Option<String> {
    let txt = fs::read_to_string(repo.join("Makefile")).ok()?;
    let (mut v, mut p, mut s) = ("", "", "");
    for ln in txt.lines().take(12) {
        if let Some(r) = ln.strip_prefix("VERSION =") {
            v = r.trim();
        } else if let Some(r) = ln.strip_prefix("PATCHLEVEL =") {
            p = r.trim();
        } else if let Some(r) = ln.strip_prefix("SUBLEVEL =") {
            s = r.trim();
        }
    }
    if !v.is_empty() && !p.is_empty() && !s.is_empty() {
        Some(format!("{v}.{p}.{s}"))
    } else {
        None
    }
}

pub fn cmd_img_audit(ctx: &Ctx, save_baseline: bool, log_override: Option<&Path>) -> i32 {
    println!("========================================================================");
    println!("ktool img-audit: pre-flash boot safety check ({})", ctx.product_out.display());
    println!("========================================================================");
    let mut fail = false;
    let mut rows: Vec<(&'static str, &'static str, String)> = Vec::new();

    // 1. UTS_RELEASE vs Makefile + HEAD SHA
    let head_short = git(ctx, &["rev-parse", "--short=12", "HEAD"]).trim().to_string();
    let mk_ver = read_makefile_version(&ctx.repo).unwrap_or_default();
    let uts = read_utsrelease(&ctx.kernel_obj).unwrap_or_default();
    println!("\n[1/5] Kernel release & HEAD alignment:");
    println!("  Makefile : {mk_ver}  |  HEAD: {head_short}");
    println!("  UTS_REL  : {uts}");
    let uts_ok = !uts.is_empty()
        && (mk_ver.is_empty() || uts.starts_with(&mk_ver))
        && (head_short.is_empty() || uts.contains(&head_short[..7.min(head_short.len())]));
    if !uts_ok {
        println!("  !! MISMATCH: built kernel UTS_RELEASE does not match Makefile ({mk_ver}) / HEAD ({head_short})!");
        fail = true;
    }
    rows.push(("uts-release", if uts_ok { "PASS" } else { "FAIL" }, uts.clone()));

    // 2. Partition image freshness & timestamp sync
    println!("\n[2/5] Partition image sync (prevents stale vendor_dlkm/vendor_boot splash hang):");
    let imgs = ["boot.img", "dtbo.img", "vendor_boot.img", "vendor_dlkm.img", "system_dlkm.img"];
    let mut mtimes: Vec<(&str, u64, SystemTime)> = Vec::new();
    let mut img_ok = true;
    for name in imgs {
        let p = ctx.product_out.join(name);
        match fs::metadata(&p) {
            Ok(meta) if meta.len() > 0 => {
                let mt = meta.modified().unwrap_or(UNIX_EPOCH);
                mtimes.push((name, meta.len(), mt));
            }
            _ => {
                println!("  !! MISSING/EMPTY: {name}");
                img_ok = false;
            }
        }
    }
    if let Some(newest) = mtimes.iter().map(|x| x.2).max() {
        for (name, sz, mt) in &mtimes {
            let age = newest.duration_since(*mt).unwrap_or(Duration::ZERO).as_secs();
            let flag = if age > 2400 { " !! STALE (>40m older than newest)" } else { "" };
            if age > 2400 {
                img_ok = false;
            }
            println!(
                "  {name:<18} {:>6.1} MiB  (delta {:>4}s){flag}",
                *sz as f64 / (1024.0 * 1024.0),
                age
            );
        }
    }
    if !img_ok {
        fail = true;
    }
    rows.push(("img-sync", if img_ok { "PASS" } else { "FAIL" }, format!("{}/{} images synced", mtimes.len(), imgs.len())));

    // 3. Pure-Rust ELF64 `.ko` binary audit: vermagic, depends= closure, partition order,
    //    SHN_UNDEF symbol resolution, __versions CRC, modules.load*, & prebuilt .ko check!
    println!("\n[3/5] ELF64 module binary audit (vermagic, depends=, symbols, CRCs, boot-order):");
    let mod_roots = [
        ("vendor_ramdisk", ctx.product_out.join("vendor_ramdisk/lib/modules")),
        ("system_dlkm", ctx.product_out.join("system_dlkm/lib/modules")),
        ("vendor_dlkm", ctx.product_out.join("vendor_dlkm/lib/modules")),
    ];
    let mut all_kos: Vec<(String, PathBuf)> = Vec::new();
    let mut per_part_names: HashMap<String, HashSet<String>> = HashMap::new();
    for (part, dir) in &mod_roots {
        let mut found = Vec::new();
        collect_ko_files(dir, &mut found);
        println!("  {part:<15}: {} .ko", found.len());
        let set = per_part_names.entry(part.to_string()).or_default();
        for p in found {
            if let Some(n) = p.file_name().map(|s| s.to_string_lossy().into_owned()) {
                set.insert(n);
            }
            all_kos.push((part.to_string(), p));
        }
    }

    let elf_res = elf::audit_staged_modules(ctx, &uts, &all_kos);
    if !elf_res.vermagic_errs.is_empty() {
        println!("  !! VERMAGIC MISMATCH ({} .ko) — WILL FAIL TO LOAD AT BOOT:", elf_res.vermagic_errs.len());
        for b in elf_res.vermagic_errs.iter().take(12) {
            println!("     {b}");
        }
        fail = true;
    } else if elf_res.total_kos > 0 {
        println!("  ok: all {} .ko vermagic match `{uts}`", elf_res.total_kos);
    }
    if !elf_res.missing_deps.is_empty() {
        println!("  !! MISSING depends= MODULES ({}):", elf_res.missing_deps.len());
        for m in elf_res.missing_deps.iter().take(12) {
            println!("     {m}");
        }
        fail = true;
    }
    if !elf_res.partition_order_errs.is_empty() {
        println!("  !! BOOT PARTITION ORDER VIOLATIONS ({} — early-boot .ko needs later partition!):", elf_res.partition_order_errs.len());
        for e in elf_res.partition_order_errs.iter().take(12) {
            println!("     {e}");
        }
        fail = true;
    }
    if !elf_res.unresolved_syms.is_empty() {
        println!("  !! UNRESOLVED ELF SYMBOLS ({} .ko — insmod WILL FAIL!):", elf_res.unresolved_syms.len());
        for u in elf_res.unresolved_syms.iter().take(12) {
            println!("     {u}");
        }
        fail = true;
    }
    if !elf_res.crc_mismatches.is_empty() {
        println!("  !! MODVERSIONS CRC MISMATCH ({} .ko — KABI BROKEN!):", elf_res.crc_mismatches.len());
        for c in elf_res.crc_mismatches.iter().take(12) {
            println!("     {c}");
        }
        fail = true;
    }

    let mut load_list_errs = Vec::new();
    for (part, dir) in &mod_roots {
        if let Some(set) = per_part_names.get(*part) {
            load_list_errs.extend(elf::check_modules_load_lists(dir, part, set));
        }
    }
    if !load_list_errs.is_empty() {
        println!("  !! modules.load* REFERENCES MISSING .ko ({}):", load_list_errs.len());
        for e in load_list_errs.iter().take(12) {
            println!("     {e}");
        }
        fail = true;
    }

    let prebuilt_kos = elf::find_prebuilt_kos(&ctx.ws_root);
    if !prebuilt_kos.is_empty() {
        println!("  !! WARN: {} prebuilt binary .ko in device/vendor (KABI-sensitive!):", prebuilt_kos.len());
        for p in prebuilt_kos.iter().take(8) {
            println!("     {}", p.display());
        }
    } else {
        println!("  ok: 0 prebuilt binary .ko in device/vendor (100% source-built), 0 ELF symbol/dep/CRC/order errors");
    }

    // Check critical SM8735 / onyx boot module patterns (must match at least 1 .ko per group)
    let all_ko_joined: String = elf_res.all_basenames.join("\n");
    let critical_groups: &[(&str, &[&str])] = &[
        ("display/DRM", &["msm_drm", "mi_disp"]),
        ("GPU/kgsl", &["msm_kgsl"]),
        ("WLAN", &["qca_cld3", "icnss2", "cnss2"]),
        ("crypto/QCE", &["qce50", "sps_drv"]),
        ("reboot/PON", &["qcom-reboot-reason", "qcom_reboot_reason"]),
        ("DICE/GKI", &["open-dice", "open_dice"]),
        ("audio", &["snd_event", "spf_core", "q6_pdr", "aw882xx"]),
        ("touch", &["xiaomi_touch", "nt36532", "goodix", "focaltech"]),
        ("charging/MCA", &["mca_", "pmic_glink", "qti_battery"]),
    ];
    let mut missing_crit = Vec::new();
    for (grp, pats) in critical_groups {
        if !pats.iter().any(|p| all_ko_joined.contains(p)) {
            missing_crit.push(*grp);
        }
    }
    if !missing_crit.is_empty() {
        println!("  !! MISSING CRITICAL MODULE GROUPS: {}", missing_crit.join(", "));
        fail = true;
    }

    // Recovery / fastbootd parity gate: vendor_ramdisk modules.load.recovery must include
    // msm_drm.ko AND match vendor_dlkm's msm_drm.ko byte-for-byte (prevents stuck fastbootd logo!).
    let mut recovery_ok = true;
    let rec_load = ctx.product_out.join("vendor_ramdisk/lib/modules/modules.load.recovery");
    let rec_drm = ctx.product_out.join("vendor_ramdisk/lib/modules/msm_drm.ko");
    let dlkm_drm = ctx.product_out.join("vendor_dlkm/lib/modules/msm_drm.ko");
    match fs::read_to_string(&rec_load) {
        Ok(txt) if txt.lines().any(|l| l.trim().ends_with("msm_drm.ko")) => {
            if rec_drm.is_file() && dlkm_drm.is_file() {
                let b1 = fs::read(&rec_drm).unwrap_or_default();
                let b2 = fs::read(&dlkm_drm).unwrap_or_default();
                if b1 != b2 {
                    println!(
                        "  !! STALE RECOVERY msm_drm.ko: vendor_ramdisk ({} B) != vendor_dlkm ({} B) — fastbootd UI will fail!",
                        b1.len(),
                        b2.len()
                    );
                    recovery_ok = false;
                } else {
                    println!("  ok: recovery modules.load.recovery has synced msm_drm.ko ({} B)", b1.len());
                }
            } else {
                println!("  !! MISSING msm_drm.ko in vendor_ramdisk or vendor_dlkm");
                recovery_ok = false;
            }
        }
        Ok(_) => {
            println!("  !! modules.load.recovery missing msm_drm.ko — fastbootd will stay stuck on boot logo!");
            recovery_ok = false;
        }
        Err(_) => {
            println!("  !! MISSING vendor_ramdisk/lib/modules/modules.load.recovery");
            recovery_ok = false;
        }
    }
    if !recovery_ok {
        fail = true;
    }

    // AVB boot.img signing + BoardConfig cmdline hazard check
    let mut avb_cmd_ok = true;
    let boot_img = ctx.product_out.join("boot.img");
    if let Ok(bdata) = fs::read(&boot_img) {
        let tail = if bdata.len() > 65536 { &bdata[bdata.len() - 65536..] } else { &bdata[..] };
        let has_avbf = tail.windows(4).any(|w| w == b"AVBf");
        let has_avb0 = bdata.windows(4).any(|w| w == b"AVB0");
        if !has_avbf || !has_avb0 {
            println!("  !! UNSIGNED boot.img: missing AVB0/AVBf metadata (Play Integrity / verified boot risk!)");
            avb_cmd_ok = false;
        } else {
            println!("  ok: boot.img contains AVB0 + AVBf footer");
        }
    }
    let board_mk = ctx.ws_root.join("src/device/xiaomi/onyx/BoardConfig.mk");
    if let Ok(btxt) = fs::read_to_string(&board_mk) {
        let mut bad_cmd = Vec::new();
        for tok in ["arm64.nopauth", "arm64.nobti", "reboot=w"] {
            if btxt.lines().any(|l| !l.trim_start().starts_with('#') && l.contains(tok)) {
                bad_cmd.push(tok);
            }
        }
        if !bad_cmd.is_empty() {
            println!("  !! HAZARDOUS BoardConfig.mk cmdline flags: {}", bad_cmd.join(", "));
            avb_cmd_ok = false;
        }
    }
    if !avb_cmd_ok {
        fail = true;
    }
    rows.push((
        "recovery+avb",
        if recovery_ok && avb_cmd_ok { "PASS" } else { "FAIL" },
        format!("recovery_drm={} avb_cmd={}", recovery_ok, avb_cmd_ok),
    ));

    // Select version-matched baseline directory (`kernel-upstream-612` for 6.12+, else `kernel-upstream-66x`)
    let baseline_dir = if uts.starts_with("6.12.") {
        ctx.ws_root.join("lab/kernel-upstream-612")
    } else {
        ctx.ws_root.join("lab/kernel-upstream-66x")
    };

    // Compare against saved module baseline (or save it)
    let mod_baseline = baseline_dir.join("modules-baseline.txt");
    let mut dropped_kos = Vec::new();
    if save_baseline && !elf_res.ko_names.is_empty() {
        let _ = fs::create_dir_all(&baseline_dir);
        let content = elf_res.ko_names.iter().cloned().collect::<Vec<_>>().join("\n") + "\n";
        let _ = fs::write(&mod_baseline, content);
        println!("  saved {} module entries to {}", elf_res.ko_names.len(), mod_baseline.display());
    } else if let Ok(txt) = fs::read_to_string(&mod_baseline) {
        let base_set: BTreeSet<String> = txt.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        for m in base_set.difference(&elf_res.ko_names) {
            dropped_kos.push(m.clone());
        }
        let added_cnt = elf_res.ko_names.difference(&base_set).count();
        if !dropped_kos.is_empty() {
            println!("  !! DROPPED .ko vs baseline ({}):", dropped_kos.len());
            for d in dropped_kos.iter().take(15) {
                println!("     - {d}");
            }
            fail = true;
        } else {
            println!("  ok: 0 .ko dropped vs baseline (+{added_cnt} new)");
        }
    }
    let ko_ok = elf_res.ok && load_list_errs.is_empty() && missing_crit.is_empty() && dropped_kos.is_empty();
    rows.push((
        "elf-modules",
        if ko_ok { "PASS" } else { "FAIL" },
        format!(
            "{} .ko, {} vm, {} sym, {} dep, {} crc, {} ord",
            elf_res.total_kos,
            elf_res.vermagic_errs.len(),
            elf_res.unresolved_syms.len(),
            elf_res.missing_deps.len(),
            elf_res.crc_mismatches.len(),
            elf_res.partition_order_errs.len()
        ),
    ));

    // 4. Generated .config + LTO + zero gki_is_module_ check
    println!("\n[4/5] Kernel .config, LTO & Module.symvers hygiene:");
    let cfg_path = ctx.kernel_obj.join(".config");
    let cfg_base = if uts.starts_with("6.12.") {
        baseline_dir.join("config-baseline-612.txt")
    } else {
        baseline_dir.join("config-baseline-140.txt")
    };
    let mut cfg_ok = true;
    if save_baseline && cfg_path.is_file() && uts.starts_with("6.12.") {
        let _ = fs::create_dir_all(&baseline_dir);
        if fs::copy(&cfg_path, &cfg_base).is_ok() {
            println!("  saved .config baseline to {}", cfg_base.display());
        }
    } else if cfg_base.is_file() && cfg_path.is_file() {
        if gate::cmd_config(&cfg_base, &cfg_path) != 0 {
            cfg_ok = false;
            fail = true;
        }
    } else if uts.starts_with("6.12.") {
        println!("  info: no 6.12 config baseline yet (run `ktool img-audit --save-baseline` after first clean 6.12 build)");
    }
    let mut overhead_warns = Vec::new();
    if let Ok(cfg_txt) = fs::read_to_string(&cfg_path) {
        let has_cfg = |k: &str| cfg_txt.lines().any(|l| l == k);
        let lto_full = has_cfg("CONFIG_LTO_CLANG_FULL=y");
        let lto_thin = has_cfg("CONFIG_LTO_CLANG_THIN=y");
        println!(
            "  LTO mode : {}",
            if lto_full { "FULL" } else if lto_thin { "THIN" } else { "NONE (warning: bring-up mode, perf overhead!)" }
        );
        // Hard crash/severe-overhead config traps
        for (sym, reason) in [
            ("CONFIG_UNWIND_PATCH_PAC_INTO_SCS=y", "Clang 21 Dynamic SCS boot fault"),
            ("CONFIG_LOCKDEP=y", "severe runtime lockdep overhead"),
            ("CONFIG_PROVE_LOCKING=y", "severe runtime locking overhead"),
            ("CONFIG_DEBUG_KMEMLEAK=y", "severe memory/CPU overhead"),
            ("CONFIG_KASAN_GENERIC=y", "severe KASAN generic memory/CPU overhead"),
            ("CONFIG_SLUB_DEBUG_ON=y", "severe SLUB debug overhead"),
        ] {
            if has_cfg(sym) {
                println!("  !! FORBIDDEN CONFIG: {sym} ({reason})");
                cfg_ok = false;
                fail = true;
            }
        }
        // Compound 6.12 traps learned from real bring-up failures
        if (lto_full || lto_thin)
            && (has_cfg("CONFIG_DEBUG_INFO_BTF=y") || has_cfg("CONFIG_MODVERSIONS=y"))
            && !has_cfg("CONFIG_RUST=y")
        {
            println!("  !! FORBIDDEN CONFIG COMBO: LTO + (DEBUG_INFO_BTF=y or MODVERSIONS=y) silently disabled CONFIG_RUST (rust_binder.ko dropped!)");
            cfg_ok = false;
            fail = true;
        }
        if has_cfg("CONFIG_INIT_STACK_NONE=y") {
            let mk_txt = fs::read_to_string(ctx.repo.join("Makefile")).unwrap_or_default();
            let has_extmod_zero = mk_txt
                .split("ifdef CONFIG_INIT_STACK_NONE")
                .nth(1)
                .is_some_and(|s| s.contains("KBUILD_EXTMOD") && s.contains("-ftrivial-auto-var-init=zero"));
            if !has_extmod_zero {
                println!("  !! HAZARDOUS CONFIG: CONFIG_INIT_STACK_NONE=y without KBUILD_EXTMOD zero-init guard in Makefile breaks display/camera/fastrpc!");
                cfg_ok = false;
                fail = true;
            } else {
                println!("  ok: CONFIG_INIT_STACK_NONE=y paired with Makefile KBUILD_EXTMOD zero-init guard");
            }
        }
        // Soft bring-up performance / overhead advisories
        for (sym, note) in [
            ("CONFIG_LTO_NONE=y", "LTO disabled (restore FullLTO for final perf)"),
            ("CONFIG_CFI_PERMISSIVE=y", "CFI permissive bring-up mode"),
            ("CONFIG_UBSAN=y", "UBSAN bounds checks enabled"),
            ("CONFIG_KASAN_HW_TAGS=y", "KASAN HW-tags enabled (verify kasan=off on cmdline)"),
            ("CONFIG_DEBUG_FS_ALLOW_ALL=y", "debugfs allow-all enabled"),
            ("CONFIG_SCHED_DEBUG=y", "sched_debug overhead"),
            ("CONFIG_LOCALVERSION=\"-4k\"", "generic -4k localversion (expected -Drago)"),
        ] {
            if has_cfg(sym) {
                overhead_warns.push(format!("{sym} [{note}]"));
            }
        }
        if !overhead_warns.is_empty() {
            println!("  INFO perf/debug config advisories ({}):", overhead_warns.len());
            for w in &overhead_warns {
                println!("     {w}");
            }
        }
    }
    let symvers = ctx.kernel_obj.join("Module.symvers");
    let mut gki_syms = 0usize;
    if let Ok(stxt) = fs::read_to_string(&symvers) {
        gki_syms = stxt.lines().filter(|l| l.contains("gki_is_module_")).count();
        println!("  symvers  : {gki_syms} gki_is_module_ symbols");
        if gki_syms > 0 {
            cfg_ok = false;
            fail = true;
        }
    }
    rows.push(("config+abi", if cfg_ok { "PASS" } else { "FAIL" }, format!("gki_is_module_={gki_syms}")));

    // 5. Build log error / modpost / section mismatch audit
    println!("\n[5/5] Build log error & modpost audit:");
    let log_path = log_override
        .map(Path::to_path_buf)
        .or_else(|| find_latest_build_log(&ctx.ws_root));
    let mut log_ok = true;
    let mut log_summary = "no log found".to_string();
    if let Some(lp) = log_path {
        println!("  log file : {}", lp.display());
        if let Ok(txt) = fs::read_to_string(&lp) {
            let mut errs = Vec::new();
            let mut modpost_warns = Vec::new();
            let mut build_ok_banner = false;
            for (i, ln) in txt.lines().enumerate() {
                if ln.contains("build completed successfully") {
                    build_ok_banner = true;
                }
                if ln.contains("failed to build some targets")
                    || ln.contains(": error:")
                    || ln.contains("ld.lld: error:")
                    || ln.contains("ERROR: modpost:")
                {
                    errs.push(format!("L{}: {}", i + 1, truncate_str(ln.trim(), 110)));
                } else if ln.contains("WARNING: modpost:") || ln.contains("Section mismatch") {
                    modpost_warns.push(format!("L{}: {}", i + 1, truncate_str(ln.trim(), 110)));
                }
            }
            if !errs.is_empty() || !build_ok_banner {
                log_ok = false;
                fail = true;
                println!("  !! BUILD ERRORS ({}) | success_banner={build_ok_banner}:", errs.len());
                for e in errs.iter().take(15) {
                    println!("     {e}");
                }
            } else {
                println!("  ok: 0 errors, build completed successfully");
            }
            if !modpost_warns.is_empty() {
                println!("  WARN modpost/section ({}):", modpost_warns.len());
                for w in modpost_warns.iter().take(10) {
                    println!("     {w}");
                }
            }
            log_summary = format!("{} errs, {} modpost-warn, ok_banner={build_ok_banner}", errs.len(), modpost_warns.len());
        }
    }
    rows.push(("build-log", if log_ok { "PASS" } else { "FAIL" }, log_summary));

    println!("\n========================================================================");
    println!("IMG-AUDIT VERDICT: {}", if fail { "DO NOT FLASH (FAIL)" } else { "SAFE TO FLASH (PASS)" });
    println!("========================================================================");
    for (k, st, msg) in &rows {
        println!("  [{st:<4}] {k:<12} {msg}");
    }
    if fail { 1 } else { 0 }
}

// ------------------------------------------------------ 6. Post-flash `ktool live-audit`

fn adb_shell_serial(ctx: &Ctx, serial: &str, shell_args: &[&str]) -> (i32, String, String) {
    let mut args = vec!["-s", serial, "shell"];
    args.extend_from_slice(shell_args);
    run_cmd("adb", &args, &ctx.ws_root, None)
}

pub fn cmd_live_audit(ctx: &Ctx, requested_serial: Option<&str>) -> i32 {
    println!("========================================================================");
    println!("ktool live-audit: post-flash hardware kernel health check (adb)");
    println!("========================================================================");
    let dev = match device::select_adb_device(ctx, requested_serial) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    let serial = dev.serial.as_str();
    println!("  device   : {serial}");
    let (rc, uname, err) = adb_shell_serial(ctx, serial, &["uname", "-a"]);
    if rc != 0 {
        eprintln!("!! adb shell failed: {}", err.trim());
        return 1;
    }
    let uname = uname.trim();
    let head_short = git(ctx, &["rev-parse", "--short=12", "HEAD"]).trim().to_string();
    let mk_ver = read_makefile_version(&ctx.repo).unwrap_or_default();
    println!("  uname -a : {uname}");
    let uname_ok = (mk_ver.is_empty() || uname.contains(&mk_ver))
        && (head_short.is_empty() || uname.contains(&head_short[..7.min(head_short.len())]));
    if !uname_ok {
        println!("  !! WARN: device kernel does not match local HEAD ({mk_ver} / {head_short})");
    }

    let (_, taint_raw, _) = adb_shell_serial(ctx, serial, &["cat", "/proc/sys/kernel/tainted"]);
    let taint_val: u64 = taint_raw.trim().parse().unwrap_or(0);
    // Bits 12 (4096: OOT_MODULE) and 13 (8192: UNSIGNED_MODULE) are normal for Android vendor_dlkm .ko
    let mut taint_flags = Vec::new();
    for (bit, name) in [
        (0, "PROPRIETARY"), (4, "UNSAFE_SMP"), (5, "BAD_PAGE"), (7, "DIE"),
        (9, "WARN"), (11, "FIRMWARE_WORKAROUND"), (12, "OOT"), (13, "UNSIGNED"), (14, "SOFTLOCKUP"),
    ] {
        if (taint_val & (1u64 << bit)) != 0 {
            taint_flags.push(name);
        }
    }
    let unexpected_taint = taint_val & !((1u64 << 12) | (1u64 << 13));
    println!(
        "  tainted  : {taint_val} ({})",
        if taint_flags.is_empty() { "clean".into() } else { taint_flags.join("+") }
    );

    let (_, lsmod, _) = adb_shell_serial(ctx, serial, &["lsmod"]);
    let mod_cnt = lsmod.lines().count().saturating_sub(1);
    println!("  lsmod    : {mod_cnt} loaded modules");
    let loaded_mods: HashSet<&str> = lsmod
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let required_live = [
        "msm_drm",
        "msm_kgsl",
        "qca_cld3_wcn7750",
        "qce50_dlkm",
        "sps_drv",
        "qcom_reboot_reason",
        "open_dice",
    ];
    let missing_live: Vec<&str> = required_live
        .iter()
        .copied()
        .filter(|m| !loaded_mods.contains(m))
        .collect();
    if !missing_live.is_empty() {
        println!("  !! MISSING CRITICAL LIVE MODULES: {}", missing_live.join(", "));
    } else {
        println!("  ok: all {} critical live modules loaded (DRM/GPU/WLAN/QCE/reboot/DICE)", required_live.len());
    }

    let (drc, mut dmesg, _) = adb_shell_serial(ctx, serial, &["su", "-c", "dmesg"]);
    if drc != 0 || dmesg.trim().is_empty() {
        let (_, d2, _) = adb_shell_serial(ctx, serial, &["dmesg"]);
        dmesg = d2;
    }

    let mut critical = Vec::new();
    let mut probe_fails = Vec::new();
    let mut subsys_errs = Vec::new();
    for ln in dmesg.lines() {
        let low = ln.to_ascii_lowercase();
        if ln.contains("BUG:")
            || ln.contains("Kernel panic")
            || ln.contains("Unable to handle kernel")
            || ln.contains("Internal error:")
            || ln.contains("Call Trace:")
            || ln.contains("KASAN:")
            || ln.contains("UBSAN:")
            || ln.contains("CFI failure")
            || ln.contains("WARNING: CPU:")
            || ln.contains("Synchronous External Abort")
            || ln.contains("SError Interrupt")
            || ln.contains("RCU stall")
            || ln.contains("soft lockup")
            || ln.contains("hung_task")
            || ln.contains("Out of memory:")
            || ln.contains("page allocation failure")
            || ln.contains("vma_pad_pages")
            || ln.contains("invalid pad vma")
        {
            critical.push(truncate_str(ln.trim(), 120).to_string());
        } else if low.contains("probe with driver") && low.contains("failed with error") {
            probe_fails.push(truncate_str(ln.trim(), 120).to_string());
        } else if (low.contains("tsens")
            || low.contains("ufshcd")
            || low.contains("ufs_qcom_phy")
            || low.contains("glink")
            || low.contains("qrtr")
            || low.contains("kgsl")
            || low.contains("mi_disp")
            || low.contains("icnss")
            || low.contains("qce")
            || low.contains("sps")
            || low.contains("regulatory.db")
            || low.contains("hw-fences")
            || low.contains("mca_"))
            && (low.contains("error") || low.contains("failed") || low.contains("fail ") || low.contains("timeout"))
        {
            subsys_errs.push(truncate_str(ln.trim(), 120).to_string());
        }
    }

    println!("  dmesg    : {} lines scanned", dmesg.lines().count());
    if critical.is_empty() {
        println!("  critical : 0 panics / BUG / WARNING / KASAN / UBSAN / CFI / OOM / external-abort");
    } else {
        println!("  !! CRITICAL SPLATS ({}):", critical.len());
        for c in critical.iter().take(20) {
            println!("     {c}");
        }
    }
    if !probe_fails.is_empty() {
        println!("  WARN probe failures ({}):", probe_fails.len());
        for p in probe_fails.iter().take(15) {
            println!("     {p}");
        }
    }
    if !subsys_errs.is_empty() {
        println!("  INFO subsystem error/timeout lines ({}, first 15):", subsys_errs.len());
        for s in subsys_errs.iter().take(15) {
            println!("     {s}");
        }
    }

    // Kernel memory footprint & slab/vmalloc/page-table leak telemetry
    let (_, kmem_raw, _) = adb_shell_serial(
        ctx,
        serial,
        &["grep -E '^(MemTotal|MemAvailable|Slab|SReclaimable|SUnreclaim|KernelStack|PageTables|VmallocUsed|Percpu):' /proc/meminfo"],
    );
    let mut kmem: HashMap<&str, u64> = HashMap::new();
    for ln in kmem_raw.lines() {
        if let Some((k, v)) = ln.split_once(':') {
            let kb = v.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            kmem.insert(k.trim(), kb);
        }
    }
    let slab_unrecl = *kmem.get("SUnreclaim").unwrap_or(&0);
    let vmalloc_used = *kmem.get("VmallocUsed").unwrap_or(&0);
    if !kmem.is_empty() {
        println!(
            "  kmem     : Slab={:.0}M (recl={:.0}M unrecl={:.0}M) | Vmalloc={:.0}M | PT={:.0}M | KStack={:.0}M | Percpu={:.0}M",
            *kmem.get("Slab").unwrap_or(&0) as f64 / 1024.0,
            *kmem.get("SReclaimable").unwrap_or(&0) as f64 / 1024.0,
            slab_unrecl as f64 / 1024.0,
            vmalloc_used as f64 / 1024.0,
            *kmem.get("PageTables").unwrap_or(&0) as f64 / 1024.0,
            *kmem.get("KernelStack").unwrap_or(&0) as f64 / 1024.0,
            *kmem.get("Percpu").unwrap_or(&0) as f64 / 1024.0,
        );
        if slab_unrecl > 614_400 {
            println!("  !! WARN: SUnreclaim > 600 MiB ({:.1} MiB) — check for slab leak!", slab_unrecl as f64 / 1024.0);
        }
        if vmalloc_used > 524_288 {
            println!("  !! WARN: VmallocUsed > 512 MiB ({:.1} MiB) — check for vmalloc/ioremap leak!", vmalloc_used as f64 / 1024.0);
        }
    }

    let (_, pstore_out, _) = adb_shell_serial(ctx, serial, &["su", "-c", "ls /sys/fs/pstore 2>/dev/null"]);
    let pstore_files: Vec<&str> = pstore_out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !pstore_files.is_empty() {
        println!("  !! WARN pstore crash logs present ({}): {}", pstore_files.len(), pstore_files.join(", "));
    } else {
        println!("  pstore   : clean (no prior panic ramoops)");
    }

    let (_, def_out, _) = adb_shell_serial(ctx, serial, &["su", "-c", "cat /sys/kernel/debug/devices_deferred 2>/dev/null"]);
    let def_lines: Vec<&str> = def_out.lines().filter(|l| !l.trim().is_empty()).collect();
    if !def_lines.is_empty() {
        println!("  deferred probes ({}):", def_lines.len());
        for d in def_lines.iter().take(10) {
            println!("     {d}");
        }
    }

    let ok = uname_ok && unexpected_taint == 0 && critical.is_empty() && missing_live.is_empty();
    println!("\nLIVE-AUDIT VERDICT: {}", if ok { "CLEAN BOOT (PASS)" } else { "INVESTIGATE (WARN/FAIL)" });
    if ok { 0 } else { 1 }
}

// ------------------------------------------------------ 7. Crash & Reboot Forensics (`ktool crash-log`)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtdoopsSlotSummary {
    pub slot: usize,
    pub seq: u32,
    pub boot_index: Option<String>,
    pub pureason: Option<String>,
    pub critical_hits: Vec<String>,
    pub tail_lines: Vec<String>,
}

pub fn decode_xiaomi_boot_reason(code: u32) -> &'static str {
    match code {
        0x00 => "COLD/UNSET",
        0x01 => "RECOVERY",
        0x02 => "BOOTLOADER",
        0x03 => "RTC",
        0x04 => "DM-VERITY",
        0x20 => "NORMAL(0x20)",
        0x21 => "KERNEL_PANIC(0x21)",
        0x40 => "FFUS(0x40)",
        0x41 => "FFUF(0x41)",
        _ => "OTHER",
    }
}

pub fn parse_mtdoops_slots(data: &[u8], slot_size: usize) -> Vec<MtdoopsSlotSummary> {
    if slot_size == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, chunk) in data.chunks(slot_size).enumerate() {
        if chunk.len() < 8 {
            continue;
        }
        let seq = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if seq == 0 || seq == u32::MAX {
            continue;
        }
        // Extract printable ASCII text directly in Rust (avoids broken toybox `tr` on Android!)
        let mut text = String::new();
        for &b in &chunk[4..] {
            if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) {
                text.push(b as char);
            } else if b == 0 {
                // Skip NUL padding
            }
        }
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.len() >= 4)
            .collect();
        if lines.is_empty() {
            continue;
        }
        let mut boot_index = None;
        let mut pureason = None;
        let mut critical_hits = Vec::new();
        for &ln in &lines {
            if boot_index.is_none() {
                if let Some(pos) = ln.find("mtdoops.boot_index=") {
                    let rest = &ln[pos + "mtdoops.boot_index=".len()..];
                    boot_index = rest.split_whitespace().next().map(|s| s.to_string());
                } else if let Some(pos) = ln.find("Boot_Index:") {
                    let rest = ln[pos + "Boot_Index:".len()..].trim();
                    boot_index = rest.split(|c: char| !c.is_ascii_digit()).next().filter(|s| !s.is_empty()).map(|s| s.to_string());
                }
            }
            if pureason.is_none() {
                if let Some(pos) = ln.find("bootinfo.pureason=") {
                    let rest = &ln[pos + "bootinfo.pureason=".len()..];
                    pureason = rest.split_whitespace().next().map(|s| s.to_string());
                }
            }
            if ln.contains("Kernel panic")
                || ln.contains("Unable to handle kernel")
                || ln.contains("Internal error:")
                || ln.contains("BUG:")
                || ln.contains("Oops:")
                || ln.contains("CFI failure")
                || ln.contains("SError Interrupt")
                || ln.contains("Synchronous External Abort")
                || ln.contains("WARNING: CPU:")
                || ln.contains("reboot: Restarting")
                || ln.contains("reboot: Power down")
                || ln.contains("SysRq :")
            {
                if critical_hits.len() < 8 {
                    critical_hits.push(truncate_str(ln, 115).to_string());
                }
            }
        }
        let tail_start = lines.len().saturating_sub(4);
        let tail_lines = lines[tail_start..]
            .iter()
            .map(|l| truncate_str(l, 115).to_string())
            .collect();
        out.push(MtdoopsSlotSummary {
            slot: idx,
            seq,
            boot_index,
            pureason,
            critical_hits,
            tail_lines,
        });
    }
    out.sort_by_key(|s| s.seq);
    out
}

pub fn parse_blackbox_slot_header(raw: &str) -> Option<(Option<String>, Option<u32>, Option<String>)> {
    let mut boot_idx = None;
    let mut reason: Option<u32> = None;
    let mut pureason = None;
    for ln in raw.lines() {
        let t = ln.trim();
        if boot_idx.is_none() {
            if let Some(pos) = t.find("Boot_Index:") {
                let v = t[pos + "Boot_Index:".len()..].trim();
                let tok = v.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
                if !tok.is_empty() {
                    boot_idx = Some(tok.to_string());
                }
            } else if let Some(pos) = t.find("mtdoops.boot_index=") {
                let v = &t[pos + "mtdoops.boot_index=".len()..];
                let tok = v.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
                if !tok.is_empty() {
                    boot_idx = Some(tok.to_string());
                }
            }
        }
        if reason.is_none() {
            if let Some(pos) = t.find("BootReason:") {
                let v = t[pos + "BootReason:".len()..].trim();
                let tok = v.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
                if let Ok(n) = tok.parse::<u32>() {
                    reason = Some(n);
                }
            }
        }
        if pureason.is_none() {
            if let Some(pos) = t.find("pureason") {
                let after = t[pos + "pureason".len()..]
                    .trim_start_matches(|c: char| c == ' ' || c == '=' || c == ':');
                let tok = after
                    .split(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                    .next()
                    .unwrap_or("");
                if !tok.is_empty() {
                    pureason = Some(if tok.starts_with("0x") || tok.starts_with("0X") {
                        tok.to_string()
                    } else {
                        format!("0x{tok}")
                    });
                }
            }
        }
    }
    if boot_idx.is_none() && reason.is_none() && pureason.is_none() {
        None
    } else {
        Some((boot_idx, reason, pureason))
    }
}

fn bytes_to_ascii_lines(buf: &[u8]) -> String {
    let mut text = String::with_capacity(buf.len() / 2);
    for &b in buf {
        if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            text.push(b as char);
        }
    }
    text
}

pub fn cmd_crash_log(ctx: &Ctx, requested_serial: Option<&str>, max_slots: usize) -> i32 {
    println!("========================================================================");
    println!("ktool crash-log: pstore + shutdown-checkpoints + blackbox + mtdoops");
    println!("========================================================================");
    let dev = match device::select_adb_device(ctx, requested_serial) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    let serial = dev.serial.as_str();
    println!("  device   : {serial}");

    // 1. Single fast shell probe: cmdline, pstore, shutdown-checkpoints, and dump blackbox headers + oops to /data/local/tmp
    let slots = max_slots.clamp(1, 16);
    let tmp_oops = "/data/local/tmp/.ktool_oops.bin";
    let tmp_bb = "/data/local/tmp/.ktool_bb.bin";
    let script = format!(
        r#"LC_ALL=C
echo '@@SEC:CMDLINE@@'
cat /proc/cmdline 2>/dev/null
echo ''
echo '@@SEC:PSTORE@@'
if [ -d /sys/fs/pstore ]; then
  for f in /sys/fs/pstore/*; do
    [ -f "$f" ] || continue
    echo "@@PFILE:$f@@"
    tail -n 40 "$f" 2>/dev/null
  done
fi
echo '@@SEC:SHUTDOWN@@'
for f in $(ls -1t /data/system/shutdown-checkpoints/checkpoints-* 2>/dev/null | head -n 6); do
  echo "@@SFILE:$f@@"
  head -n 4 "$f" 2>/dev/null
done
if [ -e /dev/block/by-name/blackbox ]; then
  rm -f {tmp_bb}
  i=0
  while [ "$i" -lt {slots} ]; do
    # ABL BootReason/pureason lives at +64 KiB inside each 8 MiB blackbox slot (128 x 64 KiB)
    dd if=/dev/block/by-name/blackbox bs=65536 count=1 skip=$((i * 128 + 1)) 2>/dev/null >> {tmp_bb}
    i=$((i + 1))
  done
  chmod 644 {tmp_bb} 2>/dev/null
fi
if [ -e /dev/block/by-name/oops ]; then
  dd if=/dev/block/by-name/oops of={tmp_oops} bs=1048576 2>/dev/null && chmod 644 {tmp_oops} 2>/dev/null
fi
echo '@@SEC:END@@'
"#
    );
    let probe_out = match device::run_adb_probe(ctx, serial, &script) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("!! adb probe failed: {e}");
            return 1;
        }
    };

    // Split sections
    let mut cur_sec = "";
    let mut secs: HashMap<&str, String> = HashMap::new();
    for ln in probe_out.lines() {
        if let Some(rest) = ln.strip_prefix("@@SEC:").and_then(|s| s.strip_suffix("@@")) {
            cur_sec = rest;
        } else if !cur_sec.is_empty() && cur_sec != "END" {
            secs.entry(cur_sec).or_default().push_str(ln);
            secs.entry(cur_sec).or_default().push('\n');
        }
    }

    let cmdline = secs.get("CMDLINE").map(|s| s.as_str()).unwrap_or("");
    let cur_bi = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("mtdoops.boot_index="))
        .unwrap_or("?");
    let cur_pu = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("bootinfo.pureason="))
        .unwrap_or("?");
    println!("  current  : boot_index={cur_bi} pureason={cur_pu}");

    // [1] pstore
    println!("\n[1/4] /sys/fs/pstore (ramoops across warm-reset panics):");
    let pstore_raw = secs.get("PSTORE").map(|s| s.as_str()).unwrap_or("").trim();
    let mut saw_panic = false;
    if pstore_raw.is_empty() {
        println!("  clean: no files in /sys/fs/pstore");
    } else {
        saw_panic = true;
        for ln in pstore_raw.lines() {
            if let Some(f) = ln.strip_prefix("@@PFILE:").and_then(|s| s.strip_suffix("@@")) {
                println!("  --- {f} ---");
            } else {
                println!("    {}", truncate_str(ln, 115));
            }
        }
    }

    // [2] shutdown-checkpoints
    println!("\n[2/4] /data/system/shutdown-checkpoints (recent clean userspace reboots):");
    let shut_raw = secs.get("SHUTDOWN").map(|s| s.as_str()).unwrap_or("").trim();
    if shut_raw.is_empty() {
        println!("  (none)");
    } else {
        for ln in shut_raw.lines() {
            if let Some(f) = ln.strip_prefix("@@SFILE:").and_then(|s| s.strip_suffix("@@")) {
                let name = Path::new(f).file_name().unwrap_or_default().to_string_lossy();
                println!("  {name}:");
            } else if !ln.trim().is_empty() {
                println!("    {}", truncate_str(ln.trim(), 115));
            }
        }
    }

    // [3] blackbox headers (pulled compact 64 KiB/slot binary — decoded in pure Rust!)
    println!("\n[3/4] /dev/block/by-name/blackbox (first {slots} x 8 MiB slot headers):");
    let host_bb = std::env::temp_dir().join(format!("ktool_bb_{}.bin", std::process::id()));
    let host_bb_s = host_bb.to_string_lossy().into_owned();
    let (rc_bb, _, _) = run_cmd("adb", &["-s", serial, "pull", tmp_bb, &host_bb_s], &ctx.ws_root, None);
    let _ = device::run_adb_probe(ctx, serial, &format!("rm -f {tmp_bb}\n"));
    if rc_bb == 0 {
        if let Ok(bytes) = fs::read(&host_bb) {
            let _ = fs::remove_file(&host_bb);
            let mut found_any = false;
            for (slot, chunk) in bytes.chunks(65536).enumerate() {
                let ascii = bytes_to_ascii_lines(chunk);
                if let Some((bi, br, pu)) = parse_blackbox_slot_header(&ascii) {
                    found_any = true;
                    let br_str = br
                        .map(|c| format!("{c} [{}]", decode_xiaomi_boot_reason(c)))
                        .unwrap_or_else(|| "?".to_string());
                    if br == Some(0x21) {
                        saw_panic = true;
                    }
                    println!(
                        "  slot {slot}: boot_index={:<6} BootReason={:<24} pureason={}",
                        bi.as_deref().unwrap_or("?"),
                        br_str,
                        pu.as_deref().unwrap_or("?")
                    );
                }
            }
            if !found_any {
                println!("  (no readable blackbox slot headers)");
            }
        }
    } else {
        println!("  (skipped: could not pull blackbox slot headers)");
    }

    // [4] mtdoops (fast adb pull of 16 MiB dump + immediate cleanup + pure-Rust decoder)
    println!("\n[4/4] /dev/block/by-name/oops (mtdoops 2 MiB slots decoded in Rust):");
    let tmp_host = std::env::temp_dir().join(format!("ktool_oops_{}.bin", std::process::id()));
    let host_s = tmp_host.to_string_lossy().into_owned();
    let (rc_pull, _, err_pull) = run_cmd("adb", &["-s", serial, "pull", tmp_oops, &host_s], &ctx.ws_root, None);
    let _ = device::run_adb_probe(ctx, serial, &format!("rm -f {tmp_oops}\n"));
    if rc_pull != 0 {
        println!("  !! adb pull oops failed: {}", err_pull.trim());
    } else if let Ok(bytes) = fs::read(&tmp_host) {
        let _ = fs::remove_file(&tmp_host);
        let parsed = parse_mtdoops_slots(&bytes, 2 * 1024 * 1024);
        if parsed.is_empty() {
            println!("  (all 8 mtdoops slots empty)");
        } else {
            for s in &parsed {
                println!(
                    "  slot {} (seq={}): boot_index={} pureason={} crit_hits={}",
                    s.slot,
                    s.seq,
                    s.boot_index.as_deref().unwrap_or("?"),
                    s.pureason.as_deref().unwrap_or("?"),
                    s.critical_hits.len()
                );
                for c in &s.critical_hits {
                    if c.contains("Kernel panic") || c.contains("Oops:") || c.contains("BUG:") || c.contains("Internal error:") {
                        saw_panic = true;
                    }
                    println!("     [!] {c}");
                }
                if s.critical_hits.is_empty() {
                    if let Some(last) = s.tail_lines.last() {
                        println!("     tail: {last}");
                    }
                }
            }
        }
    }

    println!(
        "\nCRASH-LOG SUMMARY: {}",
        if saw_panic { "PANIC / RAMOOPS RECORDED (inspect above)" } else { "NO ACTIVE PANIC FOUND" }
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mtdoops_slots_and_blackbox() {
        let mut buf = vec![0xffu8; 4096];
        // Slot 0 (2048 bytes): seq=7, panic line
        buf[0..4].copy_from_slice(&7u32.to_le_bytes());
        let msg = b"[    1.000] mtdoops.boot_index=5822 bootinfo.pureason=0x20001\n[   31.500] Kernel panic - not syncing: Oops\n";
        buf[4..4 + msg.len()].copy_from_slice(msg);
        // Slot 1: empty (0xffffffff)
        let slots = parse_mtdoops_slots(&buf, 2048);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].slot, 0);
        assert_eq!(slots[0].seq, 7);
        assert_eq!(slots[0].boot_index.as_deref(), Some("5822"));
        assert_eq!(slots[0].pureason.as_deref(), Some("0x20001"));
        assert_eq!(slots[0].critical_hits.len(), 1);

        let bb = "Boot_Index: 5818\nKeyPress:0, BootReason:33\npureason = 0x20001\n";
        let (bi, br, pu) = parse_blackbox_slot_header(bb).unwrap();
        assert_eq!(bi.as_deref(), Some("5818"));
        assert_eq!(br, Some(33));
        assert_eq!(decode_xiaomi_boot_reason(33), "KERNEL_PANIC(0x21)");
        assert_eq!(pu.as_deref(), Some("0x20001"));
    }
}
