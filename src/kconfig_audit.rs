use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::merge_intel;
use crate::util::*;

// ====================================================== 1. Kconfig `source`-graph reachability

#[derive(Debug, Default)]
pub struct KconfigGraph {
    /// Repo-relative normalized paths of every Kconfig file reached from root `Kconfig`.
    pub reachable_files: HashSet<String>,
    /// Every `config` / `menuconfig` symbol defined inside reachable Kconfig files.
    pub reachable_syms: HashSet<String>,
    /// Unresolvable / missing `source` targets encountered during traversal: (from_file, target).
    pub broken_sources: Vec<(String, String)>,
}

/// Normalize a repo-relative POSIX path (`a/b/../c` -> `a/c`).
fn norm_rel_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// Expand Kconfig `$(SRCARCH)` / `$SRCARCH` / `$(ARCH)` / `$ARCH` / `$(srctree)` macros.
/// Returns `None` if an unknown dynamic variable (e.g. `$(KCONFIG_DEFCONFIG_LIST)`) remains.
pub fn expand_kconfig_vars(raw: &str, arch: &str) -> Option<String> {
    let mut s = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    for (pat, rep) in [
        ("$(SRCARCH)", arch),
        ("$SRCARCH", arch),
        ("$(ARCH)", arch),
        ("$ARCH", arch),
        ("$(SUBARCH)", arch),
        ("$SUBARCH", arch),
        ("$(srctree)/", ""),
        ("$srctree/", ""),
        ("$(srctree)", ""),
        ("$srctree", ""),
    ] {
        if s.contains(pat) {
            s = s.replace(pat, rep);
        }
    }
    if s.contains('$') || s.is_empty() {
        return None;
    }
    Some(norm_rel_path(&s))
}

/// Parse a `source` / `osource` / `rsource` / `orsource` directive line.
/// Returns `Some((is_optional, is_relative, raw_target))`.
/// Rejects prose lines inside Kconfig `help` blocks (multi-word English sentences).
pub fn parse_kconfig_source_line(line: &str) -> Option<(bool, bool, String)> {
    let code = line.split('#').next().unwrap_or("").trim();
    let (opt, rel, rest) = if let Some(r) = code.strip_prefix("orsource") {
        (true, true, r)
    } else if let Some(r) = code.strip_prefix("rsource") {
        (false, true, r)
    } else if let Some(r) = code.strip_prefix("osource") {
        (true, false, r)
    } else if let Some(r) = code.strip_prefix("source") {
        (false, false, r)
    } else {
        return None;
    };
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let raw = rest.trim();
    let (quoted, target) = if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        (true, inner.trim())
    } else if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        (true, inner.trim())
    } else {
        // Unquoted source path must be a single path token (never English prose!)
        if raw.contains(|c: char| c.is_ascii_whitespace()) {
            return None;
        }
        (false, raw)
    };
    if target.is_empty() || target.contains(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    // If indented (possibly inside `if ... endif` or `help`), require quoted path or Kconfig path shape
    if !quoted && (line.starts_with('\t') || line.starts_with("  ")) {
        if !target.contains('/') && !target.contains("Kconfig") {
            return None;
        }
    }
    Some((opt, rel, target.to_string()))
}

/// Parse a `config FOO` or `menuconfig FOO` symbol definition line (including indented `choice` items).
pub fn parse_kconfig_sym_def(line: &str) -> Option<String> {
    let code = line.split('#').next().unwrap_or("").trim();
    let rest = if let Some(r) = code.strip_prefix("menuconfig") {
        r
    } else if let Some(r) = code.strip_prefix("config") {
        r
    } else {
        return None;
    };
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let mut toks = rest.split_whitespace();
    let sym = toks.next()?;
    // Real Kconfig symbol definitions have ONLY the symbol name on the line (and uppercase/digit/underscore)
    if toks.next().is_some() {
        return None;
    }
    if sym.len() < 2
        || !sym.as_bytes()[0].is_ascii_uppercase()
        || !sym
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some(sym.to_string())
}

/// Simple wildcard expander for a single `*` path component (e.g. `drivers/*/Kconfig`).
fn expand_simple_glob(repo: &Path, rel_pattern: &str) -> Vec<String> {
    if !rel_pattern.contains('*') {
        return vec![rel_pattern.to_string()];
    }
    let parts: Vec<&str> = rel_pattern.split('/').collect();
    let Some(star_idx) = parts.iter().position(|p| p.contains('*')) else {
        return vec![rel_pattern.to_string()];
    };
    let prefix = parts[..star_idx].join("/");
    let suffix = parts[star_idx + 1..].join("/");
    let star_pat = parts[star_idx];
    let (pre_lit, suf_lit) = star_pat.split_once('*').unwrap_or(("", ""));
    let dir = if prefix.is_empty() {
        repo.to_path_buf()
    } else {
        repo.join(&prefix)
    };
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        let mut names: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.starts_with(pre_lit) && n.ends_with(suf_lit))
            .collect();
        names.sort();
        for name in names {
            let cand = match (prefix.is_empty(), suffix.is_empty()) {
                (true, true) => name,
                (true, false) => format!("{name}/{suffix}"),
                (false, true) => format!("{prefix}/{name}"),
                (false, false) => format!("{prefix}/{name}/{suffix}"),
            };
            let norm = norm_rel_path(&cand);
            if repo.join(&norm).is_file() {
                out.push(norm);
            }
        }
    }
    out
}

/// Walk the live Kconfig `source` graph from root `Kconfig` (default `arch = "arm64"`).
pub fn walk_kconfig_tree(repo: &Path, arch: &str) -> KconfigGraph {
    let mut graph = KconfigGraph::default();
    let mut stack: Vec<String> = Vec::new();
    if repo.join("Kconfig").is_file() {
        stack.push("Kconfig".to_string());
    } else {
        return graph;
    }

    while let Some(rel) = stack.pop() {
        if !graph.reachable_files.insert(rel.clone()) {
            continue;
        }
        let full = repo.join(&rel);
        let Ok(txt) = fs::read_to_string(&full) else {
            continue;
        };
        let parent_rel = Path::new(&rel)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        for ln in txt.lines() {
            if let Some(sym) = parse_kconfig_sym_def(ln) {
                graph.reachable_syms.insert(sym);
                continue;
            }
            if let Some((is_opt, is_rel, raw_target)) = parse_kconfig_source_line(ln) {
                let Some(expanded) = expand_kconfig_vars(&raw_target, arch) else {
                    continue;
                };
                let joined = if is_rel && !parent_rel.is_empty() {
                    norm_rel_path(&format!("{parent_rel}/{expanded}"))
                } else {
                    expanded
                };
                let targets = expand_simple_glob(repo, &joined);
                if targets.is_empty() && !is_opt && !joined.contains('*') {
                    graph.broken_sources.push((rel.clone(), joined));
                    continue;
                }
                for tgt in targets {
                    if repo.join(&tgt).is_file() {
                        if !graph.reachable_files.contains(&tgt) {
                            stack.push(tgt);
                        }
                    } else if !is_opt {
                        graph.broken_sources.push((rel.clone(), tgt));
                    }
                }
            }
        }
    }
    graph
}

// ====================================================== 2. Vendor Config Fragment Discovery

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgVal {
    Enabled(String), // "y", "m", or literal value
    Disabled,
}

/// Evaluate a stack of defconfig / `.config` fragments in override order.
/// Returns `sym_without_CONFIG_prefix -> (CfgVal, fragment_basename)`.
pub fn eval_config_fragments(fragments: &[(String, String)]) -> BTreeMap<String, (CfgVal, String)> {
    let mut map: BTreeMap<String, (CfgVal, String)> = BTreeMap::new();
    for (name, txt) in fragments {
        for raw in txt.lines() {
            let t = raw.trim();
            if let Some(rest) = t.strip_prefix("# CONFIG_") {
                if let Some(sym) = rest.strip_suffix(" is not set") {
                    if !sym.is_empty() {
                        map.insert(sym.to_string(), (CfgVal::Disabled, name.clone()));
                    }
                }
            } else if let Some(rest) = t.strip_prefix("CONFIG_") {
                if let Some((sym, val)) = rest.split_once('=') {
                    let sym = sym.trim();
                    let val = val.trim();
                    if !sym.is_empty() && !val.is_empty() {
                        let cv = if val == "n" {
                            CfgVal::Disabled
                        } else {
                            CfgVal::Enabled(val.to_string())
                        };
                        map.insert(sym.to_string(), (cv, name.clone()));
                    }
                }
            }
        }
    }
    map
}

/// Parse `TARGET_KERNEL_CONFIG := ...` entries from a Lineage/AOSP `BoardConfig.mk`.
pub fn parse_boardconfig_kernel_fragments(board_mk: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_var = false;
    for raw in board_mk.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if !in_var {
            if let Some(rest) = line.strip_prefix("TARGET_KERNEL_CONFIG") {
                let rest = rest.trim_start();
                if let Some(rhs) = rest
                    .strip_prefix(":=")
                    .or_else(|| rest.strip_prefix("+="))
                    .or_else(|| rest.strip_prefix('='))
                {
                    let cont = rhs.trim_end().ends_with('\\');
                    let clean = rhs.trim_end().trim_end_matches('\\');
                    for tok in clean.split_whitespace() {
                        if !tok.starts_with("$(") {
                            out.push(tok.to_string());
                        }
                    }
                    in_var = cont;
                }
            }
        } else {
            let cont = line.ends_with('\\');
            let clean = line.trim_end_matches('\\');
            for tok in clean.split_whitespace() {
                if !tok.starts_with("$(") {
                    out.push(tok.to_string());
                }
            }
            in_var = cont;
        }
    }
    out
}

/// Auto-discover active vendor config fragments (BoardConfig.mk `TARGET_KERNEL_CONFIG` or fallback).
fn discover_vendor_fragments(ctx: &Ctx, extra_configs: &[PathBuf]) -> Vec<(String, PathBuf)> {
    if !extra_configs.is_empty() {
        return extra_configs
            .iter()
            .filter(|p| p.is_file())
            .map(|p| {
                (
                    p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.display().to_string()),
                    p.clone(),
                )
            })
            .collect();
    }

    let cfg_root = ctx.repo.join("arch/arm64/configs");
    let mut found: Vec<(String, PathBuf)> = Vec::new();

    // 1. Try reading TARGET_KERNEL_CONFIG from BoardConfig.mk
    let board_mk = ctx.ws_root.join("src/device/xiaomi/onyx/BoardConfig.mk");
    if let Ok(txt) = fs::read_to_string(&board_mk) {
        for entry in parse_boardconfig_kernel_fragments(&txt) {
            // Focus on vendor/ device fragments (base gki_defconfig is upstream-maintained)
            if entry.contains('/') {
                let p = cfg_root.join(&entry);
                if p.is_file() {
                    found.push((entry, p));
                }
            }
        }
    }

    // 2. Fallback: look for vendor/*_perf.config inside the kernel repo itself
    if found.is_empty() {
        let vendor_dir = cfg_root.join("vendor");
        if let Ok(rd) = fs::read_dir(&vendor_dir) {
            let mut cands: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.ends_with("_perf.config"))
                })
                .collect();
            cands.sort();
            for p in cands {
                let label = format!(
                    "vendor/{}",
                    p.file_name().unwrap_or_default().to_string_lossy()
                );
                found.push((label, p));
            }
        }
    }
    found
}

// ====================================================== 3. `kawal kconfig-audit` (Gate 15)

pub fn cmd_kconfig_audit(
    ctx: &Ctx,
    base: Option<&str>,
    head: &str,
    extra_configs: &[PathBuf],
) -> i32 {
    let (rc, _) = run_kconfig_audit(ctx, base, head, extra_configs);
    rc
}

pub fn run_kconfig_audit(
    ctx: &Ctx,
    base: Option<&str>,
    head: &str,
    extra_configs: &[PathBuf],
) -> (i32, String) {
    let label = match base {
        Some(b) => format!("{b}..{head}"),
        None => "live tree".to_string(),
    };
    println!("=== kconfig-audit: Kconfig source-graph reachability & Kbuild drop guard ({label}) ===");

    if !ctx.repo.join("Kconfig").is_file() {
        println!("  skip: no root Kconfig in {}", ctx.repo.display());
        return (0, "no root Kconfig".to_string());
    }

    let graph = walk_kconfig_tree(&ctx.repo, "arm64");
    let mut hard_issues: Vec<String> = Vec::new();
    let mut warns: Vec<String> = Vec::new();

    // 1. Broken non-optional `source` directives in live Kconfig graph
    for (from_f, tgt) in &graph.broken_sources {
        hard_issues.push(format!(
            "[BROKEN-SOURCE] {from_f} sources missing file `{tgt}`"
        ));
    }

    // 2. Vendor config fragment reachability check
    let frag_paths = discover_vendor_fragments(ctx, extra_configs);
    let mut loaded_frags: Vec<(String, String)> = Vec::new();
    for (name, p) in &frag_paths {
        if let Ok(txt) = fs::read_to_string(p) {
            loaded_frags.push((name.clone(), txt));
        }
    }
    let effective = eval_config_fragments(&loaded_frags);
    let enabled_vendor: Vec<(&String, &String, &String)> = effective
        .iter()
        .filter_map(|(sym, (cv, src))| match cv {
            CfgVal::Enabled(v) if v == "y" || v == "m" => Some((sym, v, src)),
            _ => None,
        })
        .collect();

    // Check which enabled vendor symbols are NOT reachable from root Kconfig!
    let unreachable: Vec<(&String, &String, &String)> = enabled_vendor
        .iter()
        .copied()
        .filter(|(sym, _, _)| !graph.reachable_syms.contains(*sym))
        .collect();

    if !unreachable.is_empty() {
        // Check which unreachable symbols exist in an ORPHANED Kconfig file on disk!
        let mut sym_disk_loc: HashMap<String, String> = HashMap::new();
        for chunk in unreachable.chunks(60) {
            let alt = chunk
                .iter()
                .map(|(s, _, _)| s.as_str())
                .collect::<Vec<_>>()
                .join("|");
            let pat = format!(r"^\s*(menu)?config\s+({alt})\b");
            let (_, out) = rg(&ctx.repo, &["-n", "-g", "*Kconfig*", &pat]);
            for ln in out.lines() {
                let p: Vec<&str> = ln.splitn(3, ':').collect();
                if p.len() == 3 {
                    // Ignore foreign arch/<other>/ Kconfig definitions when auditing arm64
                    if p[0].starts_with("arch/") && !p[0].starts_with("arch/arm64/") {
                        continue;
                    }
                    if let Some(sym) = parse_kconfig_sym_def(p[2]) {
                        sym_disk_loc
                            .entry(sym)
                            .or_insert_with(|| format!("{}:{}", p[0], p[1]));
                    }
                }
            }
        }

        // If base ref given, also check which unreachable symbols WERE defined in base Kconfigs!
        let mut dropped_from_file: HashMap<String, String> = HashMap::new();
        if let Some(b) = base {
            let diff = git(ctx, &["diff", "-U0", b, head, "--", "*Kconfig*"]);
            let mut cur = String::new();
            for ln in diff.lines() {
                if let Some(p) = ln.strip_prefix("--- a/") {
                    cur = p.trim().to_string();
                } else if let Some(rem) = ln.strip_prefix('-') {
                    if !ln.starts_with("---") {
                        if let Some(sym) = parse_kconfig_sym_def(rem) {
                            dropped_from_file.entry(sym).or_insert_with(|| cur.clone());
                        }
                    }
                }
            }
        }

        for (sym, val, frag) in &unreachable {
            if let Some(loc) = sym_disk_loc.get(*sym) {
                hard_issues.push(format!(
                    "[ORPHANED-KCONFIG] CONFIG_{sym}={val} (from {frag}) is defined at {loc}, \
                     but that Kconfig is NOT reachable from root Kconfig! (dropped `source` line?)"
                ));
            } else if let Some(from_k) = dropped_from_file.get(*sym) {
                hard_issues.push(format!(
                    "[DROPPED-KCONFIG] CONFIG_{sym}={val} (from {frag}) was DELETED from {from_k} in {label}!"
                ));
            } else {
                warns.push(format!(
                    "[UNREACHABLE-CFG] CONFIG_{sym}={val} (from {frag}) has no reachable Kconfig definition"
                ));
            }
        }
    }

    // 3. Diff-based Kconfig `source` & Makefile `obj-$(CONFIG_...)` drop guard!
    if let Some(b) = base {
        let kdiff = git(ctx, &["diff", "-U0", b, head, "--", "*Kconfig*"]);
        let mut cur_file = String::new();
        let mut removed_sources: Vec<(String, String)> = Vec::new();
        let mut added_sources: HashSet<String> = HashSet::new();
        for ln in kdiff.lines() {
            if let Some(p) = ln.strip_prefix("+++ b/") {
                cur_file = p.trim().to_string();
            } else if let Some(rem) = ln.strip_prefix('-') {
                if !ln.starts_with("---") {
                    if let Some((_, is_rel, raw_tgt)) = parse_kconfig_source_line(rem) {
                        if let Some(exp) = expand_kconfig_vars(&raw_tgt, "arm64") {
                            let full_rel = if is_rel {
                                let par = Path::new(&cur_file)
                                    .parent()
                                    .map(|p| p.to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                if par.is_empty() {
                                    exp
                                } else {
                                    norm_rel_path(&format!("{par}/{exp}"))
                                }
                            } else {
                                exp
                            };
                            removed_sources.push((cur_file.clone(), full_rel));
                        }
                    }
                }
            } else if let Some(add) = ln.strip_prefix('+') {
                if !ln.starts_with("+++") {
                    if let Some((_, is_rel, raw_tgt)) = parse_kconfig_source_line(add) {
                        if let Some(exp) = expand_kconfig_vars(&raw_tgt, "arm64") {
                            let full_rel = if is_rel {
                                let par = Path::new(&cur_file)
                                    .parent()
                                    .map(|p| p.to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                if par.is_empty() {
                                    exp
                                } else {
                                    norm_rel_path(&format!("{par}/{exp}"))
                                }
                            } else {
                                exp
                            };
                            added_sources.insert(full_rel);
                        }
                    }
                }
            }
        }
        for (kfile, tgt) in removed_sources {
            if added_sources.contains(&tgt) {
                continue;
            }
            if ctx.repo.join(&tgt).is_file() && !graph.reachable_files.contains(&tgt) {
                hard_issues.push(format!(
                    "[DROPPED-SOURCE] {kfile} dropped `source \"{tgt}\"` — file STILL EXISTS on disk but is now orphaned!"
                ));
            }
        }

        // Check dropped `obj-$(CONFIG_FOO) += bar.o` in Makefiles where CONFIG_FOO is enabled in vendor fragments!
        let mdiff = git(ctx, &["diff", "-U0", b, head, "--", "*Makefile*"]);
        let mut cur_mk = String::new();
        for ln in mdiff.lines() {
            if let Some(p) = ln.strip_prefix("+++ b/") {
                cur_mk = p.trim().to_string();
            } else if let Some(rem) = ln.strip_prefix('-') {
                if ln.starts_with("---") || cur_mk.is_empty() {
                    continue;
                }
                let tr = rem.trim();
                if let Some(after) = tr.strip_prefix("obj-$(CONFIG_") {
                    if let Some((sym, rhs)) = after.split_once(')') {
                        let is_en = matches!(
                            effective.get(sym),
                            Some((CfgVal::Enabled(v), _)) if v == "y" || v == "m"
                        );
                        if is_en {
                            if let Some((_, objs_str)) = rhs.split_once('=') {
                                let cur_txt = fs::read_to_string(ctx.repo.join(&cur_mk))
                                    .unwrap_or_default();
                                if !cur_txt.contains(&format!("CONFIG_{sym}")) {
                                    let dir = Path::new(&cur_mk)
                                        .parent()
                                        .unwrap_or(Path::new(""));
                                    for tok in objs_str.split_whitespace() {
                                        let stem = tok.trim_end_matches(".o").trim_end_matches('/');
                                        let exists = ctx.repo.join(dir).join(format!("{stem}.c")).is_file()
                                            || ctx.repo.join(dir).join(stem).is_dir();
                                        if exists {
                                            hard_issues.push(format!(
                                                "[DROPPED-MAKEFILE-OBJ] {cur_mk} dropped `obj-$(CONFIG_{sym}) += {tok}` \
                                                 while CONFIG_{sym} is enabled and source still exists!"
                                            ));
                                            break;
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

    println!(
        "  indexed {} reachable Kconfig files ({} symbols); checked {} enabled vendor configs ({})",
        graph.reachable_files.len(),
        graph.reachable_syms.len(),
        enabled_vendor.len(),
        if frag_paths.is_empty() {
            "no vendor fragments found".to_string()
        } else {
            frag_paths
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(" -> ")
        }
    );

    if !warns.is_empty() {
        println!(
            "  note: {} vendor config(s) not in Kconfig (stale/legacy fragment entries):",
            warns.len()
        );
        for w in warns.iter().take(6) {
            println!("    {w}");
        }
        if warns.len() > 6 {
            println!("    ... (+{} more)", warns.len() - 6);
        }
    }

    if hard_issues.is_empty() {
        println!("  clean: 0 orphaned/dropped Kconfig sources, symbols, or active Makefile targets");
        (
            0,
            format!(
                "0 drops ({} reachable Kconfigs, {} vendor configs)",
                graph.reachable_files.len(),
                enabled_vendor.len()
            ),
        )
    } else {
        for h in &hard_issues {
            println!("  !! {h}");
        }
        (
            1,
            format!(
                "{} Kconfig/Makefile drop(s) detected!",
                hard_issues.len()
            ),
        )
    }
}

// ====================================================== 4. `kawal merge-audit` (Gate 16)

fn ls_tree_blobs(ctx: &Ctx, rev: &str) -> HashMap<String, String> {
    let out = git(ctx, &["ls-tree", "-r", rev]);
    let mut m = HashMap::with_capacity(80000);
    for ln in out.lines() {
        if let Some((meta, path)) = ln.split_once('\t') {
            let mut it = meta.split_whitespace();
            let _mode = it.next();
            let _kind = it.next();
            if let Some(sha) = it.next() {
                m.insert(path.to_string(), sha.to_string());
            }
        }
    }
    m
}

fn diff_numstat_map(ctx: &Ctx, a: &str, b: &str) -> HashMap<String, (usize, usize)> {
    let out = git(ctx, &["diff", "--numstat", a, b]);
    let mut m = HashMap::new();
    for ln in out.lines() {
        let p: Vec<&str> = ln.split('\t').collect();
        if p.len() == 3 && p[0] != "-" && p[1] != "-" {
            let add = p[0].parse::<usize>().unwrap_or(0);
            let del = p[1].parse::<usize>().unwrap_or(0);
            m.insert(p[2].to_string(), (add, del));
        }
    }
    m
}

/// Check if a file path is a Kbuild / Kconfig / defconfig file.
pub fn is_kbuild_file(path: &str) -> bool {
    let base = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);
    base == "Kconfig"
        || base.starts_with("Kconfig.")
        || base == "Makefile"
        || base.starts_with("Makefile.")
        || base == "Kbuild"
        || base.ends_with(".config")
        || base.ends_with(".cfg")
        || base.ends_with("defconfig")
}

/// Filter out blank and comment-only lines when comparing custom additions.
fn is_meaningful_line(s: &str) -> bool {
    let t = s.trim();
    if t.len() <= 2 {
        return false;
    }
    if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with('#') && !t.starts_with("#include") && !t.starts_with("#define") && !t.starts_with("#if") {
        return false;
    }
    true
}

/// Pure function: evaluate whether a file replaced by `--theirs` actually lost local custom lines
/// (vs being a genuinely upstreamed fix like `ufs_bsg.c`, `tcp_metrics.c`, `gendwarfksyms.c`).
/// Returns `(lost_count, total_custom_added, sample_lost)`.
pub fn count_lost_custom_lines(
    ours_diff_vs_base: &str,
    theirs_content: &str,
) -> (usize, usize, Vec<String>) {
    let theirs_set: HashSet<&str> = theirs_content.lines().map(|l| l.trim()).collect();
    let mut added: BTreeSet<String> = BTreeSet::new();
    for ln in ours_diff_vs_base.lines() {
        if let Some(rest) = ln.strip_prefix('+') {
            if ln.starts_with("+++") {
                continue;
            }
            let t = rest.trim();
            if is_meaningful_line(t) {
                added.insert(t.to_string());
            }
        }
    }
    let total = added.len();
    let mut lost: Vec<String> = Vec::new();
    for l in &added {
        if !theirs_set.contains(l.as_str()) {
            lost.push(l.clone());
        }
    }
    let n_lost = lost.len();
    lost.truncate(4);
    (n_lost, total, lost)
}

/// Pure function: detect abnormal diff-bloat where `pre..head` changed far more lines than
/// `up_base..theirs` (e.g. `arm-smmu-v3.c`: `+1225/-187` vs `+6/-0`).
pub fn is_diff_bloat(head_add: usize, head_del: usize, up_add: usize, up_del: usize) -> bool {
    let h_chg = head_add + head_del;
    let u_chg = up_add + up_del;
    h_chg >= 25 && h_chg > (3 * u_chg + 10)
}

/// Auto-resolve `(upstream_base, theirs)` for `merge-audit` when not explicitly passed.
fn resolve_audit_upstream_refs(
    ctx: &Ctx,
    head: &str,
    up_base_opt: Option<&str>,
    theirs_opt: Option<&str>,
) -> Option<(String, String)> {
    if let (Some(b), Some(t)) = (up_base_opt, theirs_opt) {
        return Some((b.to_string(), t.to_string()));
    }
    // 1. Check if `head` is a real 2-parent merge commit
    let parents: Vec<String> = git(ctx, &["rev-list", "--parents", "-n", "1", head])
        .split_whitespace()
        .skip(1)
        .map(String::from)
        .collect();
    if parents.len() >= 2 {
        let mb = git(ctx, &["merge-base", &parents[0], &parents[1]])
            .trim()
            .to_string();
        if !mb.is_empty() {
            return Some((mb, parents[1].clone()));
        }
    }
    // 2. Fall back to `.git/KAWAL_MERGE3_META` or `.git/KAWAL_LAST_MERGE`
    merge_intel::read_merge3_meta(ctx).or_else(|| merge_intel::read_last_merge_meta(ctx))
}

pub fn cmd_merge_audit(
    ctx: &Ctx,
    pre: &str,
    head: &str,
    up_base_opt: Option<&str>,
    theirs_opt: Option<&str>,
    all_files: bool,
) -> i32 {
    let (rc, _) = run_merge_audit(ctx, pre, head, up_base_opt, theirs_opt, all_files);
    rc
}

/// Forensic anti-silent-merge auditor:
///  A. `WIPED->THEIRS`: files where `ours` had local/CLO/ACK code (`pre != up_base`) and `--theirs`
///     overwrote the file with exact upstream blob (`head == theirs`), dropping custom lines.
///  B. `DIFF-BLOAT`: files where `|pre..head|` is >3x `|up_base..theirs| + 10` on diverged files.
///  C. `HELD-OURS`: built non-CLO files kept byte-identical to `pre` while upstream changed them.
pub fn run_merge_audit(
    ctx: &Ctx,
    pre: &str,
    head: &str,
    up_base_opt: Option<&str>,
    theirs_opt: Option<&str>,
    all_files: bool,
) -> (i32, String) {
    let Some((up_base, theirs)) = resolve_audit_upstream_refs(ctx, head, up_base_opt, theirs_opt)
    else {
        println!("=== merge-audit: skipped (no upstream-base/theirs refs; pass --up-base <ref> --theirs <ref>) ===");
        return (0, "skipped (no upstream refs)".to_string());
    };

    println!(
        "=== merge-audit: forensic wipe/bloat/held-ours check ({pre}..{head} vs {up_base}..{theirs}) ==="
    );

    // Load 4 tree blob maps in parallel (~80ms total!)
    let revs = [pre, head, up_base.as_str(), theirs.as_str()];
    let trees: Vec<HashMap<String, String>> =
        par_map(&revs, 4, |&r| ls_tree_blobs(ctx, r));
    let (t_pre, t_head, t_upb, t_th) = (&trees[0], &trees[1], &trees[2], &trees[3]);

    // Check A candidates: pre != up_base AND head == theirs AND head != pre
    let mut wipe_cands: Vec<String> = Vec::new();
    for (path, h_head) in t_head {
        if !all_files
            && IGNORED_PREFIXES.iter().any(|p| path.starts_with(p))
            && !is_kbuild_file(path)
        {
            continue;
        }
        let h_pre = t_pre.get(path);
        let h_upb = t_upb.get(path);
        let h_th = t_th.get(path);
        if h_th == Some(h_head) && h_pre != Some(h_head) && h_pre != h_upb {
            wipe_cands.push(path.clone());
        }
    }
    wipe_cands.sort();

    // Evaluate each wipe candidate in parallel
    struct WipeHit {
        path: String,
        lost: usize,
        total_added: usize,
        sample: Vec<String>,
        stripped_markers: Vec<&'static str>,
        kbuild: bool,
        built: bool,
        head_chg: (usize, usize),
        up_chg: (usize, usize),
    }

    let ns_head = diff_numstat_map(ctx, pre, head);
    let ns_up = diff_numstat_map(ctx, &up_base, &theirs);

    let wipe_res: Vec<WipeHit> = par_map(&wipe_cands, ctx.threads, |path| {
        let ours_diff = git(ctx, &["diff", "-U0", &up_base, pre, "--", path]);
        let theirs_txt = git(ctx, &["show", &format!("{theirs}:{path}")]);
        let ours_txt = git(ctx, &["show", &format!("{pre}:{path}")]);
        let (lost, total_added, sample) = count_lost_custom_lines(&ours_diff, &theirs_txt);
        let mut markers = merge_intel::detect_stripped_protected_markers(&ours_txt, &theirs_txt);
        markers.extend(merge_intel::detect_clo_markers(&ours_txt, &theirs_txt));
        WipeHit {
            path: path.clone(),
            lost,
            total_added,
            sample,
            stripped_markers: markers,
            kbuild: is_kbuild_file(path),
            built: is_built_file(ctx, path),
            head_chg: ns_head.get(path).copied().unwrap_or((0, 0)),
            up_chg: ns_up.get(path).copied().unwrap_or((0, 0)),
        }
    });

    let mut hard_wipes: Vec<&WipeHit> = Vec::new();
    let mut upstreamed_ok = 0usize;
    let mut minor_wipes: Vec<&WipeHit> = Vec::new();

    for w in &wipe_res {
        if w.lost == 0 && w.stripped_markers.is_empty() {
            upstreamed_ok += 1;
            continue;
        }
        let bloat = is_diff_bloat(w.head_chg.0, w.head_chg.1, w.up_chg.0, w.up_chg.1);
        if w.kbuild || !w.stripped_markers.is_empty() || bloat || (w.built && w.lost >= 3) {
            hard_wipes.push(w);
        } else if w.lost > 0 {
            minor_wipes.push(w);
        }
    }

    // Check B: DIFF-BLOAT (even if file is NOT byte-equal to `theirs`, e.g. 1-line tweak after wipe!)
    let wipe_set: HashSet<&str> = hard_wipes.iter().map(|w| w.path.as_str()).collect();
    let mut bloat_hits: Vec<(String, (usize, usize), (usize, usize))> = Vec::new();
    for (path, &(ha, hd)) in &ns_head {
        if wipe_set.contains(path.as_str()) {
            continue;
        }
        if !all_files && IGNORED_PREFIXES.iter().any(|p| path.starts_with(p)) && !is_kbuild_file(path) {
            continue;
        }
        // Only files existing in both pre & head AND diverged from up_base before merge
        if !t_pre.contains_key(path) || !t_head.contains_key(path) {
            continue;
        }
        if t_pre.get(path) == t_upb.get(path) {
            continue;
        }
        let (ua, ud) = ns_up.get(path).copied().unwrap_or((0, 0));
        if is_diff_bloat(ha, hd, ua, ud) {
            bloat_hits.push((path.clone(), (ha, hd), (ua, ud)));
        }
    }
    bloat_hits.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)));

    // Check C: HELD-OURS advisory (built non-CLO files untouched by merge while upstream changed them,
    // filtering out fixes ALREADY present in ACK/CLO prior to this merge!)
    let mut held_cands: Vec<(String, usize, usize)> = Vec::new();
    for (path, &(ua, ud)) in &ns_up {
        if ua + ud == 0 {
            continue;
        }
        if merge_intel::is_clo_soc_path(path) || !is_built_file(ctx, path) {
            continue;
        }
        if t_pre.get(path).is_some() && t_pre.get(path) == t_head.get(path) {
            held_cands.push((path.clone(), ua, ud));
        }
    }
    held_cands.sort();

    let held_checked: Vec<Option<(String, usize, usize, usize)>> =
        par_map(&held_cands, ctx.threads, |(path, ua, ud)| {
            let up_diff = git(ctx, &["diff", "-U0", &up_base, &theirs, "--", path]);
            let head_txt = git(ctx, &["show", &format!("{head}:{path}")]);
            let (missing, total_up_add, _) = count_lost_custom_lines(&up_diff, &head_txt);
            if total_up_add > 0 && missing == 0 {
                // Upstream additions were ALREADY present in ACK/CLO!
                return None;
            }
            // If upstream only deleted lines, check whether those deleted lines still exist in head
            if total_up_add == 0 && *ud > 0 {
                let head_set: HashSet<&str> = head_txt.lines().map(|l| l.trim()).collect();
                let still_present = up_diff
                    .lines()
                    .filter_map(|l| l.strip_prefix('-'))
                    .filter(|l| !l.starts_with("--") && is_meaningful_line(l))
                    .filter(|l| head_set.contains(l.trim()))
                    .count();
                if still_present == 0 {
                    return None;
                }
                return Some((path.clone(), *ua, *ud, still_present));
            }
            Some((path.clone(), *ua, *ud, missing))
        });
    let held_ours: Vec<(String, usize, usize, usize)> =
        held_checked.into_iter().flatten().collect();

    if !hard_wipes.is_empty() {
        println!(
            "  !! FAIL [WIPED->THEIRS]: {} file(s) had local/CLO/ACK changes overwritten by --theirs:",
            hard_wipes.len()
        );
        for w in &hard_wipes {
            let tag = if w.kbuild {
                "[KBUILD]"
            } else if w.built {
                "[BUILT] "
            } else {
                "[unblt] "
            };
            let mnote = if w.stripped_markers.is_empty() {
                String::new()
            } else {
                format!(
                    " | STRIPPED: {}",
                    w.stripped_markers
                        .iter()
                        .take(3)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            println!(
                "     {tag} {}  (lost {}/{} custom lines; HEAD=+{}/-{} vs up=+{}/-{}{mnote})",
                w.path, w.lost, w.total_added, w.head_chg.0, w.head_chg.1, w.up_chg.0, w.up_chg.1
            );
            for s in w.sample.iter().take(2) {
                println!("         dropped: {}", truncate_str(s, 90));
            }
        }
    }

    if !bloat_hits.is_empty() {
        println!(
            "  !! FAIL [DIFF-BLOAT]: {} diverged file(s) changed >3x upstream patch size:",
            bloat_hits.len()
        );
        for (p, (ha, hd), (ua, ud)) in bloat_hits.iter().take(15) {
            println!("     {p}  (HEAD=+{ha}/-{hd} vs upstream=+{ua}/-{ud})");
        }
    }

    if !minor_wipes.is_empty() {
        println!(
            "  note: {} minor unbuilt file(s) matched --theirs ({upstreamed_ok} upstreamed/lossless)",
            minor_wipes.len()
        );
    } else if upstreamed_ok > 0 {
        println!("  ok: {upstreamed_ok} file(s) matching --theirs were 100% lossless (upstreamed fixes)");
    }

    if !held_ours.is_empty() {
        println!(
            "  WARN [HELD-OURS]: {} built non-CLO file(s) stayed byte-identical to {pre} with unmerged upstream lines:",
            held_ours.len()
        );
        for (p, ua, ud, miss) in held_ours.iter().take(12) {
            println!("     {p}  (upstream +{ua}/-{ud}, {miss} line(s) absent in {head} — verify no fix missed!)");
        }
        if held_ours.len() > 12 {
            println!("     ... (+{} more)", held_ours.len() - 12);
        }
    }

    let fails = hard_wipes.len() + bloat_hits.len();
    if fails == 0 {
        println!(
            "  clean: 0 --theirs wipes, 0 diff-bloat anomalies ({} held-ours advisories)",
            held_ours.len()
        );
        (
            0,
            format!(
                "0 wipes, 0 bloat ({} held-ours)",
                held_ours.len()
            ),
        )
    } else {
        (
            1,
            format!(
                "{} WIPED->THEIRS + {} DIFF-BLOAT!",
                hard_wipes.len(),
                bloat_hits.len()
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kconfig_source_and_sym_parsing() {
        assert_eq!(
            parse_kconfig_source_line(r#"source "kernel/sched/walt/Kconfig""#),
            Some((false, false, "kernel/sched/walt/Kconfig".to_string()))
        );
        assert_eq!(
            parse_kconfig_source_line(r#"osource "arch/$(SRCARCH)/Kconfig" # comment"#),
            Some((true, false, "arch/$(SRCARCH)/Kconfig".to_string()))
        );
        assert_eq!(
            parse_kconfig_source_line(r#"rsource "sub/Kconfig""#),
            Some((false, true, "sub/Kconfig".to_string()))
        );
        // Indented help prose must NEVER be parsed as a source directive!
        assert_eq!(
            parse_kconfig_source_line("\tsource and sink components. These can be used."),
            None
        );
        assert_eq!(
            parse_kconfig_source_line("  source tree isn't cleaned after install."),
            None
        );
        assert_eq!(parse_kconfig_source_line("sourced_foo bar"), None);

        assert_eq!(
            expand_kconfig_vars("arch/$(SRCARCH)/Kconfig", "arm64"),
            Some("arch/arm64/Kconfig".to_string())
        );
        assert_eq!(expand_kconfig_vars("$(KCONFIG_DEFCONFIG_LIST)", "arm64"), None);

        assert_eq!(parse_kconfig_sym_def("config SCHED_WALT"), Some("SCHED_WALT".to_string()));
        assert_eq!(parse_kconfig_sym_def("\tconfig HZ_300"), Some("HZ_300".to_string()));
        assert_eq!(
            parse_kconfig_sym_def("menuconfig QCOM_MPAM # hdr"),
            Some("QCOM_MPAM".to_string())
        );
        assert_eq!(parse_kconfig_sym_def("\tconfig option allows setting"), None);
        assert_eq!(parse_kconfig_sym_def("config_foo bar"), None);
    }

    #[test]
    fn test_eval_config_fragments_override_order() {
        let frags = vec![
            (
                "sun_perf.config".to_string(),
                "CONFIG_SCHED_WALT=m\nCONFIG_CORESIGHT=m\nCONFIG_MSM_SYSSTATS=m\n".to_string(),
            ),
            (
                "onyx_perf.config".to_string(),
                "# CONFIG_CORESIGHT is not set\nCONFIG_TCP_CONG_BBR=y\n".to_string(),
            ),
        ];
        let eff = eval_config_fragments(&frags);
        assert_eq!(eff.get("SCHED_WALT").unwrap().0, CfgVal::Enabled("m".into()));
        assert_eq!(eff.get("CORESIGHT").unwrap().0, CfgVal::Disabled);
        assert_eq!(eff.get("TCP_CONG_BBR").unwrap().0, CfgVal::Enabled("y".into()));
    }

    #[test]
    fn test_parse_boardconfig_kernel_fragments() {
        let mk = r#"
TARGET_KERNEL_CONFIG := \
    gki_defconfig \
    vendor/sun_perf.config \
    vendor/onyx_perf.config \
    $(TARGET_KERNEL_CONFIG_EXTRA)
BOARD_KERNEL_CMDLINE := foo
"#;
        assert_eq!(
            parse_boardconfig_kernel_fragments(mk),
            vec!["gki_defconfig", "vendor/sun_perf.config", "vendor/onyx_perf.config"]
        );
    }

    #[test]
    fn test_count_lost_custom_lines_wipe_vs_upstreamed() {
        // Case 1: init/Kconfig wiped by --theirs
        let ours_diff = r#"+++ b/init/Kconfig
+source "kernel/sched/walt/Kconfig"
+config MSM_SYSSTATS
+	tristate "Export system/task statistics through netlink"
"#;
        let theirs_wiped = "source \"kernel/Kconfig.preempt\"\nendmenu\n";
        let (lost, tot, sample) = count_lost_custom_lines(ours_diff, theirs_wiped);
        assert_eq!(tot, 3);
        assert_eq!(lost, 3);
        assert!(sample.iter().any(|s| s.contains("walt/Kconfig")));

        // Case 2: ufs_bsg.c upstreamed fix (all our added lines exist in theirs)
        let ufs_diff = r#"+++ b/drivers/ufs/core/ufs_bsg.c
+		if (uc.argument2 & MASK_UIC_COMMAND_RESULT) {
+			ret = -EINVAL;
+			break;
"#;
        let ufs_theirs = "if (uc.argument2 & MASK_UIC_COMMAND_RESULT) {\nret = -EINVAL;\nbreak;\n}\n";
        let (lost2, tot2, _) = count_lost_custom_lines(ufs_diff, ufs_theirs);
        assert_eq!(tot2, 3);
        assert_eq!(lost2, 0);
    }

    #[test]
    fn test_is_diff_bloat() {
        // arm-smmu-v3.c wiped: HEAD=+1225/-187 vs upstream=+6/-0
        assert!(is_diff_bloat(1225, 187, 6, 0));
        // Normal merge: HEAD=+22/-8 vs upstream=+20/-7
        assert!(!is_diff_bloat(22, 8, 20, 7));
        // Small noise below threshold
        assert!(!is_diff_bloat(8, 4, 1, 0));
    }

    #[test]
    fn test_is_kbuild_file() {
        assert!(is_kbuild_file("init/Kconfig"));
        assert!(is_kbuild_file("drivers/soc/qcom/Kconfig.msm"));
        assert!(is_kbuild_file("Makefile"));
        assert!(is_kbuild_file("arch/arm64/configs/vendor/onyx_perf.config"));
        assert!(!is_kbuild_file("drivers/soc/qcom/mpam/cpu_mpam.c"));
    }
}
