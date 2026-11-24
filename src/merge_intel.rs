use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::gate;
use crate::util::*;

const MERGE3_META_FILE: &str = "KAWAL_MERGE3_META";

/// Known QCOM CLO `soc-repo` overlay paths where CLO heavily extends/replaces upstream drivers.
const CLO_SOC_PREFIXES: &[&str] = &[
    "drivers/firmware/qcom/",
    "include/linux/firmware/qcom/",
    "drivers/remoteproc/qcom_",
    "drivers/soc/qcom/ice.c",
    "drivers/soc/qcom/mdt_loader.c",
    "include/linux/soc/qcom/mdt_loader.h",
    "drivers/soc/qcom/rpmh-rsc.c",
    "drivers/phy/qualcomm/",
    "drivers/ufs/host/ufs-qcom.c",
    "drivers/thermal/qcom/tsens",
    "drivers/slimbus/qcom-ngd",
    "drivers/bus/mhi/",
    "net/qrtr/",
    "drivers/misc/fastrpc.c",
    "drivers/hwtracing/coresight/",
    "drivers/interconnect/qcom/",
    "drivers/clk/qcom/",
    "drivers/rpmsg/qcom_glink",
];

/// Source-level markers that prove a file carries CLO-only `soc-repo` code.
const CLO_CODE_MARKERS: &[&str] = &[
    "qcom_scm_pas_metadata",
    "hab_calling_convention",
    "KP 5.0 soc-repo",
    "ipc_log_context",
    ".clkr.vdd_data",
    "ufs_qcom_phy_set_src_clk_h8_enter",
    "qcom_rproc_update_recovery_status",
    "qcom_tzmem_flush_shm_buf",
    "MHI_REG_ACCESS_VALID",
    "qrtr_mhi_of_parse",
    "hwkm_v1.h",
];

/// Android GKI / KMI / Yasvara markers that MUST NEVER be silently dropped by blind `--theirs`.
const ACK_PROTECTED_MARKERS: &[&str] = &[
    "trace_android_vh_",
    "trace_android_rvh_",
    "ANDROID_KABI_RESERVE",
    "ANDROID_KABI_USE",
    "ANDROID_VENDOR_DATA",
    "EXPORT_SYMBOL_GPL(security_binder_set_context_mgr)",
    "EXPORT_SYMBOL_GPL(security_binder_transaction)",
    "EXPORT_SYMBOL_GPL(security_binder_transfer_binder)",
    "EXPORT_SYMBOL_GPL(security_binder_transfer_file)",
    "VMA_LOCK_OFFSET",
    "vma->vm_refcnt",
    "pkvm_get_loaded_hyp_vcpu",
    "yasvara_hide",
    "tcp_bbr3",
    "KBUILD_EXTMOD",
];

pub fn read_merge3_meta(ctx: &Ctx) -> Option<(String, String)> {
    let (_, p, _) = git_rc(ctx, &["rev-parse", "--git-path", MERGE3_META_FILE]);
    let p = p.trim();
    if p.is_empty() {
        return None;
    }
    let full = if Path::new(p).is_absolute() {
        std::path::PathBuf::from(p)
    } else {
        ctx.repo.join(p)
    };
    let txt = fs::read_to_string(full).ok()?;
    let mut lines = txt.lines();
    let base = lines.next()?.trim().to_string();
    let theirs = lines.next()?.trim().to_string();
    if base.is_empty() || theirs.is_empty() {
        None
    } else {
        Some((base, theirs))
    }
}

fn write_merge3_meta(ctx: &Ctx, base: &str, theirs: &str) {
    let (_, p, _) = git_rc(ctx, &["rev-parse", "--git-path", MERGE3_META_FILE]);
    let p = p.trim();
    if p.is_empty() {
        return;
    }
    let full = if Path::new(p).is_absolute() {
        std::path::PathBuf::from(p)
    } else {
        ctx.repo.join(p)
    };
    let _ = fs::write(full, format!("{base}\n{theirs}\n"));
}

pub fn clear_merge3_meta(ctx: &Ctx) {
    let (_, p, _) = git_rc(ctx, &["rev-parse", "--git-path", MERGE3_META_FILE]);
    let p = p.trim();
    if !p.is_empty() {
        let full = if Path::new(p).is_absolute() {
            std::path::PathBuf::from(p)
        } else {
            ctx.repo.join(p)
        };
        let _ = fs::remove_file(full);
    }
}

pub fn is_clo_soc_path(path: &str) -> bool {
    CLO_SOC_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Find protected ACK/KMI/Yasvara markers present in `ours` but missing from `theirs`.
pub fn detect_stripped_protected_markers(ours: &str, theirs: &str) -> Vec<&'static str> {
    ACK_PROTECTED_MARKERS
        .iter()
        .copied()
        .filter(|m| ours.contains(*m) && !theirs.contains(*m))
        .collect()
}

/// Detect CLO-only markers present in `ours` but absent in `theirs`.
pub fn detect_clo_markers(ours: &str, theirs: &str) -> Vec<&'static str> {
    CLO_CODE_MARKERS
        .iter()
        .copied()
        .filter(|m| ours.contains(*m) && !theirs.contains(*m))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriageBucket {
    AckKmiGuard,
    CloSocOwned,
    HeaderWatch,
    Hybrid,
    SafeTheirs,
}

impl TriageBucket {
    pub fn label(&self) -> &'static str {
        match self {
            TriageBucket::AckKmiGuard => "ACK-KMI-GUARD",
            TriageBucket::CloSocOwned => "CLO-SOC-OWNED",
            TriageBucket::HeaderWatch => "HEADER-WATCH ",
            TriageBucket::Hybrid => "HYBRID       ",
            TriageBucket::SafeTheirs => "SAFE-THEIRS  ",
        }
    }

    pub fn advice(&self) -> &'static str {
        match self {
            TriageBucket::AckKmiGuard => "HYBRID (NEVER blind --theirs!)",
            TriageBucket::CloSocOwned => "KEEP --ours (verify sibling .h)",
            TriageBucket::HeaderWatch => "HYBRID (check dropped +defs)",
            TriageBucket::Hybrid => "MANUAL HYBRID",
            TriageBucket::SafeTheirs => "TAKE --theirs",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            TriageBucket::AckKmiGuard => 0,
            TriageBucket::HeaderWatch => 1,
            TriageBucket::Hybrid => 2,
            TriageBucket::CloSocOwned => 3,
            TriageBucket::SafeTheirs => 4,
        }
    }
}

pub fn classify_conflict(
    path: &str,
    code: &str,
    ours: &str,
    theirs: &str,
    local_delta_lines: usize,
    up_added_hdr_syms: &[String],
) -> (TriageBucket, Vec<String>) {
    let mut notes = Vec::new();
    let stripped_ack = detect_stripped_protected_markers(ours, theirs);
    if !stripped_ack.is_empty() {
        notes.push(format!(
            "theirs strips: {}",
            stripped_ack.iter().take(4).copied().collect::<Vec<_>>().join(", ")
        ));
        return (TriageBucket::AckKmiGuard, notes);
    }

    let clo_hits = detect_clo_markers(ours, theirs);
    if is_clo_soc_path(path) || !clo_hits.is_empty() {
        if !clo_hits.is_empty() {
            notes.push(format!(
                "CLO: {}",
                clo_hits.iter().take(3).copied().collect::<Vec<_>>().join(", ")
            ));
        } else if code == "AA" {
            notes.push("add/add QCOM soc-repo file".to_string());
        } else {
            notes.push("QCOM soc-repo path".to_string());
        }
        return (TriageBucket::CloSocOwned, notes);
    }

    if path.ends_with(".h") && !up_added_hdr_syms.is_empty() {
        notes.push(format!(
            "upstream +syms: {}",
            up_added_hdr_syms.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
        ));
        return (TriageBucket::HeaderWatch, notes);
    }

    if code == "UU" && local_delta_lines <= 2 {
        notes.push("minimal local divergence".to_string());
        return (TriageBucket::SafeTheirs, notes);
    }

    (TriageBucket::Hybrid, notes)
}

/// Extract newly added `#define NAME`, `static inline ... name(`, and struct field names from a header diff.
pub fn extract_added_header_symbols(diff_text: &str) -> Vec<String> {
    let mut syms = BTreeSet::new();
    for ln in diff_text.lines() {
        let Some(rest) = ln.strip_prefix('+') else {
            continue;
        };
        if ln.starts_with("+++") {
            continue;
        }
        let code = strip_c_comments(rest);
        let trim = code.trim();
        if trim.is_empty() {
            continue;
        }
        // 1. #define NAME
        if let Some(after_hash) = trim.strip_prefix('#') {
            let d = after_hash.trim_start();
            if let Some(after_def) = d.strip_prefix("define") {
                if after_def.starts_with(|c: char| c.is_ascii_whitespace()) {
                    let nm = after_def.trim_start();
                    let b = nm.as_bytes();
                    let mut i = 0;
                    while i < b.len() && is_ident_char(b[i]) {
                        i += 1;
                    }
                    let ident = &nm[..i];
                    if ident.len() >= 5 && !ident.ends_with("_H") && !ident.starts_with("__") {
                        syms.insert(ident.to_string());
                    }
                }
            }
            continue;
        }
        // 2. static inline / extern function declaration at col 0
        if !rest.starts_with('\t') && !rest.starts_with("    ") {
            if let Some(par) = trim.find('(') {
                let before = trim[..par].trim_end();
                let b = before.as_bytes();
                let mut i = b.len();
                while i > 0 && is_ident_char(b[i - 1]) {
                    i -= 1;
                }
                let fname = &before[i..];
                let left = before[..i].trim();
                if !left.is_empty()
                    && fname.len() >= 5
                    && fname.as_bytes()[0].is_ascii_lowercase()
                    && !C_KEYWORDS.contains(&fname)
                    && !NOT_A_CALL.contains(&fname)
                {
                    syms.insert(fname.to_string());
                }
            }
            continue;
        }
        // 3. Struct member declaration (`\tbool no_wakeup_source;`)
        if (rest.starts_with('\t') || rest.starts_with("    ")) && !rest.contains('=') {
            let fake_minus = format!("-{rest}");
            if let Some(field) = gate::parse_removed_header_decl(&fake_minus) {
                if field.len() >= 5 && !GENERIC_MEMBERS.contains(&field.as_str()) {
                    syms.insert(field);
                }
            }
        }
    }
    syms.into_iter().collect()
}

// ====================================================== 1. `kawal merge3 <base> <theirs>`

pub fn cmd_merge3(ctx: &Ctx, base: &str, theirs: &str, dry_run: bool) -> i32 {
    if git_rc(ctx, &["rev-parse", "--verify", "--quiet", base]).0 != 0 {
        eprintln!("!! base ref not found: {base}");
        return 2;
    }
    if git_rc(ctx, &["rev-parse", "--verify", "--quiet", theirs]).0 != 0 {
        eprintln!("!! target ref not found: {theirs}");
        return 2;
    }

    if dry_run {
        println!("=== kawal merge3 --dry-run (merge-base={base}, HEAD <- {theirs}) ===");
        let (rc, out, err) = git_rc(
            ctx,
            &[
                "merge-tree",
                "--write-tree",
                "--name-only",
                &format!("--merge-base={base}"),
                "HEAD",
                theirs,
            ],
        );
        if rc == 0 {
            println!("  CLEAN MERGE! 0 conflicts between HEAD and {theirs} (base={base})");
            return 0;
        }
        let mut conflicts = Vec::new();
        for (idx, ln) in out.lines().enumerate() {
            if idx == 0 {
                continue; // tree hash
            }
            let t = ln.trim();
            if t.is_empty() {
                break;
            }
            conflicts.push(t.to_string());
        }
        if conflicts.is_empty() {
            eprintln!("!! git merge-tree failed (rc={rc}): {}", err.trim());
            return rc;
        }
        let n_built = conflicts.iter().filter(|p| is_built_file(ctx, p)).count();
        let n_clo = conflicts.iter().filter(|p| is_clo_soc_path(p)).count();
        println!(
            "  CONFLICTS: {} total ({} [BUILT], {} [unbuilt], {} QCOM/CLO soc-repo paths)",
            conflicts.len(),
            n_built,
            conflicts.len() - n_built,
            n_clo
        );
        // Group top directories
        let mut by_dir: BTreeMap<String, usize> = BTreeMap::new();
        for p in &conflicts {
            let mut parts = p.split('/');
            let key = match (parts.next(), parts.next()) {
                (Some(a), Some(b)) => format!("{a}/{b}"),
                (Some(a), None) => a.to_string(),
                _ => p.clone(),
            };
            *by_dir.entry(key).or_insert(0) += 1;
        }
        let mut dir_vec: Vec<(String, usize)> = by_dir.into_iter().collect();
        dir_vec.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        println!("  top conflict areas:");
        for (d, n) in dir_vec.iter().take(15) {
            println!("    {n:4}  {d}");
        }
        println!("\n  [BUILT] conflicted files:");
        for p in conflicts.iter().filter(|p| is_built_file(ctx, p)) {
            let tag = if is_clo_soc_path(p) { "[CLO-SOC]" } else { "[CORE   ]" };
            println!("    {tag} {p}");
        }
        return 1;
    }

    // Live 3-way merge requires a clean working tree
    let dirty = git(ctx, &["status", "--porcelain"]);
    if !dirty.trim().is_empty() {
        eprintln!("!! working tree is not clean — commit or stash before `kawal merge3`");
        return 2;
    }

    let exec_path = git(ctx, &["--exec-path"]).trim().to_string();
    let merge_rec = Path::new(&exec_path).join("git-merge-recursive");
    if !merge_rec.exists() {
        eprintln!("!! git-merge-recursive not found at {}", merge_rec.display());
        return 2;
    }

    println!("=== kawal merge3: explicit 3-way merge (base={base}, HEAD <- {theirs}) ===");
    let (rc, _out, err) = run_cmd(
        merge_rec.to_string_lossy().as_ref(),
        &[base, "--", "HEAD", theirs],
        &ctx.repo,
        None,
    );
    write_merge3_meta(ctx, base, theirs);
    if ctx.is_default_kernel {
        let left = unmerged_with_status(ctx);
        if left.iter().any(|(_, p)| p.starts_with(BINDINGS)) {
            gate::fix_bindings(ctx);
        }
    }
    if rc == 0 {
        println!("  CLEAN MERGE (0 conflicts)! Review staged changes and `git commit -S`.");
        clear_merge3_meta(ctx);
        return 0;
    }
    if !err.trim().is_empty() {
        let preview: Vec<&str> = err.lines().take(6).collect();
        for ln in preview {
            println!("  {ln}");
        }
    }
    cmd_triage(ctx, Some(base), Some(theirs), false)
}

// ====================================================== 2. `kawal triage`

pub fn cmd_triage(
    ctx: &Ctx,
    base_opt: Option<&str>,
    theirs_opt: Option<&str>,
    apply_safe: bool,
) -> i32 {
    let pairs = unmerged_with_status(ctx);
    if pairs.is_empty() {
        println!("RESOLVED: no unmerged paths left.");
        return 0;
    }

    let meta = read_merge3_meta(ctx);
    let _base_ref = base_opt
        .map(String::from)
        .or_else(|| meta.as_ref().map(|m| m.0.clone()));
    let _theirs_ref = theirs_opt
        .map(String::from)
        .or_else(|| meta.as_ref().map(|m| m.1.clone()));

    // Find all auto-merged `.h` files currently staged in the index (for co-changed header warnings!)
    let staged_headers: HashMap<String, Vec<String>> = {
        let mut m: HashMap<String, Vec<String>> = HashMap::new();
        let unmerged_set: HashSet<&str> = pairs.iter().map(|(_, p)| p.as_str()).collect();
        let staged = git(ctx, &["diff", "--cached", "--name-only"]);
        for ln in staged.lines() {
            let f = ln.trim();
            if f.ends_with(".h") && !unmerged_set.contains(f) {
                let dir = Path::new(f)
                    .parent()
                    .map(|d| d.to_string_lossy().into_owned())
                    .unwrap_or_default();
                m.entry(dir).or_default().push(f.to_string());
            }
        }
        m
    };

    struct TriageRow {
        built: bool,
        code: String,
        bucket: TriageBucket,
        hunks: usize,
        path: String,
        notes: Vec<String>,
        co_headers: Vec<String>,
    }

    let mut rows: Vec<TriageRow> = par_map(&pairs, ctx.threads, |(code, path)| {
        let built = is_built_file(ctx, path);
        let s1 = format!(":1:{path}");
        let s2 = format!(":2:{path}");
        let s3 = format!(":3:{path}");
        let ours = git(ctx, &["show", &s2]);
        let theirs = git(ctx, &["show", &s3]);

        let local_delta = if code == "UU" {
            let d = git(ctx, &["diff", "--unified=0", &s1, &s2]);
            d.lines()
                .filter(|l| (l.starts_with('+') && !l.starts_with("+++")) || (l.starts_with('-') && !l.starts_with("---")))
                .count()
        } else {
            999
        };

        let up_hdr_syms = if path.ends_with(".h") && code == "UU" {
            let d = git(ctx, &["diff", "--unified=0", &s1, &s3]);
            extract_added_header_symbols(&d)
        } else {
            Vec::new()
        };

        let hunks = fs::read_to_string(ctx.repo.join(path))
            .map(|t| {
                let lns: Vec<&str> = t.lines().collect();
                parse_conflict_hunks(&lns).len()
            })
            .unwrap_or(0);

        let (bucket, notes) = classify_conflict(path, code, &ours, &theirs, local_delta, &up_hdr_syms);
        let co_headers = if bucket == TriageBucket::CloSocOwned && path.ends_with(".c") {
            let dir = Path::new(path)
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default();
            staged_headers.get(&dir).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };

        TriageRow {
            built,
            code: code.clone(),
            bucket,
            hunks,
            path: path.clone(),
            notes,
            co_headers,
        }
    });

    rows.sort_by(|a, b| {
        a.bucket
            .rank()
            .cmp(&b.bucket.rank())
            .then(b.built.cmp(&a.built))
            .then(a.path.cmp(&b.path))
    });

    let n_built = rows.iter().filter(|r| r.built).count();
    let n_ack = rows.iter().filter(|r| r.bucket == TriageBucket::AckKmiGuard).count();
    let n_hdr = rows.iter().filter(|r| r.bucket == TriageBucket::HeaderWatch).count();
    let n_hyb = rows.iter().filter(|r| r.bucket == TriageBucket::Hybrid).count();
    let n_clo = rows.iter().filter(|r| r.bucket == TriageBucket::CloSocOwned).count();
    let n_th = rows.iter().filter(|r| r.bucket == TriageBucket::SafeTheirs).count();

    println!(
        "=== kawal triage ({} unmerged: {} [BUILT], {} [unbuilt]) ===",
        rows.len(),
        n_built,
        rows.len() - n_built
    );
    println!(
        "  buckets: {n_ack} ACK-KMI-GUARD | {n_hdr} HEADER-WATCH | {n_hyb} HYBRID | {n_clo} CLO-SOC-OWNED | {n_th} SAFE-THEIRS"
    );

    let mut co_hdr_warnings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in &rows {
        let btag = if r.built { "[BUILT]" } else { "[unbuilt]" };
        let ctag = if r.code == "UU" {
            String::new()
        } else {
            format!(" ({})", r.code)
        };
        let note_str = if r.notes.is_empty() {
            r.bucket.advice().to_string()
        } else {
            format!("{} | {}", r.bucket.advice(), r.notes.join("; "))
        };
        println!(
            "  {} {btag:<9} h={:<2} {:<46}{ctag} -> {note_str}",
            r.bucket.label(),
            r.hunks,
            r.path
        );
        for ch in &r.co_headers {
            co_hdr_warnings.entry(ch.clone()).or_default().insert(r.path.clone());
        }
    }

    if !co_hdr_warnings.is_empty() {
        println!("\n  !! CO-HEADER DRIFT (auto-merged .h in same dir as CLO-SOC-OWNED .c conflicts):");
        for (hdr, cfiles) in &co_hdr_warnings {
            let sample: Vec<&String> = cfiles.iter().take(3).collect();
            println!(
                "     {hdr}  (sibling of {}) -> verify struct/lock parity if taking --ours!",
                sample.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    let safe_theirs: Vec<&str> = rows
        .iter()
        .filter(|r| r.bucket == TriageBucket::SafeTheirs)
        .map(|r| r.path.as_str())
        .collect();
    let clean_clo: Vec<&str> = rows
        .iter()
        .filter(|r| r.bucket == TriageBucket::CloSocOwned && r.co_headers.is_empty())
        .map(|r| r.path.as_str())
        .collect();
    let manual_priority: Vec<&str> = rows
        .iter()
        .filter(|r| {
            matches!(
                r.bucket,
                TriageBucket::AckKmiGuard | TriageBucket::HeaderWatch | TriageBucket::Hybrid
            )
        })
        .map(|r| r.path.as_str())
        .collect();

    if apply_safe && !safe_theirs.is_empty() {
        let mut applied = 0usize;
        for p in &safe_theirs {
            if git_rc(ctx, &["checkout", "--theirs", "--", p]).0 == 0
                && git_rc(ctx, &["add", "--", p]).0 == 0
            {
                applied += 1;
            }
        }
        println!("\n  [apply-safe] resolved {applied}/{} SAFE-THEIRS file(s) via --theirs", safe_theirs.len());
    } else if !safe_theirs.is_empty() || !clean_clo.is_empty() || !manual_priority.is_empty() {
        println!("\n  SUGGESTED WORKFLOW:");
        if !safe_theirs.is_empty() {
            println!("    1. Auto-resolve {} SAFE-THEIRS file(s): kawal triage --apply-safe", safe_theirs.len());
        }
        if !clean_clo.is_empty() {
            println!(
                "    2. Review {} zero-drift CLO-SOC-OWNED file(s) (likely --ours): {}",
                clean_clo.len(),
                clean_clo.iter().take(4).copied().collect::<Vec<_>>().join(", ")
            );
        }
        if !manual_priority.is_empty() {
            println!(
                "    3. Inspect {} priority ACK/HEADER/HYBRID file(s): kawal explain {}",
                manual_priority.len(),
                manual_priority.iter().take(4).copied().collect::<Vec<_>>().join(" ")
            );
        }
    }
    1
}

// ====================================================== 3. `kawal header-drop <from> <to>`

pub fn cmd_header_drop(ctx: &Ctx, up_base: &str, up_to: &str, all_files: bool) -> i32 {
    let (rc, _) = run_header_drop(ctx, up_base, up_to, all_files);
    rc
}

/// Detect upstream header additions (in `up_base..up_to`) that are ABSENT in `HEAD` (e.g. lost via
/// `--ours` resolution on `include/linux/mm.h`) while still referenced by `.c` files in `HEAD`!
pub fn run_header_drop(ctx: &Ctx, up_base: &str, up_to: &str, all_files: bool) -> (i32, String) {
    println!("=== header-drop: upstream header additions missing in HEAD ({up_base}..{up_to}) ===");
    let diff = git(
        ctx,
        &["diff", "-U0", up_base, up_to, "--", "include/", "arch/arm64/include/"],
    );

    let mut syms_by_hdr: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur_hdr: Option<String> = None;
    let mut cur_buf = String::new();

    let flush = |hdr: &mut Option<String>, buf: &mut String, out: &mut BTreeMap<String, Vec<String>>| {
        if let Some(h) = hdr.take() {
            let syms = extract_added_header_symbols(buf);
            if !syms.is_empty() {
                out.insert(h, syms);
            }
        }
        buf.clear();
    };

    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            flush(&mut cur_hdr, &mut cur_buf, &mut syms_by_hdr);
            cur_hdr = Some(p.trim().to_string());
        } else if cur_hdr.is_some() {
            cur_buf.push_str(ln);
            cur_buf.push('\n');
        }
    }
    flush(&mut cur_hdr, &mut cur_buf, &mut syms_by_hdr);

    // Find symbols absent from HEAD's copy of the same header
    let mut dropped: BTreeMap<String, String> = BTreeMap::new(); // sym -> header
    for (hdr, syms) in &syms_by_hdr {
        let Ok(head_txt) = fs::read_to_string(ctx.repo.join(hdr)) else {
            continue;
        };
        for sym in syms {
            if !word_in_text(&head_txt, sym) {
                dropped.insert(sym.clone(), hdr.clone());
            }
        }
    }

    if dropped.is_empty() {
        println!(
            "  clean: all upstream header additions ({} headers checked) are present in HEAD",
            syms_by_hdr.len()
        );
        return (0, format!("0 dropped ({} headers checked)", syms_by_hdr.len()));
    }

    // Filter out symbols declared elsewhere in HEAD (e.g. moved header), then grep for callers!
    let drop_names: Vec<String> = dropped.keys().cloned().collect();
    let mut used_hits: Vec<(String, String, Vec<String>)> = Vec::new();
    for chunk in drop_names.chunks(80) {
        let alt = chunk.join("|");
        let pat = format!(r"\b({alt})\b");
        let (_, out) = rg(&ctx.repo, &["-n", "-g", "*.c", &pat]);
        let mut refs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for ln in out.lines() {
            let p: Vec<&str> = ln.splitn(3, ':').collect();
            if p.len() == 3 && is_c_source(p[0]) && (all_files || is_built_file(ctx, p[0])) {
                let code = strip_c_comments(p[2]);
                for sym in chunk {
                    if word_in_text(code, sym) {
                        refs.entry(sym.clone())
                            .or_default()
                            .push(format!("{}:{}", p[0], p[1]));
                    }
                }
            }
        }
        // Only flag if symbol is NOT defined in any header under include/ or arch/arm64/include/
        for (sym, locs) in refs {
            let def_pat = format!(
                r"(^\s*#\s*define\s+{sym}\b|\b{sym}\s*\(|[\t ]{sym}\s*(;|\[|:))"
            );
            let (_, def_out) = rg(&ctx.repo, &["-l", "-g", "*.h", &def_pat, "include", "arch/arm64/include"]);
            if def_out.trim().is_empty() {
                let hdr = dropped.get(&sym).cloned().unwrap_or_else(|| "?".to_string());
                used_hits.push((sym, hdr, locs));
            }
        }
    }

    if used_hits.is_empty() {
        println!(
            "  clean: 0 broken header drops ({} upstream header symbols omitted, none referenced by built .c)",
            dropped.len()
        );
        return (0, format!("0 broken ({} omitted safely)", dropped.len()));
    }

    for (sym, hdr, locs) in &used_hits {
        let sample: Vec<&String> = locs.iter().take(4).collect();
        let more = if locs.len() > 4 {
            format!(" (+{} more)", locs.len() - 4)
        } else {
            String::new()
        };
        println!(
            "  HEADER-DROP `{sym}` missing from {hdr} -> referenced by {}{more}",
            sample.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
    }
    (1, format!("{} dropped header symbol(s) still referenced!", used_hits.len()))
}

// ====================================================== 4. ACK vs Upstream Semantic Clash Guard

/// Pure text check for Per-VMA lock `vm_refcnt` vs `__mm_reset_vma_seqcounts` deadlock clash.
pub fn has_per_vma_lock_clash(mm_h: &str, mmap_lock_h: &str, mmap_lock_c: &str) -> bool {
    let ack_refcnt_vma = mm_h.contains("VMA_LOCK_OFFSET") && mm_h.contains("vma->vm_refcnt");
    let has_odd_even_check = mm_h.contains("vma_seqcount_is_write_locked");
    let resets_seqcounts = mmap_lock_h.contains("__mm_reset_vma_seqcounts")
        || mmap_lock_c.contains("__mm_reset_vma_seqcounts");
    ack_refcnt_vma && !has_odd_even_check && resets_seqcounts
}

/// Extract parameter count for a C function prototype/definition by name.
pub fn extract_fn_arity(text: &str, fn_name: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let needle = format!("{fn_name}(");
    for (idx, raw) in lines.iter().enumerate() {
        let code = strip_c_comments(raw);
        let Some(pos) = code.find(&needle) else {
            continue;
        };
        if pos > 0 && is_ident_char(code.as_bytes()[pos - 1]) {
            continue;
        }
        // Must look like a declaration/definition (type token to the left, not a call/return/if)
        let left = code[..pos].trim();
        if left.is_empty()
            || left.ends_with('=')
            || left.ends_with("return")
            || left.contains("->")
            || left.contains('.')
            || left.starts_with("EXPORT_")
            || left.starts_with('#')
        {
            continue;
        }
        // Gather up to 8 lines until matching ')'
        let mut combined = code[pos + needle.len()..].to_string();
        for next in lines.iter().skip(idx + 1).take(8) {
            if combined.contains(')') {
                break;
            }
            combined.push(' ');
            combined.push_str(strip_c_comments(next));
        }
        let Some(close) = combined.find(')') else {
            continue;
        };
        let params = combined[..close].trim();
        // Verify trailing ';' or '{' (declaration or definition, not a function call inside an expr)
        let tail = combined[close + 1..].trim();
        let next_line = lines.get(idx + 1).map(|s| s.trim()).unwrap_or("");
        let is_decl_or_def = tail.starts_with(';')
            || tail.starts_with('{')
            || tail.is_empty()
            || next_line.starts_with('{');
        if !is_decl_or_def {
            continue;
        }
        if params.is_empty() || params == "void" {
            return Some(0);
        }
        // Count top-level commas
        let mut depth = 0i32;
        let mut commas = 0usize;
        for ch in params.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => commas += 1,
                _ => {}
            }
        }
        return Some(commas + 1);
    }
    None
}

pub fn run_semantic_clashes(ctx: &Ctx) -> (i32, String) {
    println!("=== ack-clash: ACK vs upstream semantic & KMI invariants ===");
    let mut hits: Vec<String> = Vec::new();

    // 1. Per-VMA lock vm_refcnt vs __mm_reset_vma_seqcounts deadlock guard
    let mm_h = fs::read_to_string(ctx.repo.join("include/linux/mm.h")).unwrap_or_default();
    let mmap_lock_h = fs::read_to_string(ctx.repo.join("include/linux/mmap_lock.h")).unwrap_or_default();
    let mmap_lock_c = fs::read_to_string(ctx.repo.join("mm/mmap_lock.c")).unwrap_or_default();
    if has_per_vma_lock_clash(&mm_h, &mmap_lock_h, &mmap_lock_c) {
        hits.push(
            "CRITICAL [VMA-LOCK-CLASH]: include/linux/mm.h uses ACK refcount Per-VMA lock (VMA_LOCK_OFFSET), \
             but mmap_lock.{h,c} calls __mm_reset_vma_seqcounts() (resets vm_lock_seq=0 -> deadlocks on wrap!)"
                .to_string(),
        );
    }

    // 2. Protected rust_binder LSM exports in security/security.c
    if ctx.repo.join("drivers/android/binder").is_dir() {
        let sec_c = fs::read_to_string(ctx.repo.join("security/security.c")).unwrap_or_default();
        for exp in [
            "EXPORT_SYMBOL_GPL(security_binder_set_context_mgr)",
            "EXPORT_SYMBOL_GPL(security_binder_transaction)",
            "EXPORT_SYMBOL_GPL(security_binder_transfer_binder)",
            "EXPORT_SYMBOL_GPL(security_binder_transfer_file)",
        ] {
            if !sec_c.is_empty() && !sec_c.contains(exp) {
                hits.push(format!(
                    "CRITICAL [RUST-BINDER-EXPORT]: security/security.c is missing `{exp}` (needed by rust_binder.ko!)"
                ));
            }
        }
    }

    // 3. Cross-check arm-gic-v3.h vs irq-gic-v3-its.c `struct its_baser` duplication
    let gic_h = fs::read_to_string(ctx.repo.join("include/linux/irqchip/arm-gic-v3.h")).unwrap_or_default();
    let its_c = fs::read_to_string(ctx.repo.join("drivers/irqchip/irq-gic-v3-its.c")).unwrap_or_default();
    if gic_h.contains("struct its_baser {") && its_c.contains("struct its_baser {") {
        hits.push(
            "CRITICAL [STRUCT-REDEF]: `struct its_baser {` is defined in BOTH include/linux/irqchip/arm-gic-v3.h AND drivers/irqchip/irq-gic-v3-its.c"
                .to_string(),
        );
    }

    // 4. ACK KMI header-vs-C arity parity guards (catches blind --theirs on KMI-frozen functions)
    const KMI_ARITY_CHECKS: &[(&str, &str, &str)] = &[
        ("include/linux/fs.h", "fs/backing-file.c", "alloc_empty_backing_file"),
        ("include/linux/security.h", "security/security.c", "security_perf_event_open"),
        ("include/net/bluetooth/l2cap.h", "net/bluetooth/l2cap_core.c", "l2cap_chan_set_defaults"),
    ];
    for &(hdr_rel, c_rel, func) in KMI_ARITY_CHECKS {
        let h_txt = fs::read_to_string(ctx.repo.join(hdr_rel)).unwrap_or_default();
        let c_txt = fs::read_to_string(ctx.repo.join(c_rel)).unwrap_or_default();
        if let (Some(ha), Some(ca)) = (extract_fn_arity(&h_txt, func), extract_fn_arity(&c_txt, func)) {
            if ha != ca {
                hits.push(format!(
                    "CRITICAL [KMI-ARITY-DRIFT]: `{func}()` has {ha} param(s) in {hdr_rel} vs {ca} param(s) in {c_rel}"
                ));
            }
        }
    }

    if hits.is_empty() {
        println!("  clean: 0 ACK/KMI semantic clashes (Per-VMA lock, rust_binder exports, GIC ITS struct, KMI arity OK)");
        (0, "0 semantic clashes".to_string())
    } else {
        for h in &hits {
            println!("  !! {h}");
        }
        (1, format!("{} critical ACK/KMI clash(es)!", hits.len()))
    }
}

// ====================================================== 5. `kawal backport-check <repo> <shas...>`

pub fn cmd_backport_check(
    ctx: &Ctx,
    upstream_repo: &str,
    shas: &[String],
    apply_clean: bool,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    if shas.is_empty() {
        eprintln!("usage: kawal backport-check <upstream.git> [--apply-clean] <sha1> [sha2 ...]");
        return 2;
    }

    // Expand `@file` entries so users can pass a file of SHAs
    let mut expanded_shas: Vec<String> = Vec::new();
    for s in shas {
        if let Some(p) = s.strip_prefix('@') {
            if let Ok(txt) = fs::read_to_string(p) {
                for ln in txt.lines() {
                    let tok = ln.split('#').next().unwrap_or("").trim();
                    if !tok.is_empty() {
                        expanded_shas.push(tok.split_whitespace().next().unwrap_or("").to_string());
                    }
                }
            }
        } else {
            expanded_shas.push(s.clone());
        }
    }

    // Build subject index of recent local history once
    let local_log = git(ctx, &["log", "--no-merges", "-n", "15000", "--format=%s", "HEAD"]);
    let local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();

    struct BpRes {
        sha: String,
        status: &'static str,
        risk: &'static str,
        subj: String,
        files: Vec<String>,
        patch: Vec<u8>,
    }

    let results: Vec<BpRes> = par_map(&expanded_shas, ctx.threads, |sha| {
        let subj = git_in(up_path, &["show", "-s", "--format=%s", sha])
            .trim()
            .to_string();
        let files: Vec<String> = git_in(up_path, &["diff-tree", "--no-commit-id", "--name-only", "-r", sha])
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let (rc_p, patch_str, _) = run_cmd("git", &["format-patch", "-1", "--stdout", sha], up_path, None);
        let patch = patch_str.into_bytes();

        let status = if subj.is_empty() || rc_p != 0 {
            "NOT-FOUND"
        } else if local_subjs.contains(&norm_subj(&subj)) {
            "IN-LOG"
        } else if git_stdin(ctx, &["apply", "--check", "--reverse"], &patch).0 == 0 {
            "ALREADY"
        } else if git_stdin(ctx, &["apply", "--check"], &patch).0 == 0 {
            "CLEAN"
        } else if git_stdin(ctx, &["apply", "--check", "-C1"], &patch).0 == 0 {
            "CLEAN-C1"
        } else {
            "ADAPT"
        };

        let mut has_ack = false;
        let mut has_clo = false;
        for f in &files {
            if is_clo_soc_path(f) {
                has_clo = true;
            }
            if let Ok(txt) = fs::read_to_string(ctx.repo.join(f)) {
                if ACK_PROTECTED_MARKERS.iter().any(|m| txt.contains(m)) {
                    has_ack = true;
                }
            }
        }
        let risk = if has_clo {
            "[CLO]"
        } else if has_ack {
            "[ACK]"
        } else {
            "     "
        };

        BpRes {
            sha: sha.clone(),
            status,
            risk,
            subj,
            files,
            patch,
        }
    });

    let mut n_clean = 0usize;
    let mut n_already = 0usize;
    let mut n_adapt = 0usize;
    let mut n_applied = 0usize;

    println!(
        "=== kawal backport-check ({} commits from {}) ===",
        results.len(),
        upstream_repo
    );
    for r in &results {
        match r.status {
            "IN-LOG" | "ALREADY" => n_already += 1,
            "CLEAN" | "CLEAN-C1" => n_clean += 1,
            _ => n_adapt += 1,
        }
        let built_cnt = r.files.iter().filter(|f| is_built_file(ctx, f)).count();
        let btag = if built_cnt > 0 { "[BUILT]" } else { "[unbuilt]" };
        let fpreview = r
            .files
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {:<9} {btag:<9} {} {} | {:<32} | {}",
            r.status,
            r.risk,
            truncate_str(&r.sha, 10),
            truncate_str(&fpreview, 32),
            truncate_str(&r.subj, 54)
        );
        if apply_clean && matches!(r.status, "CLEAN" | "CLEAN-C1") {
            let args: &[&str] = if r.status == "CLEAN" {
                &["apply"]
            } else {
                &["apply", "-C1"]
            };
            if git_stdin(ctx, args, &r.patch).0 == 0 {
                n_applied += 1;
            } else {
                println!("    !! sequential apply conflicted (overlap with earlier clean patch): {}", r.sha);
            }
        }
    }
    println!(
        "Summary: {} already/in-log | {} clean | {} need manual adapt{}",
        n_already,
        n_clean,
        n_adapt,
        if apply_clean {
            format!(" | {n_applied} applied to working tree")
        } else {
            String::new()
        }
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_added_header_symbols() {
        let diff = r#"+++ b/include/linux/mm.h
+#define MAX_FOLIO_ORDER		PUD_ORDER
+#define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
+static inline unsigned long get_mm_rss_sum(struct mm_struct *mm)
+	bool no_wakeup_source;
"#;
        let syms = extract_added_header_symbols(diff);
        assert!(syms.contains(&"MAX_FOLIO_ORDER".to_string()));
        assert!(syms.contains(&"MAX_FOLIO_NR_PAGES".to_string()));
        assert!(syms.contains(&"get_mm_rss_sum".to_string()));
        assert!(syms.contains(&"no_wakeup_source".to_string()));
    }

    #[test]
    fn test_classify_conflict_ack_kmi_vs_clo() {
        let (b1, notes1) = classify_conflict(
            "security/security.c",
            "UU",
            "EXPORT_SYMBOL_GPL(security_binder_transaction);\n",
            "int foo(void) { return 0; }\n",
            20,
            &[],
        );
        assert_eq!(b1, TriageBucket::AckKmiGuard);
        assert!(notes1[0].contains("security_binder_transaction"));

        let (b2, _) = classify_conflict(
            "drivers/firmware/qcom/qcom_scm.c",
            "UU",
            "struct qcom_scm_pas_metadata ctx;\n",
            "struct qcom_scm_pas_context ctx;\n",
            100,
            &[],
        );
        assert_eq!(b2, TriageBucket::CloSocOwned);

        let (b3, _) = classify_conflict(
            "include/linux/mm.h",
            "UU",
            "int a;\n",
            "int b;\n",
            10,
            &["MAX_FOLIO_ORDER".to_string()],
        );
        assert_eq!(b3, TriageBucket::HeaderWatch);
    }

    #[test]
    fn test_per_vma_lock_clash_detector() {
        let ack_mm_h = "if (refcnt & VMA_LOCK_OFFSET) refcount_dec(&vma->vm_refcnt);";
        let up_mm_h = "static inline bool vma_seqcount_is_write_locked(u32 a, u32 b) {}";
        let bad_mmap_lock_h = "void __mm_reset_vma_seqcounts(struct mm_struct *mm);";
        let ok_mmap_lock_h = "void mmap_write_unlock(struct mm_struct *mm);";

        assert!(has_per_vma_lock_clash(ack_mm_h, bad_mmap_lock_h, ""));
        assert!(!has_per_vma_lock_clash(ack_mm_h, ok_mmap_lock_h, ""));
        assert!(!has_per_vma_lock_clash(up_mm_h, bad_mmap_lock_h, ""));
    }

    #[test]
    fn test_fn_arity_parity() {
        let hdr = "extern struct file *alloc_empty_backing_file(int flags, const struct cred *cred);\n";
        let ok_c = "struct file *alloc_empty_backing_file(int flags, const struct cred *cred)\n{\n}\n";
        let bad_c = "struct file *alloc_empty_backing_file(int flags, const struct cred *cred, struct dentry *d)\n{\n}\n";
        assert_eq!(extract_fn_arity(hdr, "alloc_empty_backing_file"), Some(2));
        assert_eq!(extract_fn_arity(ok_c, "alloc_empty_backing_file"), Some(2));
        assert_eq!(extract_fn_arity(bad_c, "alloc_empty_backing_file"), Some(3));
    }
}
