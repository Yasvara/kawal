//! High-level ROM operations for Yasvara:
//!   - `ktool sync merge` : Promisor-safe (`GIT_NO_LAZY_FETCH=1` + `--filter=blob:none --negotiation-tip`),
//!                          in-memory `merge-tree` dry-run + GPG-signed CLO merge orchestrator.
//!   - `ktool prebuilts`  : Local toolchain/SDK/module_sdk inventory + live upstream radar against
//!                          AOSP (android.googlesource.com Gitiles) & latest CLO manifest.
//!   - `ktool hygiene`    : 16-core workspace gate (SPEC tags, wip/snapshot commits, GPG signatures,
//!                          detached-HEAD dirty repos, and abandoned `tmp_pack_*` cleanup).
//!   - `ktool push`       : Pre-push dashboard & safe batch pusher across Yasvara/device/kernel repos.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::clo;
use crate::sync::{
    self, build_sync_plan, load_pending_projects, load_yasvara_manifest, ls_remote_tags, nat_key,
    run_with_retry, PlanEntry, PlanKind, AOSP_MANIFEST_REPO, CLO_BASE,
};
use crate::util::*;

// ====================================================== 1. `ktool sync merge`

#[derive(Debug, Clone, PartialEq, Eq)]
enum MergeOutcome {
    AlreadyMerged,
    FastForwarded(usize),
    CleanMerged { incoming: usize, new_head: String },
    DryCleanFf(usize),
    DryCleanMerge(usize),
    Conflict { incoming: usize, files: Vec<String> },
    Unrelated { local_cnt: usize, note: String },
    Skipped(String),
    Failed(String),
}

fn infer_tag_from_xml(xml: &Path) -> String {
    xml.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("CLO-update")
        .to_string()
}

/// Fetch `new_rev` from CLO safely without triggering partial-clone promisor bombs:
/// 1. Check existence locally with `GIT_NO_LAZY_FETCH=1 cat-file -e`.
/// 2. If missing, fetch with `--no-tags --filter=blob:none --negotiation-tip=<old_rev>` (if `old_rev`
///    exists locally), else `--depth=80`.
fn fetch_clo_rev_safe(dir: &Path, url: &str, old_rev: &str, new_rev: &str) -> Result<(), String> {
    let target_spec = format!("{new_rev}^{{commit}}");
    if git_nolazy(dir, &["cat-file", "-e", &target_spec]).0 == 0 {
        return Ok(());
    }
    let old_exists = !old_rev.is_empty()
        && git_nolazy(dir, &["cat-file", "-e", &format!("{old_rev}^{{commit}}")]).0 == 0;
    let tip_arg = format!("--negotiation-tip={old_rev}");

    let (rc, _, err) = run_with_retry(4, || {
        if old_exists {
            run_cmd_env(
                "git",
                &["fetch", "-q", "--no-tags", "--filter=blob:none", &tip_arg, url, new_rev],
                dir,
                None,
                &[("GIT_NO_LAZY_FETCH", "1")],
            )
        } else {
            run_cmd_env(
                "git",
                &["fetch", "-q", "--no-tags", "--filter=blob:none", "--depth=80", url, new_rev],
                dir,
                None,
                &[("GIT_NO_LAZY_FETCH", "1")],
            )
        }
    });
    if rc == 0 {
        return Ok(());
    }
    // Fallback without --filter in case remote/repo rejects partial filter
    let (rc2, _, err2) = run_with_retry(3, || {
        run_cmd_env(
            "git",
            &["fetch", "-q", "--no-tags", "--depth=80", url, new_rev],
            dir,
            None,
            &[("GIT_NO_LAZY_FETCH", "1")],
        )
    });
    if rc2 == 0 {
        Ok(())
    } else {
        Err(err2
            .lines()
            .last()
            .or_else(|| err.lines().last())
            .unwrap_or("fetch failed")
            .trim()
            .to_string())
    }
}

fn parse_conflict_lines(merge_tree_out: &str) -> Vec<String> {
    let mut files = Vec::new();
    for line in merge_tree_out.lines() {
        if line.contains("CONFLICT") {
            files.push(line.trim().to_string());
        }
    }
    files
}

fn process_manual_repo(
    src_root: &Path,
    e: &PlanEntry,
    tag: &str,
    dry_run: bool,
) -> (String, String, MergeOutcome) {
    let dir = src_root.join(&e.path);
    if !dir.join(".git").exists() {
        return (e.path.clone(), e.new_rev.clone(), MergeOutcome::Skipped("missing .git".into()));
    }
    if !git_nolazy(&dir, &["status", "--porcelain"]).1.trim().is_empty() {
        return (e.path.clone(), e.new_rev.clone(), MergeOutcome::Skipped("DIRTY working tree".into()));
    }

    let url = format!("{CLO_BASE}/{}.git", e.name);
    if let Err(err) = fetch_clo_rev_safe(&dir, &url, &e.old_rev, &e.new_rev) {
        return (e.path.clone(), e.new_rev.clone(), MergeOutcome::Failed(format!("fetch: {err}")));
    }

    if git_nolazy(&dir, &["merge-base", "--is-ancestor", &e.new_rev, "HEAD"]).0 == 0 {
        return (e.path.clone(), e.new_rev.clone(), MergeOutcome::AlreadyMerged);
    }

    // Fast-forwardable (0 local divergence)?
    if git_nolazy(&dir, &["merge-base", "--is-ancestor", "HEAD", &e.new_rev]).0 == 0 {
        let cnt = git_nolazy(&dir, &["rev-list", "--count", &format!("HEAD..{}", e.new_rev)])
            .1
            .trim()
            .parse::<usize>()
            .unwrap_or(0);
        if dry_run {
            return (e.path.clone(), e.new_rev.clone(), MergeOutcome::DryCleanFf(cnt));
        }
        let (rc, _, err) = run_cmd("git", &["merge", "--ff-only", &e.new_rev], &dir, None);
        return if rc == 0 {
            (e.path.clone(), e.new_rev.clone(), MergeOutcome::FastForwarded(cnt))
        } else {
            (
                e.path.clone(),
                e.new_rev.clone(),
                MergeOutcome::Failed(err.lines().last().unwrap_or("ff-only failed").trim().to_string()),
            )
        };
    }

    // Check common ancestor (unrelated histories / shallow Lineage fork)
    if git_nolazy(&dir, &["merge-base", "HEAD", &e.new_rev]).0 != 0 {
        let local_cnt = git_nolazy(&dir, &["rev-list", "--count", "HEAD"])
            .1
            .trim()
            .parse::<usize>()
            .unwrap_or(0);
        return (
            e.path.clone(),
            e.new_rev.clone(),
            MergeOutcome::Unrelated {
                local_cnt,
                note: "no common ancestor (shallow/Lineage base -> reset to CLO rev & cherry-pick local commits)".into(),
            },
        );
    }

    let incoming = git_nolazy(&dir, &["rev-list", "--count", &format!("HEAD..{}", e.new_rev)])
        .1
        .trim()
        .parse::<usize>()
        .unwrap_or(0);

    // Pure in-memory 3-way merge check!
    // Note: merge-tree may need blobs for changed paths in partial clones, so allow lazy blob fetch
    // ONLY during merge-tree itself (never unbounded commit history).
    let (rc_mt, mt_out, mt_err) =
        run_cmd("git", &["merge-tree", "--write-tree", "HEAD", &e.new_rev], &dir, None);
    if rc_mt != 0 {
        let files = parse_conflict_lines(&mt_out);
        if !files.is_empty() {
            return (e.path.clone(), e.new_rev.clone(), MergeOutcome::Conflict { incoming, files });
        }
        return (
            e.path.clone(),
            e.new_rev.clone(),
            MergeOutcome::Failed(
                mt_err
                    .lines()
                    .last()
                    .or_else(|| mt_out.lines().last())
                    .unwrap_or("merge-tree failed")
                    .trim()
                    .to_string(),
            ),
        );
    }

    if dry_run {
        return (e.path.clone(), e.new_rev.clone(), MergeOutcome::DryCleanMerge(incoming));
    }

    // Save safety backup ref before merging
    let cur_head = git_nolazy(&dir, &["rev-parse", "HEAD"]).1.trim().to_string();
    let backup_ref = format!("refs/backups/pre-{}", tag.replace('/', "_"));
    let _ = git_nolazy(&dir, &["update-ref", &backup_ref, &cur_head]);

    let branch = git_nolazy(&dir, &["branch", "--show-current"]).1.trim().to_string();
    let target_br = if branch.is_empty() { "yasvara-17.0" } else { &branch };
    let msg = format!("Merge tag '{tag}' into {target_br}");
    let (rc_m, _, err_m) = run_cmd(
        "git",
        &["-c", "rerere.enabled=false", "merge", "-S", "--no-ff", "-m", &msg, &e.new_rev],
        &dir,
        None,
    );
    if rc_m != 0 {
        // Never leave a repo half-merged when running batch merge
        let _ = run_cmd("git", &["merge", "--abort"], &dir, None);
        return (
            e.path.clone(),
            e.new_rev.clone(),
            MergeOutcome::Failed(err_m.lines().last().unwrap_or("merge failed").trim().to_string()),
        );
    }
    let new_head = git_nolazy(&dir, &["rev-parse", "--short", "HEAD"]).1.trim().to_string();
    (e.path.clone(), e.new_rev.clone(), MergeOutcome::CleanMerged { incoming, new_head })
}

pub fn cmd_sync_merge(
    ctx: &Ctx,
    new_xml: &Path,
    old_xml_opt: Option<&Path>,
    filter: Option<&str>,
    dry_run: bool,
    jobs: usize,
    update_manifest: bool,
) -> i32 {
    let old_default = ctx.ws_root.join("manifest/clo.xml");
    let old_xml = old_xml_opt.unwrap_or(&old_default);
    let tag = infer_tag_from_xml(new_xml);

    let (entries, _added, _removed, _unchanged) =
        match build_sync_plan(ctx, old_xml, new_xml, filter, false) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("!! {e}");
                return 2;
            }
        };

    let manual: Vec<PlanEntry> = entries
        .into_iter()
        .filter(|e| e.kind == PlanKind::ManualMerge)
        .collect();

    println!("==========================================================================================");
    println!(
        "ktool sync merge ({}): {} MANUAL-MERGE repo(s) -> {tag}",
        if dry_run { "DRY-RUN" } else { "APPLY" },
        manual.len()
    );
    println!("==========================================================================================");

    let src_root = ctx.ws_root.join("src");
    // Fetch phase capped at <= 4 workers for CodeLinaro 429 hygiene; GPG signing runs sequentially
    // when !dry_run so gpg-agent never races on pinentry/lock.
    let workers = if dry_run { jobs.clamp(1, 4) } else { 1 };
    let results = par_map(&manual, workers, |e| process_manual_repo(&src_root, e, &tag, dry_run));

    let (mut ok_ff, mut ok_merge, mut already, mut conflicts, mut unrelated, mut failed) =
        (0usize, 0usize, 0usize, Vec::new(), Vec::new(), Vec::new());

    for (path, rev, out) in results {
        match out {
            MergeOutcome::AlreadyMerged => {
                already += 1;
                println!("  [DONE  ] {path:<42} already contains {}", truncate_str(&rev, 10));
            }
            MergeOutcome::FastForwarded(n) => {
                ok_ff += 1;
                println!("  [FF    ] {path:<42} +{n} commits -> {}", truncate_str(&rev, 10));
            }
            MergeOutcome::CleanMerged { incoming, new_head } => {
                ok_merge += 1;
                println!("  [MERGED] {path:<42} +{incoming} commits -> {new_head} (GPG-signed)");
            }
            MergeOutcome::DryCleanFf(n) => {
                ok_ff += 1;
                println!("  [DRY-FF] {path:<42} +{n} commits (clean fast-forward)");
            }
            MergeOutcome::DryCleanMerge(n) => {
                ok_merge += 1;
                println!("  [DRY-OK] {path:<42} +{n} commits (0 conflicts in merge-tree)");
            }
            MergeOutcome::Conflict { incoming, files } => {
                println!(
                    "  [CONFL ] {path:<42} +{incoming} commits ({} conflict line(s))",
                    files.len()
                );
                for cf in files.iter().take(6) {
                    println!("           {cf}");
                }
                conflicts.push((path, rev, files.len()));
            }
            MergeOutcome::Unrelated { local_cnt, note } => {
                println!("  [UNREL ] {path:<42} local={local_cnt} | {note}");
                unrelated.push((path, rev));
            }
            MergeOutcome::Skipped(why) => {
                println!("  [SKIP  ] {path:<42} {why}");
                failed.push((path, why));
            }
            MergeOutcome::Failed(err) => {
                println!("  [FAIL  ] {path:<42} {err}");
                failed.push((path, err));
            }
        }
    }

    println!("------------------------------------------------------------------------------------------");
    println!(
        "Summary: FF={ok_ff} | MERGED={ok_merge} | ALREADY={already} | CONFLICTS={} | UNRELATED={} | FAIL/SKIP={}",
        conflicts.len(),
        unrelated.len(),
        failed.len()
    );

    if !conflicts.is_empty() {
        println!("\nResolve conflicted repos individually with:");
        for (p, r, _) in &conflicts {
            println!("  ./lab/bin/ktool -R src/{p} merge {r} && ./lab/bin/ktool -R src/{p} explain -s");
        }
    }
    if !unrelated.is_empty() {
        println!("\nUnrelated-history repos (re-base local commits onto CLO rev):");
        for (p, r) in &unrelated {
            println!("  git -C src/{p} log --oneline -n 5   # cherry-pick onto {r}");
        }
    }

    if update_manifest && !dry_run {
        if conflicts.is_empty() && unrelated.is_empty() && failed.is_empty() {
            let dst = ctx.ws_root.join("manifest/clo.xml");
            match fs::copy(new_xml, &dst) {
                Ok(_) => println!("\n  [MANIFEST] updated {} -> {tag}", dst.display()),
                Err(e) => eprintln!("\n  !! failed to update manifest/clo.xml: {e}"),
            }
        } else {
            println!("\n  [MANIFEST] NOT updated yet (resolve conflicts/unrelated/failures first).");
        }
    }

    if conflicts.is_empty() && unrelated.is_empty() && failed.is_empty() { 0 } else { 1 }
}

// ====================================================== 2. `ktool prebuilts` (Local + AOSP/CLO SDK & Toolchain Radar)

fn dir_size_mb(path: &Path) -> u64 {
    let (rc, out, _) = run_cmd("du", &["-sm", path.to_string_lossy().as_ref()], path, None);
    if rc == 0 {
        out.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
    } else {
        0
    }
}

fn list_dir_names(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Some(s) = e.file_name().to_str() {
                if !s.starts_with('.') {
                    out.push(s.to_string());
                }
            }
        }
    }
    out.sort_by_key(|s| nat_key(s));
    out
}

fn gitiles_entries(repo: &str, git_ref: &str, subpath: &str) -> Result<Vec<String>, String> {
    let sub = if subpath.is_empty() {
        String::new()
    } else {
        format!("{}/", subpath.trim_matches('/'))
    };
    let url = format!("https://android.googlesource.com/{repo}/+/{git_ref}/{sub}?format=JSON");
    let (rc, out, err) = run_with_retry(3, || {
        run_cmd(
            "curl",
            &["-fsSL", "--max-time", "12", "-A", "ktool/2.0", &url],
            Path::new("/"),
            None,
        )
    });
    if rc != 0 {
        return Err(err.lines().last().unwrap_or("curl failed").trim().to_string());
    }
    // Lightweight zero-crate JSON `"name": "..."` extractor for Gitiles tree entries.
    let mut names = Vec::new();
    let mut rest = out.as_str();
    while let Some(pos) = rest.find("\"name\":") {
        rest = &rest[pos + 7..];
        let trimmed = rest.trim_start();
        if let Some(after_q) = trimmed.strip_prefix('"') {
            if let Some(end_q) = after_q.find('"') {
                names.push(after_q[..end_q].to_string());
                rest = &after_q[end_q + 1..];
                continue;
            }
        }
        break;
    }
    names.sort_by_key(|s| nat_key(s));
    names.dedup();
    Ok(names)
}

fn gitiles_text_file(repo: &str, git_ref: &str, filepath: &str) -> Result<String, String> {
    let url = format!(
        "https://android.googlesource.com/{repo}/+/{git_ref}/{}?format=TEXT",
        filepath.trim_start_matches('/')
    );
    let (rc, b64, err) = run_with_retry(3, || {
        run_cmd(
            "curl",
            &["-fsSL", "--max-time", "12", "-A", "ktool/2.0", &url],
            Path::new("/"),
            None,
        )
    });
    if rc != 0 {
        return Err(err.lines().last().unwrap_or("curl failed").trim().to_string());
    }
    let (rc2, dec, _) = run_cmd("base64", &["-d"], Path::new("/"), Some(b64.as_bytes()));
    if rc2 == 0 {
        Ok(dec.trim().to_string())
    } else {
        Err("base64 decode failed".into())
    }
}

fn latest_aosp_17_tag(ws_root: &Path) -> Option<String> {
    let tags = ls_remote_tags(
        ws_root,
        AOSP_MANIFEST_REPO,
        &["android-17.0.0_r*", "android-security-17.0.0_r*"],
    )
    .ok()?;
    tags.into_iter().max_by_key(|t| nat_key(t))
}

fn latest_local_clo_qssi_xml(ws_root: &Path) -> Option<PathBuf> {
    let dir = ws_root.join("lab/clo-manifests");
    let mut best: Option<(Vec<sync::NatPart>, PathBuf)> = None;
    if let Ok(rd) = fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.starts_with("LA.QSSI.") && name.ends_with(".xml") {
                    let k = nat_key(name);
                    if best.as_ref().map(|(bk, _)| &k > bk).unwrap_or(true) {
                        best = Some((k, p));
                    }
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

fn module_sdk_source_path(sdk_name: &str) -> Option<&'static str> {
    match sdk_name {
        "art" => Some("art"),
        "conscrypt" => Some("external/conscrypt"),
        "AdServices" => Some("packages/modules/AdServices"),
        "AppSearch" => Some("packages/modules/AppSearch"),
        "Bluetooth" => Some("packages/modules/Bluetooth"),
        "ConfigInfrastructure" => Some("packages/modules/ConfigInfrastructure"),
        "Connectivity" => Some("packages/modules/Connectivity"),
        "CrashRecovery" => Some("packages/modules/CrashRecovery"),
        "HealthFitness" => Some("packages/modules/HealthFitness"),
        "IPsec" => Some("packages/modules/IPsec"),
        "Media" => Some("packages/modules/Media"),
        "MediaProvider" => Some("packages/providers/MediaProvider"),
        "Nfc" => Some("packages/modules/Nfc"),
        "OnDevicePersonalization" => Some("packages/modules/OnDevicePersonalization"),
        "Permission" => Some("packages/modules/Permission"),
        "Profiling" => Some("packages/modules/Profiling"),
        "RemoteKeyProvisioning" => Some("packages/modules/RemoteKeyProvisioning"),
        "Scheduling" => Some("packages/modules/Scheduling"),
        "SdkExtensions" => Some("packages/modules/SdkExtensions"),
        "StatsD" => Some("packages/modules/StatsD"),
        "UprobeStats" => Some("packages/modules/UprobeStats"),
        "Uwb" => Some("packages/modules/Uwb"),
        "Wifi" => Some("packages/modules/Wifi"),
        _ => None,
    }
}

pub fn cmd_prebuilts(ctx: &Ctx, check_upstream: bool, filter: Option<&str>) -> i32 {
    let src_root = ctx.ws_root.join("src");
    let pre_root = src_root.join("prebuilts");
    if !pre_root.is_dir() {
        eprintln!("!! missing {}", pre_root.display());
        return 2;
    }
    let flt = filter.map(|s| s.to_ascii_lowercase());

    // 1. Detect installed toolchain & SDK versions
    let clang_dir = pre_root.join("clang/host/linux-x86");
    let local_clangs: Vec<String> = list_dir_names(&clang_dir)
        .into_iter()
        .filter(|n| n.starts_with("clang-r"))
        .collect();
    let local_clang_latest = local_clangs.last().cloned().unwrap_or_else(|| "none".into());
    let local_clang_llvm = fs::read_to_string(clang_dir.join(&local_clang_latest).join("AndroidVersion.txt"))
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .unwrap_or_default();

    let rust_dir = pre_root.join("rust-toolchain/linux-x86");
    let local_rusts: Vec<String> = list_dir_names(&rust_dir)
        .into_iter()
        .filter(|n| n.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .collect();
    let local_rust_latest = local_rusts.last().cloned().unwrap_or_else(|| "none".into());

    let local_go = fs::read_to_string(pre_root.join("go/linux-x86/VERSION"))
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .unwrap_or_else(|| "unknown".into());

    let sdk_apis: Vec<u32> = list_dir_names(&pre_root.join("sdk"))
        .into_iter()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    let local_sdk_max = sdk_apis.iter().copied().max().unwrap_or(0);

    let local_jdks = list_dir_names(&pre_root.join("jdk"));

    // 2. Measure disk footprint across top-level prebuilts in parallel
    let top_dirs: Vec<String> = list_dir_names(&pre_root)
        .into_iter()
        .filter(|d| pre_root.join(d).is_dir())
        .filter(|d| flt.as_ref().map(|f| d.to_ascii_lowercase().contains(f)).unwrap_or(true))
        .collect();
    let sized = par_map(&top_dirs, ctx.threads, |d| (d.clone(), dir_size_mb(&pre_root.join(d))));
    let total_mb: u64 = sized.iter().map(|(_, m)| *m).sum();

    println!("==========================================================================================");
    println!(
        "ktool prebuilts: toolchain & SDK inventory ({} dirs, {:.2} GB total)",
        sized.len(),
        total_mb as f64 / 1024.0
    );
    println!("==========================================================================================");
    println!(
        "  Clang (LLVM)  : {} ({})  [all: {}]",
        local_clang_latest,
        if local_clang_llvm.is_empty() { "?" } else { &local_clang_llvm },
        local_clangs.join(", ")
    );
    println!("  Rust toolchain: {}  [all: {}]", local_rust_latest, local_rusts.join(", "));
    println!("  Go toolchain  : {}", local_go);
    println!("  Android SDK   : API {} ({} API levels installed)", local_sdk_max, sdk_apis.len());
    println!("  JDKs          : {}", local_jdks.join(", "));

    // 3. Largest directories + reclaimable bloat
    let mut by_size = sized.clone();
    by_size.sort_by(|a, b| b.1.cmp(&a.1));
    println!("\nTop disk consumers under src/prebuilts/:");
    for (d, mb) in by_size.iter().take(12) {
        let tag = match d.as_str() {
            "android-emulator" | "qemu-kernel" => "  [UNUSED-ON-DEVICE]",
            "remoteexecution-client" | "bazel" => "  [OPTIONAL-BUILD]",
            _ => "",
        };
        println!("  prebuilts/{:<28} {:>6} MB ({:>5.2} GB){}", d, mb, *mb as f64 / 1024.0, tag);
    }

    // 4. Compare module_sdk/* against CLO latest XML (if downloaded) & source-built detection
    let old_clo_xml = ctx.ws_root.join("manifest/clo.xml");
    let new_clo_xml = latest_local_clo_qssi_xml(&ctx.ws_root);
    if let (Ok(old_txt), Some(new_p)) = (fs::read_to_string(&old_clo_xml), new_clo_xml.as_ref()) {
        if let Ok(new_txt) = fs::read_to_string(new_p) {
            let old_m = clo::parse_manifest_xml(&old_txt);
            let new_m = clo::parse_manifest_xml(&new_txt);
            let mut changed_pre: Vec<(String, String, String)> = Vec::new();
            for (p, np) in &new_m.projects {
                if !p.starts_with("prebuilts/") {
                    continue;
                }
                if let Some(ref f) = flt {
                    if !p.to_ascii_lowercase().contains(f) {
                        continue;
                    }
                }
                if old_m.projects.get(p).map(|op| op.revision.as_str()) != Some(np.revision.as_str()) {
                    let old_r = old_m.projects.get(p).map(|x| x.revision.clone()).unwrap_or_default();
                    changed_pre.push((p.clone(), old_r, np.revision.clone()));
                }
            }
            if !changed_pre.is_empty() {
                let tag_name = infer_tag_from_xml(new_p);
                println!("\nCLO prebuilt updates in {tag_name} ({} changed):", changed_pre.len());
                let rows = par_map(&changed_pre, ctx.threads, |(p, o, n)| {
                    let mb = dir_size_mb(&src_root.join(p));
                    let src_built = p
                        .strip_prefix("prebuilts/module_sdk/")
                        .and_then(module_sdk_source_path)
                        .map(|sp| src_root.join(sp).join(".git").exists())
                        .unwrap_or(false);
                    (p.clone(), o.clone(), n.clone(), mb, src_built)
                });
                let mut tot_chg_mb = 0u64;
                for (p, o, n, mb, src_built) in &rows {
                    tot_chg_mb += *mb;
                    let badge = if *src_built { "SRC-BUILT" } else { "PREBUILT " };
                    println!(
                        "  [{badge}] {:<44} {} -> {} ({:>4} MB)",
                        p,
                        truncate_str(o, 10),
                        truncate_str(n, 10),
                        mb
                    );
                }
                println!(
                    "  Total local size of changed CLO prebuilts: {:.2} GB ({tot_chg_mb} MB) — SRC-BUILT stubs are optional unless Soong complains.",
                    tot_chg_mb as f64 / 1024.0
                );
            } else {
                println!("\nCLO prebuilts: 0 prebuilts changed vs {}.", infer_tag_from_xml(new_p));
            }
        }
    }

    // 5. Optional live AOSP upstream toolchain & SDK check!
    if check_upstream {
        println!("\n==========================================================================================");
        println!("Live AOSP Upstream Prebuilts & SDK Check (android.googlesource.com)");
        println!("==========================================================================================");
        let aosp_tag = latest_aosp_17_tag(&ctx.ws_root)
            .unwrap_or_else(|| "android-security-17.0.0_r3".to_string());
        let git_ref = format!("refs/tags/{aosp_tag}");
        println!("  Target AOSP release tag: {aosp_tag}");

        // Query Clang, Rust, Go, SDK, R8, Build-Tools in parallel (3 workers, polite to GoogleSource)
        let checks = vec!["clang", "rust", "go", "sdk", "jdk", "r8", "build-tools"];
        let res = par_map(&checks, 3, |kind| -> (&str, String, String, String) {
            match *kind {
                "clang" => match gitiles_entries("platform/prebuilts/clang/host/linux-x86", &git_ref, "") {
                    Ok(v) => {
                        let up = v.into_iter().filter(|s| s.starts_with("clang-r")).last().unwrap_or_else(|| "?".into());
                        let st = if nat_key(&up) > nat_key(&local_clang_latest) { "UPDATE" } else { "UP2DAT" };
                        ("Clang", local_clang_latest.clone(), up, st.into())
                    }
                    Err(e) => ("Clang", local_clang_latest.clone(), e, "ERR".into()),
                },
                "rust" => match gitiles_entries("platform/prebuilts/rust-toolchain/linux-x86", &git_ref, "") {
                    Ok(v) => {
                        let up = v
                            .into_iter()
                            .filter(|s| s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                            .last()
                            .unwrap_or_else(|| "?".into());
                        let st = if nat_key(&up) > nat_key(&local_rust_latest) { "UPDATE" } else { "UP2DAT" };
                        ("Rust toolchain", local_rust_latest.clone(), up, st.into())
                    }
                    Err(e) => ("Rust toolchain", local_rust_latest.clone(), e, "ERR".into()),
                },
                "go" => match gitiles_text_file("platform/prebuilts/go/linux-x86", &git_ref, "VERSION") {
                    Ok(v) => {
                        let up = v.lines().next().unwrap_or("?").trim().to_string();
                        let st = if nat_key(&up) > nat_key(&local_go) { "UPDATE" } else { "UP2DAT" };
                        ("Go toolchain", local_go.clone(), up, st.into())
                    }
                    Err(e) => ("Go toolchain", local_go.clone(), e, "ERR".into()),
                },
                "sdk" => match gitiles_entries("platform/prebuilts/sdk", &git_ref, "") {
                    Ok(v) => {
                        let max_api = v.into_iter().filter_map(|s| s.parse::<u32>().ok()).max().unwrap_or(0);
                        let loc_s = format!("API {local_sdk_max}");
                        let up_s = format!("API {max_api}");
                        let st = if max_api > local_sdk_max { "UPDATE" } else { "UP2DAT" };
                        ("Android SDK", loc_s, up_s, st.into())
                    }
                    Err(e) => ("Android SDK", format!("API {local_sdk_max}"), e, "ERR".into()),
                },
                "jdk" => {
                    let loc = local_jdks.last().cloned().unwrap_or_else(|| "?".into());
                    let url = "https://android.googlesource.com/platform/prebuilts/jdk/jdk25";
                    let (rc, out, _) = run_with_retry(2, || {
                        run_cmd("git", &["ls-remote", url, &git_ref], &ctx.ws_root, None)
                    });
                    if rc == 0 && !out.trim().is_empty() {
                        let up_sha = out.split_whitespace().next().unwrap_or("?").to_string();
                        let loc_sha = git_nolazy(&pre_root.join("jdk/jdk25"), &["rev-parse", "HEAD"]).1.trim().to_string();
                        let st = if loc_sha == up_sha { "UP2DAT" } else { "DIFF  " };
                        ("JDK 25", format!("{loc} ({})", truncate_str(&loc_sha, 10)), truncate_str(&up_sha, 10).to_string(), st.into())
                    } else {
                        ("JDK 25", loc, "not in tag".into(), "INFO".into())
                    }
                }
                "r8" => {
                    let url = "https://android.googlesource.com/platform/prebuilts/r8";
                    let (rc, out, _) = run_with_retry(2, || {
                        run_cmd("git", &["ls-remote", url, &git_ref], &ctx.ws_root, None)
                    });
                    let loc_sha = git_nolazy(&pre_root.join("r8"), &["rev-parse", "HEAD"]).1.trim().to_string();
                    if rc == 0 && !out.trim().is_empty() {
                        let up_sha = out.split_whitespace().next().unwrap_or("?").to_string();
                        let st = if loc_sha == up_sha { "UP2DAT" } else { "DIFF  " };
                        ("R8 (D8/R8)", truncate_str(&loc_sha, 10).to_string(), truncate_str(&up_sha, 10).to_string(), st.into())
                    } else {
                        ("R8 (D8/R8)", truncate_str(&loc_sha, 10).to_string(), "query failed".into(), "ERR".into())
                    }
                }
                _ => {
                    let url = "https://android.googlesource.com/platform/prebuilts/build-tools";
                    let (rc, out, _) = run_with_retry(2, || {
                        run_cmd("git", &["ls-remote", url, &git_ref], &ctx.ws_root, None)
                    });
                    let loc_sha = git_nolazy(&pre_root.join("build-tools"), &["rev-parse", "HEAD"]).1.trim().to_string();
                    if rc == 0 && !out.trim().is_empty() {
                        let up_sha = out.split_whitespace().next().unwrap_or("?").to_string();
                        let st = if loc_sha == up_sha { "UP2DAT" } else { "DIFF  " };
                        ("build-tools", truncate_str(&loc_sha, 10).to_string(), truncate_str(&up_sha, 10).to_string(), st.into())
                    } else {
                        ("build-tools", truncate_str(&loc_sha, 10).to_string(), "query failed".into(), "ERR".into())
                    }
                }
            }
        });

        for (label, loc, up, st) in res {
            println!("  [{st:<6}] {label:<16} local: {loc:<22} aosp({aosp_tag}): {up}");
        }
    } else {
        println!("\nTip: pass `--check-upstream` to compare Clang/Rust/Go/SDK/JDK/R8 against live AOSP 17 upstream.");
    }
    0
}

// ====================================================== 3. `ktool hygiene` (Workspace Release Gate)

fn walk_tmppacks(root: &Path, out: &mut Vec<(PathBuf, u64)>) {
    let Ok(rd) = fs::read_dir(root) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name.starts_with("tmp_pack_") || name.starts_with("tmp_idx_") {
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.push((p, sz));
                continue;
            }
        }
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            walk_tmppacks(&p, out);
        }
    }
}

pub fn cmd_hygiene(ctx: &Ctx, fix_tmppacks: bool) -> i32 {
    let src_root = ctx.ws_root.join("src");
    println!("==========================================================================================");
    println!("ktool hygiene: Yasvara workspace release-readiness gate (16-core)");
    println!("==========================================================================================");

    let mut fails = 0usize;

    // Gate 1: Zero internal SPEC-xxxx tags in src/ (excluding out/ and prebuilts/)
    let (_, rg_out, _) = run_cmd(
        "rg",
        &[
            "-n",
            "-g", "!.git/**",
            "-g", "!out/**",
            "-g", "!prebuilts/**",
            "-g", "!*.apk",
            "-g", "!*.so",
            "-g", "!*.jar",
            "-g", "!*.bin",
            r"SPEC-\d+",
            ".",
        ],
        &src_root,
        None,
    );
    let spec_hits: Vec<&str> = rg_out
        .lines()
        .filter(|l| !l.contains("/src/out/") && !l.contains("/src/prebuilts/"))
        .collect();
    if spec_hits.is_empty() {
        println!("  [PASS] Gate 1 — Zero internal SPEC-xxxx references in source");
    } else {
        fails += 1;
        println!("  [FAIL] Gate 1 — {} SPEC-xxxx reference(s) remain:", spec_hits.len());
        for h in spec_hits.iter().take(8) {
            println!("         {}", truncate_str(h, 120));
        }
    }

    // Gate 2, 3, 4: Parallel audit over manifest + pending repos
    let manifest = load_yasvara_manifest(&ctx.ws_root).unwrap_or_default();
    let pending = load_pending_projects(&ctx.ws_root);
    let mut all_paths: BTreeSet<String> = manifest.projects.keys().cloned().collect();
    all_paths.extend(pending.keys().cloned());
    let paths_vec: Vec<String> = all_paths.into_iter().collect();

    struct RepoCheck {
        path: String,
        detached_dirty: usize,
        wip_commits: Vec<String>,
        unsigned_commits: Vec<String>,
    }

    let checks = par_map(&paths_vec, ctx.threads, |p| {
        let dir = src_root.join(p);
        let mut rc = RepoCheck {
            path: p.clone(),
            detached_dirty: 0,
            wip_commits: Vec::new(),
            unsigned_commits: Vec::new(),
        };
        if !dir.join(".git").exists() {
            return rc;
        }
        let br = git_nolazy(&dir, &["branch", "--show-current"]).1.trim().to_string();
        if br.is_empty() && p != "external/chromium-webview" {
            let dirty = git_nolazy(&dir, &["status", "--porcelain"])
                .1
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count();
            rc.detached_dirty = dirty;
        }
        if br == "yasvara-17.0" {
            // Check recent local commits authored by user / Yasvara for wip/snapshot or unsigned
            let log = git_nolazy(&dir, &["log", "-n", "30", "--format=%h|%G?|%an|%s"]).1;
            for line in log.lines() {
                let parts: Vec<&str> = line.splitn(4, '|').collect();
                if parts.len() < 4 {
                    continue;
                }
                let (h, g, an, subj) = (parts[0], parts[1], parts[2], parts[3]);
                let low = subj.to_ascii_lowercase();
                if low.contains("pre-clo snapshot") || low.contains("carry yasvara") || low.starts_with("wip:") {
                    rc.wip_commits.push(format!("{h} {subj}"));
                }
                if an.contains("IRedDragonICY") && g != "G" && g != "U" {
                    rc.unsigned_commits.push(format!("{h} ({g}) {subj}"));
                }
            }
        }
        rc
    });

    let det_dirty: Vec<&RepoCheck> = checks.iter().filter(|c| c.detached_dirty > 0).collect();
    let wip_repos: Vec<&RepoCheck> = checks.iter().filter(|c| !c.wip_commits.is_empty()).collect();
    let unsig_repos: Vec<&RepoCheck> = checks.iter().filter(|c| !c.unsigned_commits.is_empty()).collect();

    if wip_repos.is_empty() {
        println!("  [PASS] Gate 2 — Zero wip/pre-CLO-snapshot/carry dump commits on yasvara-17.0");
    } else {
        fails += 1;
        println!("  [FAIL] Gate 2 — {} repo(s) still contain wip/snapshot commits:", wip_repos.len());
        for c in &wip_repos {
            println!("         {}: {}", c.path, c.wip_commits.join("; "));
        }
    }

    if unsig_repos.is_empty() {
        println!("  [PASS] Gate 3 — All recent Yasvara commits on yasvara-17.0 are GPG-signed");
    } else {
        fails += 1;
        println!("  [WARN] Gate 3 — {} repo(s) have unsigned Yasvara commits:", unsig_repos.len());
        for c in unsig_repos.iter().take(10) {
            println!("         {}: {}", c.path, c.unsigned_commits[0]);
        }
    }

    if det_dirty.is_empty() {
        println!("  [PASS] Gate 4 — Zero detached-HEAD dirty repositories");
    } else {
        fails += 1;
        println!("  [FAIL] Gate 4 — {} detached-HEAD dirty repo(s):", det_dirty.len());
        for c in &det_dirty {
            println!("         {} (DIRTY {})", c.path, c.detached_dirty);
        }
    }

    // Gate 5: Abandoned tmp_pack_* files under src/.repo/
    let mut tmps = Vec::new();
    for sub in ["src/.repo/project-objects", "src/.repo/projects"] {
        let root = ctx.ws_root.join(sub);
        if root.is_dir() {
            walk_tmppacks(&root, &mut tmps);
        }
    }
    let tmp_bytes: u64 = tmps.iter().map(|(_, s)| *s).sum();
    if tmps.is_empty() {
        println!("  [PASS] Gate 5 — Zero abandoned tmp_pack/tmp_idx files in src/.repo/");
    } else if fix_tmppacks {
        let mut deleted = 0usize;
        for (p, _) in &tmps {
            if fs::remove_file(p).is_ok() {
                deleted += 1;
            }
        }
        println!(
            "  [FIX ] Gate 5 — Cleaned {deleted}/{} abandoned tmp_pack file(s), reclaimed {:.1} MB",
            tmps.len(),
            tmp_bytes as f64 / (1024.0 * 1024.0)
        );
    } else {
        println!(
            "  [WARN] Gate 5 — {} abandoned tmp_pack file(s) wasting {:.1} MB (run `ktool hygiene --fix-tmppacks`)",
            tmps.len(),
            tmp_bytes as f64 / (1024.0 * 1024.0)
        );
    }

    println!("------------------------------------------------------------------------------------------");
    println!("Hygiene verdict: {}", if fails == 0 { "CLEAN (PASS)" } else { "ISSUES FOUND" });
    if fails == 0 { 0 } else { 1 }
}

// ====================================================== 4. `ktool push` (Pre-Push Audit & Safe Pusher)

struct PushRow {
    label: String,
    dir: PathBuf,
    branch: String,
    remote_name: Option<String>,
    remote_url: String,
    behind: Option<usize>,
    in_yasvara_xml: bool,
    status: String,
}

fn is_safe_push_remote(url: &str) -> bool {
    let low = url.to_ascii_lowercase();
    let owned = low.contains("github.com:yasvara/")
        || low.contains("github.com/yasvara/")
        || low.contains("github.com:yasvara-devices/")
        || low.contains("github.com/yasvara-devices/")
        || low.contains("gitlab.com:poco-f7/")
        || low.contains("gitlab.com/poco-f7/")
        || low.contains("ireddragonicy");
    owned
        && !low.contains("codelinaro.org")
        && !low.contains("googlesource.com")
        && !low.contains("lineageos/")
}

fn inspect_push_repo(label: &str, dir: &Path, in_yas_xml: bool) -> Option<PushRow> {
    if !dir.join(".git").exists() {
        return None;
    }
    let br = git_nolazy(dir, &["branch", "--show-current"]).1.trim().to_string();
    if br.is_empty() {
        return None;
    }
    // Pick preferred push remote
    let rems = git_nolazy(dir, &["remote", "-v"]).1;
    let mut candidates: BTreeMap<String, String> = BTreeMap::new();
    for line in rems.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "(push)" && is_safe_push_remote(parts[1]) {
            candidates.insert(parts[0].to_string(), parts[1].to_string());
        }
    }
    let chosen = ["yasvara", "origin", "gitlab", "onyx-dev"]
        .iter()
        .find_map(|k| candidates.get(*k).map(|u| ((*k).to_string(), u.clone())))
        .or_else(|| candidates.into_iter().next());

    let (remote_name, remote_url) = match chosen {
        Some((n, u)) => (Some(n), u),
        None => (None, String::new()),
    };

    let (behind, status) = if let Some(ref rname) = remote_name {
        let rref = format!("refs/remotes/{rname}/{br}");
        if git_nolazy(dir, &["rev-parse", "-q", "--verify", &rref]).0 == 0 {
            let lr = git_nolazy(dir, &["rev-list", "--left-right", "--count", &format!("{rname}/{br}...HEAD")]).1;
            let mut it = lr.split_whitespace();
            let b = it.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let a = it.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let st = if a == 0 && b == 0 {
                "SYNCED".to_string()
            } else {
                format!("↑{a} ↓{b}")
            };
            (Some(b), st)
        } else {
            (None, "NEW-BRANCH".to_string())
        }
    } else {
        (None, "NO-REMOTE".to_string())
    };

    Some(PushRow {
        label: label.to_string(),
        dir: dir.to_path_buf(),
        branch: br,
        remote_name,
        remote_url,
        behind,
        in_yasvara_xml: in_yas_xml,
        status,
    })
}

pub fn cmd_push(ctx: &Ctx, apply: bool, filter: Option<&str>, show_all: bool) -> i32 {
    let manifest = load_yasvara_manifest(&ctx.ws_root).unwrap_or_default();
    let pending = load_pending_projects(&ctx.ws_root);
    let yas_xml = ctx.ws_root.join("manifest/snippets/yasvara.xml");
    let yas_paths: BTreeSet<String> = fs::read_to_string(&yas_xml)
        .map(|t| clo::parse_manifest_xml(&t).projects.into_keys().collect())
        .unwrap_or_default();

    let src_root = ctx.ws_root.join("src");
    let flt = filter.map(|s| s.to_ascii_lowercase());

    let mut targets: Vec<(String, PathBuf, bool)> = Vec::new();
    // Always include manifest repo itself
    targets.push(("manifest".to_string(), ctx.ws_root.join("manifest"), true));

    // Scan ported/custom repos (yasvara-17.0, yasvara remote, pending)
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for p in manifest.projects.values() {
        let dir = src_root.join(&p.path);
        if !dir.join(".git").exists() {
            continue;
        }
        let br = git_nolazy(&dir, &["branch", "--show-current"]).1.trim().to_string();
        if br == "yasvara-17.0" || p.remote == "yasvara" || br.starts_with("lineage-") {
            seen.insert(p.path.clone());
            targets.push((p.path.clone(), dir, yas_paths.contains(&p.path)));
        }
    }
    for p in pending.values() {
        if seen.insert(p.path.clone()) {
            targets.push((p.path.clone(), src_root.join(&p.path), true));
        }
    }
    if let Some(ref f) = flt {
        targets.retain(|(l, _, _)| l.to_ascii_lowercase().contains(f));
    }

    let rows: Vec<PushRow> = par_map(&targets, ctx.threads, |(l, d, in_y)| inspect_push_repo(l, d, *in_y))
        .into_iter()
        .flatten()
        .collect();

    let ready: Vec<&PushRow> = rows
        .iter()
        .filter(|r| r.remote_name.is_some() && r.status != "SYNCED")
        .collect();
    let no_rem: Vec<&PushRow> = rows.iter().filter(|r| r.remote_name.is_none()).collect();
    let synced_cnt = rows.iter().filter(|r| r.status == "SYNCED").count();
    let untracked_manifest = rows.iter().filter(|r| !r.in_yasvara_xml && r.branch == "yasvara-17.0").count();

    println!("==========================================================================================");
    println!(
        "ktool push ({}): {} custom repos | {} ready to push | {} missing Yasvara remote | {} synced",
        if apply { "APPLY" } else { "DRY-RUN" },
        rows.len(),
        ready.len(),
        no_rem.len(),
        synced_cnt
    );
    println!("==========================================================================================");

    println!("\n[1] Ready to push ({} repos with configured Yasvara/device remote):", ready.len());
    for r in &ready {
        let rname = r.remote_name.as_deref().unwrap_or("-");
        let mtag = if r.in_yasvara_xml { "" } else { " [not-in-yasvara.xml]" };
        if apply {
            if r.behind.unwrap_or(0) > 0 {
                println!(
                    "  [SKIP  ] {:<42} {}/{} ({}) — behind remote (refusing force-push)",
                    r.label, rname, r.branch, r.status
                );
                continue;
            }
            let (rc, _, err) = run_cmd("git", &["push", "-u", rname, &r.branch], &r.dir, None);
            if rc == 0 {
                println!("  [PUSHED] {:<42} -> {}/{} ({}){}", r.label, rname, r.branch, r.status, mtag);
            } else {
                println!(
                    "  [FAIL  ] {:<42} -> {}/{}: {}",
                    r.label,
                    rname,
                    r.branch,
                    err.lines().last().unwrap_or("push failed").trim()
                );
            }
        } else {
            println!(
                "  [READY ] {:<42} {:<14} -> {:<9} {:<10} ({}){}",
                r.label, r.branch, rname, r.status, r.remote_url, mtag
            );
        }
    }

    if !no_rem.is_empty() && (show_all || !apply) {
        println!(
            "\n[2] Local yasvara-17.0 repos without a Yasvara GitHub remote ({}):",
            no_rem.len()
        );
        let lim = if show_all { no_rem.len() } else { 20 };
        for r in no_rem.iter().take(lim) {
            let mtag = if r.in_yasvara_xml { "" } else { " [not-in-yasvara.xml]" };
            println!("  [NOREM ] {:<44} br={:<14}{}", r.label, r.branch, mtag);
        }
        if no_rem.len() > lim {
            println!("  ... and {} more (pass `--all` to list every repo)", no_rem.len() - lim);
        }
    }

    println!("\nNote: {untracked_manifest} local `yasvara-17.0` repos are not yet listed in manifest/snippets/yasvara.xml.");
    if !apply {
        println!("Run `ktool push --apply [--filter <pat>]` to push the {} ready repo(s).", ready.len());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_push_remote_guard() {
        assert!(is_safe_push_remote("git@github.com:Yasvara/android_frameworks_base.git"));
        assert!(is_safe_push_remote("git@github.com:Yasvara-Devices/android_device_xiaomi_grus.git"));
        assert!(is_safe_push_remote("git@gitlab.com:poco-f7/device_xiaomi_onyx.git"));
        assert!(is_safe_push_remote("git@gitlab.com:IRedDragonICY/android_device_xiaomi_onyx.git"));
        assert!(!is_safe_push_remote("https://gitlab.com/AdarshGrewal/proprietary_vendor_xiaomi_onyx"));
        assert!(!is_safe_push_remote("https://gitlab.com/NoPrincessHere/proprietary_vendor_xiaomi_onyx-miuicamera.git"));
        assert!(!is_safe_push_remote("https://git.codelinaro.org/clo/la/platform/frameworks/base"));
        assert!(!is_safe_push_remote("https://github.com/LineageOS/android_frameworks_base"));
        assert!(!is_safe_push_remote("https://android.googlesource.com/platform/bionic"));
    }

    #[test]
    fn test_parse_conflict_lines() {
        let sample = "deadbeef\nAuto-merging foo.c\nCONFLICT (content): Merge conflict in foo.c\nCONFLICT (modify/delete): bar.h deleted in HEAD\n";
        let got = parse_conflict_lines(sample);
        assert_eq!(got.len(), 2);
        assert!(got[0].contains("foo.c"));
        assert!(got[1].contains("bar.h"));
    }

    #[test]
    fn test_infer_tag_from_xml() {
        let p = Path::new("lab/clo-manifests/LA.QSSI.17.0.r1-12500-qssi.0.xml");
        assert_eq!(infer_tag_from_xml(p), "LA.QSSI.17.0.r1-12500-qssi.0");
    }
}
