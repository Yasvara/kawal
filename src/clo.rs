use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::util::*;

// ====================================================== 1. Manifest XML Parser & Diff

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRef {
    pub name: String,
    pub project: String,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestProject {
    pub name: String,
    pub path: String,
    pub revision: String,
    pub upstream: String,
}

#[derive(Debug, Default)]
pub struct Manifest {
    pub refs: BTreeMap<String, ManifestRef>,
    pub projects: BTreeMap<String, ManifestProject>,
}

fn extract_xml_attr(tag_line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = tag_line.find(&needle)? + needle.len();
    let end = tag_line[start..].find('"')? + start;
    Some(tag_line[start..end].to_string())
}

pub fn parse_manifest_xml(text: &str) -> Manifest {
    let mut m = Manifest::default();
    for raw in text.lines() {
        let ln = raw.trim();
        if ln.starts_with("<image ") {
            if let (Some(name), Some(project), Some(tag)) = (
                extract_xml_attr(ln, "name"),
                extract_xml_attr(ln, "project"),
                extract_xml_attr(ln, "tag"),
            ) {
                m.refs.insert(name.clone(), ManifestRef { name, project, tag });
            }
        } else if ln.starts_with("<project ") {
            if let (Some(name), Some(rev)) = (
                extract_xml_attr(ln, "name"),
                extract_xml_attr(ln, "revision"),
            ) {
                let path = extract_xml_attr(ln, "path").unwrap_or_else(|| name.clone());
                let upstream = extract_xml_attr(ln, "upstream")
                    .unwrap_or_default()
                    .trim_start_matches("refs/heads/")
                    .to_string();
                m.projects.insert(
                    path.clone(),
                    ManifestProject { name, path, revision: rev, upstream },
                );
            }
        }
    }
    m
}

/// Compare two CLO/Android manifest XML files (`<refs>` techpacks + `<project>` revisions).
/// When `check_local_src` is given (e.g. `src/`), annotates changed projects with local commit
/// count ahead of the old manifest revision & dirty status (huge time-saver for ROM QSSI bumps!).
pub fn cmd_clo_diff(old_path: &Path, new_path: &Path, filter: Option<&str>, check_local_src: Option<&Path>) -> i32 {
    let Ok(old_txt) = fs::read_to_string(old_path) else {
        eprintln!("cannot read {}", old_path.display());
        return 2;
    };
    let Ok(new_txt) = fs::read_to_string(new_path) else {
        eprintln!("cannot read {}", new_path.display());
        return 2;
    };
    let old = parse_manifest_xml(&old_txt);
    let new = parse_manifest_xml(&new_txt);
    let flt = filter.map(|s| s.to_ascii_lowercase());

    println!("=== manifest diff: {} -> {} ===", old_path.display(), new_path.display());

    // 1. Techpack <refs>
    let all_refs: BTreeSet<&String> = old.refs.keys().chain(new.refs.keys()).collect();
    if !all_refs.is_empty() {
        let mut changed_refs = Vec::new();
        for k in all_refs {
            if let Some(ref f) = flt {
                if !k.to_ascii_lowercase().contains(f) {
                    continue;
                }
            }
            match (old.refs.get(k), new.refs.get(k)) {
                (Some(a), Some(b)) if a.tag != b.tag => {
                    changed_refs.push(format!("  [CHG] {:<26} {} -> {}", k, a.tag, b.tag));
                }
                (None, Some(b)) => {
                    changed_refs.push(format!("  [ADD] {:<26} {}", k, b.tag));
                }
                (Some(a), None) => {
                    changed_refs.push(format!("  [DEL] {:<26} {}", k, a.tag));
                }
                _ => {}
            }
        }
        println!("\n<refs> techpacks ({} changed):", changed_refs.len());
        for ln in changed_refs {
            println!("{ln}");
        }
    }

    // 2. <project> entries
    let all_projs: BTreeSet<&String> = old.projects.keys().chain(new.projects.keys()).collect();
    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut same = 0usize;

    for p in all_projs {
        if let Some(ref f) = flt {
            let p_low = p.to_ascii_lowercase();
            let n_low = new
                .projects
                .get(p)
                .or_else(|| old.projects.get(p))
                .map(|x| x.name.to_ascii_lowercase())
                .unwrap_or_default();
            if !p_low.contains(f) && !n_low.contains(f) {
                continue;
            }
        }
        match (old.projects.get(p), new.projects.get(p)) {
            (Some(a), Some(b)) if a.revision == b.revision => same += 1,
            (Some(a), Some(b)) => {
                let local_note = if let Some(src_root) = check_local_src {
                    let repo_dir = src_root.join(p);
                    if repo_dir.join(".git").exists() {
                        let dirty = !git_in(&repo_dir, &["status", "--porcelain"]).trim().is_empty();
                        let ahead = git_in(&repo_dir, &["rev-list", "--count", &format!("{}..HEAD", a.revision)]);
                        let cnt = ahead.trim();
                        if !cnt.is_empty() && cnt != "0" {
                            format!(" [LOCAL +{cnt}{}]", if dirty { " DIRTY" } else { "" })
                        } else if dirty {
                            " [LOCAL DIRTY]".to_string()
                        } else {
                            " [CLEAN-FF]".to_string()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                changed.push(format!(
                    "  [CHG] {:<52} {} -> {}  ({}){}",
                    p,
                    truncate_str(&a.revision, 10),
                    truncate_str(&b.revision, 10),
                    b.upstream,
                    local_note
                ));
            }
            (None, Some(b)) => added.push(format!(
                "  [ADD] {:<52} {}  ({})",
                p,
                truncate_str(&b.revision, 10),
                b.name
            )),
            (Some(a), None) => removed.push(format!(
                "  [DEL] {:<52} {}  ({})",
                p,
                truncate_str(&a.revision, 10),
                a.name
            )),
            (None, None) => {}
        }
    }

    println!(
        "\n<project> summary: {} unchanged, {} changed, {} added, {} removed",
        same,
        changed.len(),
        added.len(),
        removed.len()
    );
    for ln in changed {
        println!("{ln}");
    }
    for ln in added {
        println!("{ln}");
    }
    for ln in removed {
        println!("{ln}");
    }
    0
}

// ====================================================== 2. Exact Blob-SHA1 Fork-Point Fingerprinter

fn ls_tree_blobs(git_dir: &Path, rev: &str, subpath: Option<&str>) -> HashMap<String, String> {
    let mut args = vec!["ls-tree", "-r", rev];
    let spec;
    if let Some(sub) = subpath {
        spec = format!("{rev}:{sub}");
        args = vec!["ls-tree", "-r", &spec];
    }
    let out = if git_dir.join("HEAD").is_file() && !git_dir.join(".git").exists() {
        bare_git(git_dir, &args).1
    } else {
        git_in(git_dir, &args)
    };
    let mut map = HashMap::new();
    for ln in out.lines() {
        // `<mode> <type> <sha>\t<path>`
        let Some((meta, path)) = ln.split_once('\t') else { continue };
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "blob" {
            map.insert(path.to_string(), parts[2].to_string());
        }
    }
    map
}

fn bare_git(bare: &Path, args: &[&str]) -> (i32, String, String) {
    let mut full = Vec::with_capacity(args.len() + 2);
    full.push("--git-dir");
    full.push(".");
    full.extend_from_slice(args);
    run_cmd("git", &full, bare, None)
}

fn score_commit(bare: &Path, sha: &str, local_blobs: &HashMap<String, String>) -> (usize, usize) {
    let up = ls_tree_blobs(bare, sha, None);
    let mut exact = 0usize;
    let mut common = 0usize;
    for (path, up_sha) in &up {
        if let Some(loc_sha) = local_blobs.get(path) {
            common += 1;
            if loc_sha == up_sha {
                exact += 1;
            }
        }
    }
    (exact, common)
}

fn classify_clo_commit(subj: &str) -> &'static str {
    let sl = subj.to_ascii_lowercase();
    if ["uaf", "use-after-free", "use after free", "oob", "out-of-bound", "overflow", "cve",
        "arbitrary", "confused deputy", "type confusion", "toctou", "kva leak", "privilege",
        "uninitialized", "bypass", "reject mmap"]
        .iter()
        .any(|k| sl.contains(k))
    {
        "SEC!"
    } else if ["panic", "crash", "deadlock", "race", "null", "hang", "freeze", "leak", "corrupt", "fix"]
        .iter()
        .any(|k| sl.contains(k))
    {
        "FIX "
    } else if sl.starts_with("revert") {
        "REV "
    } else {
        "FEAT"
    }
}

/// Fingerprint the exact upstream CLO commit that our squashed local subpath was forked from,
/// using blob SHA-1 matching across coarse grid + local refinement!
pub fn cmd_clo_probe(ctx: &Ctx, local_sub: &str, bare_path: &Path, target_rev: &str, file_filter: Option<&str>) -> i32 {
    let sub_opt = if local_sub == "." || local_sub.is_empty() {
        None
    } else {
        Some(local_sub)
    };
    let local_blobs = ls_tree_blobs(&ctx.repo, "HEAD", sub_opt);
    if local_blobs.is_empty() {
        eprintln!("!! no git blobs found at HEAD:{local_sub} in {}", ctx.repo.display());
        return 2;
    }

    // Fetch first-parent commit history up to 1500 commits back from target_rev
    let (_, rev_out, err) = bare_git(bare_path, &["rev-list", "--first-parent", "-n", "1500", target_rev]);
    let commits: Vec<String> = rev_out.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if commits.is_empty() {
        eprintln!("!! rev-list failed on {} for {target_rev}: {}", bare_path.display(), err.trim());
        return 2;
    }

    // Step 1: Coarse grid scan (up to ~60 evenly spaced points) in parallel!
    let step = (commits.len() / 50).max(1);
    let mut sample_idxs: Vec<usize> = (0..commits.len()).step_by(step).collect();
    if *sample_idxs.last().unwrap() != commits.len() - 1 {
        sample_idxs.push(commits.len() - 1);
    }

    let coarse: Vec<(usize, usize, usize)> = par_map(&sample_idxs, ctx.threads.min(8), |&idx| {
        let (ex, com) = score_commit(bare_path, &commits[idx], &local_blobs);
        (idx, ex, com)
    });

    // Pick best coarse peak (tie-break: prefer older/closer-to-fork or higher exact ratio)
    let best_coarse = coarse
        .iter()
        .max_by_key(|(_, ex, _)| *ex)
        .map(|(i, _, _)| *i)
        .unwrap_or(0);

    // Step 2: Fine scan around best_coarse +/- step*2 in parallel!
    let lo = best_coarse.saturating_sub(step * 2);
    let hi = (best_coarse + step * 2).min(commits.len() - 1);
    let fine_idxs: Vec<usize> = (lo..=hi).collect();
    let fine: Vec<(usize, usize, usize)> = par_map(&fine_idxs, ctx.threads.min(8), |&idx| {
        let (ex, com) = score_commit(bare_path, &commits[idx], &local_blobs);
        (idx, ex, com)
    });

    // Among commits achieving the maximum exact blob match count, pick the NEWEST (smallest idx)
    // because commits that didn't touch existing files keep the same exact match, OR prefer
    // the one with smallest total diff (fewest changed files vs local)!
    let max_ex = fine.iter().map(|(_, ex, _)| *ex).max().unwrap_or(0);
    let best_idx = fine
        .iter()
        .filter(|(_, ex, _)| *ex == max_ex)
        .map(|(i, _, _)| *i)
        .min()
        .unwrap_or(best_coarse);
    let (_, best_ex, best_com) = fine.iter().find(|(i, _, _)| *i == best_idx).copied().unwrap();

    let base_sha = &commits[best_idx];
    let (_, base_meta, _) = bare_git(bare_path, &["show", "-s", "--format=%h %ad %s", "--date=short", base_sha]);
    let (_, tgt_meta, _) = bare_git(bare_path, &["show", "-s", "--format=%h %ad %s", "--date=short", target_rev]);

    // Identify local Xiaomi/custom customized files (differs from detected BASE)
    let base_blobs = ls_tree_blobs(bare_path, base_sha, None);
    let mut local_only = 0usize;
    let mut local_modified: HashSet<String> = HashSet::new();
    for (p, lsha) in &local_blobs {
        match base_blobs.get(p) {
            None => local_only += 1,
            Some(bsha) if bsha != lsha => {
                local_modified.insert(p.clone());
            }
            _ => {}
        }
    }

    // List commits in BASE..TARGET and check which overlap local_modified files!
    let rng = format!("{base_sha}..{target_rev}");
    let (_, log_out, _) = bare_git(
        bare_path,
        &["log", "--no-merges", "--reverse", "--format=@@@%h%x1f%ad%x1f%s", "--date=short", "--name-only", &rng],
    );

    let mut delta_commits: Vec<(String, String, String, Vec<String>)> = Vec::new();
    for ln in log_out.lines() {
        if let Some(rest) = ln.strip_prefix("@@@") {
            let p: Vec<&str> = rest.splitn(3, '\x1f').collect();
            if p.len() == 3 {
                delta_commits.push((p[0].to_string(), p[1].to_string(), p[2].to_string(), Vec::new()));
            }
        } else if !ln.trim().is_empty() {
            if let Some(last) = delta_commits.last_mut() {
                last.3.push(ln.trim().to_string());
            }
        }
    }

    let pct = if best_com > 0 { (best_ex * 1000) / best_com } else { 0 };
    println!("=== clo probe: {local_sub} ===");
    println!("  detected BASE : {}", base_meta.trim());
    println!("  target        : {}", tgt_meta.trim());
    println!(
        "  blob match    : {best_ex}/{best_com} ({}.{}%) byte-identical | {} local-modified | {} local-only (Xiaomi/custom)",
        pct / 10,
        pct % 10,
        local_modified.len(),
        local_only
    );
    println!("  delta commits : {} non-merge commit(s) in BASE..TARGET", delta_commits.len());

    let mut sec_cnt = 0usize;
    let mut overlap_cnt = 0usize;
    let mut flt_cnt = 0usize;
    let flt_low = file_filter.map(|f| f.to_ascii_lowercase());
    for (h, d, s, files) in &delta_commits {
        let tag = classify_clo_commit(s);
        if tag == "SEC!" {
            sec_cnt += 1;
        }
        let ov = files.iter().any(|f| local_modified.contains(f));
        if ov {
            overlap_cnt += 1;
        }
        let matches_flt = flt_low.as_ref().map_or(true, |pat| {
            pat.split('|').any(|p| {
                !p.is_empty()
                    && (s.to_ascii_lowercase().contains(p)
                        || files.iter().any(|f| f.to_ascii_lowercase().contains(p)))
            })
        });
        if matches_flt {
            flt_cnt += 1;
        }
        let ov_tag = if ov { "OVLP" } else { "    " };
        if (flt_low.is_some() && matches_flt) || (flt_low.is_none() && (delta_commits.len() <= 35 || tag == "SEC!" || ov)) {
            println!("    [{tag}] {ov_tag} {h} {d} {s}");
        }
    }
    if let Some(pat) = file_filter {
        println!("  filter `{pat}`: {flt_cnt}/{} commits matched ({sec_cnt} SEC!, {overlap_cnt} OVLP total)", delta_commits.len());
    } else if delta_commits.len() > 35 {
        println!(
            "  summary: {sec_cnt} SEC!, {overlap_cnt} overlap local-modified files (showing SEC!/OVLP only; total {})",
            delta_commits.len()
        );
    }
    println!("  RECOMMENDED 3-WAY MERGE: ktool -R {} clo merge {local_sub} {} {base_sha} {target_rev}",
        ctx.repo.display(), bare_path.display());
    0
}

// ====================================================== 3. True 3-Way Techpack Merge

/// Perform a true 3-way merge of upstream `base_sha..target_sha` from `bare_path` into
/// `ctx.repo/<local_sub>`, preserving 100% of local-only files (Xiaomi `mi_disp`, `nt36532`,
/// `aw882xx`, etc.) and running `git merge-file` on every file modified by BOTH sides!
pub fn cmd_clo_merge(
    ctx: &Ctx,
    local_sub: &str,
    bare_path: &Path,
    base_sha: &str,
    target_sha: &str,
    dry_run: bool,
) -> i32 {
    println!("=== clo merge ({}): {local_sub} ({} -> {}) ===",
        if dry_run { "DRY-RUN" } else { "APPLY" },
        truncate_str(base_sha, 12),
        truncate_str(target_sha, 12)
    );

    let (_, ns_out, err) = bare_git(bare_path, &["diff", "--name-status", "--no-renames", base_sha, target_sha]);
    if !err.trim().is_empty() && ns_out.is_empty() {
        eprintln!("!! git diff failed: {}", err.trim());
        return 2;
    }

    let tmp_dir = ctx.ws_root.join("lab/clo-cache/.merge-tmp");
    if !dry_run {
        let _ = fs::create_dir_all(&tmp_dir);
    }

    let mut clean_updated = 0usize;
    let mut clean_added = 0usize;
    let mut clean_deleted = 0usize;
    let mut skipped_same = 0usize;
    let mut merged_clean = 0usize;
    let mut conflicts: Vec<String> = Vec::new();
    let mut upstream_markers: Vec<String> = Vec::new();

    // Collect executable (100755) file paths in target_sha so added/updated scripts keep +x!
    let mut exec_paths: HashSet<String> = HashSet::new();
    let (_, mode_out, _) = bare_git(bare_path, &["ls-tree", "-r", target_sha]);
    for ln in mode_out.lines() {
        if let Some((meta, p)) = ln.split_once('\t') {
            if meta.starts_with("100755 ") {
                exec_paths.insert(p.to_string());
            }
        }
    }

    let check_upstream_markers = |rel_p: &str, bytes: &[u8], out: &mut Vec<String>| {
        if let Ok(txt) = std::str::from_utf8(bytes) {
            for (i, l) in txt.lines().enumerate() {
                if l.starts_with("<<<<<<< ") || l.starts_with(">>>>>>> ") {
                    out.push(format!("{local_sub}/{rel_p}:L{} (`{}`)", i + 1, truncate_str(l, 60)));
                    break;
                }
            }
        }
    };

    #[cfg(unix)]
    let apply_exec_if_needed = |dst: &Path, rel: &str, execs: &HashSet<String>| {
        use std::os::unix::fs::PermissionsExt;
        if execs.contains(rel) {
            if let Ok(meta) = fs::metadata(dst) {
                let mut perms = meta.permissions();
                perms.set_mode(perms.mode() | 0o111);
                let _ = fs::set_permissions(dst, perms);
            }
        }
    };

    for ln in ns_out.lines() {
        let parts: Vec<&str> = ln.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }
        let status = parts[0];
        let rel = parts[1];
        let dst = ctx.repo.join(local_sub).join(rel);

        match status {
            "A" => {
                let (_, data, _) = bare_git_bytes(bare_path, &["show", &format!("{target_sha}:{rel}")]);
                if dst.exists() {
                    let cur = fs::read(&dst).unwrap_or_default();
                    if cur == data {
                        skipped_same += 1;
                        continue;
                    }
                    // Both added differently -> 3-way merge with empty base
                    if !dry_run {
                        let base_f = tmp_dir.join("base");
                        let their_f = tmp_dir.join("theirs");
                        let _ = fs::write(&base_f, b"");
                        let _ = fs::write(&their_f, &data);
                        let (rc, _, _) = run_cmd(
                            "git",
                            &[
                                "merge-file",
                                "-L", "HEAD",
                                "-L", "CLO-BASE",
                                "-L", "CLO-TARGET",
                                &dst.to_string_lossy(),
                                &base_f.to_string_lossy(),
                                &their_f.to_string_lossy(),
                            ],
                            &ctx.repo,
                            None,
                        );
                        if rc == 0 {
                            merged_clean += 1;
                        } else {
                            conflicts.push(format!("{local_sub}/{rel} (add/add)"));
                        }
                    } else {
                        conflicts.push(format!("{local_sub}/{rel} (add/add)"));
                    }
                } else {
                    if !dry_run {
                        if let Some(par) = dst.parent() {
                            let _ = fs::create_dir_all(par);
                        }
                        let _ = fs::write(&dst, &data);
                        #[cfg(unix)]
                        apply_exec_if_needed(&dst, rel, &exec_paths);
                    }
                    check_upstream_markers(rel, &data, &mut upstream_markers);
                    clean_added += 1;
                }
            }
            "D" => {
                if !dst.exists() {
                    skipped_same += 1;
                    continue;
                }
                let (_, base_data, _) = bare_git_bytes(bare_path, &["show", &format!("{base_sha}:{rel}")]);
                let cur = fs::read(&dst).unwrap_or_default();
                if cur == base_data {
                    if !dry_run {
                        let _ = fs::remove_file(&dst);
                    }
                    clean_deleted += 1;
                } else {
                    conflicts.push(format!("{local_sub}/{rel} (modify/delete — kept local)"));
                }
            }
            "M" | "T" => {
                let (_, base_data, _) = bare_git_bytes(bare_path, &["show", &format!("{base_sha}:{rel}")]);
                let (_, their_data, _) = bare_git_bytes(bare_path, &["show", &format!("{target_sha}:{rel}")]);
                if !dst.exists() {
                    // Local deleted it -> flag conflict, don't blindly resurrect
                    conflicts.push(format!("{local_sub}/{rel} (delete/modify — skipped)"));
                    continue;
                }
                let cur = fs::read(&dst).unwrap_or_default();
                if cur == their_data {
                    skipped_same += 1;
                    continue;
                }
                if cur == base_data {
                    // Unmodified locally -> fast-forward cleanly!
                    if !dry_run {
                        let _ = fs::write(&dst, &their_data);
                        #[cfg(unix)]
                        apply_exec_if_needed(&dst, rel, &exec_paths);
                    }
                    check_upstream_markers(rel, &their_data, &mut upstream_markers);
                    clean_updated += 1;
                    continue;
                }
                // Both modified -> true 3-way merge via `git merge-file`!
                let base_f = tmp_dir.join("base");
                let their_f = tmp_dir.join("theirs");
                let _ = fs::create_dir_all(&tmp_dir);
                let _ = fs::write(&base_f, &base_data);
                let _ = fs::write(&their_f, &their_data);
                let mut margs = vec![
                    "merge-file",
                    "-L", "HEAD",
                    "-L", "CLO-BASE",
                    "-L", "CLO-TARGET",
                ];
                if dry_run {
                    margs.push("-p");
                }
                let dst_s = dst.to_string_lossy().into_owned();
                let base_s = base_f.to_string_lossy().into_owned();
                let their_s = their_f.to_string_lossy().into_owned();
                margs.push(&dst_s);
                margs.push(&base_s);
                margs.push(&their_s);
                let (rc, _, _) = run_cmd("git", &margs, &ctx.repo, None);
                if rc == 0 {
                    merged_clean += 1;
                } else {
                    conflicts.push(format!("{local_sub}/{rel}"));
                }
            }
            _ => {}
        }
    }

    println!(
        "  result: {} fast-forward, {} 3-way clean, {} added, {} deleted, {} already-same, {} CONFLICT(S)",
        clean_updated,
        merged_clean,
        clean_added,
        clean_deleted,
        skipped_same,
        conflicts.len()
    );
    for c in &conflicts {
        println!("  !! CONFLICT  {c}");
    }
    if !upstream_markers.is_empty() {
        println!("  !! UPSTREAM STRAY CONFLICT MARKERS ({} — committed by upstream itself!):", upstream_markers.len());
        for m in &upstream_markers {
            println!("     {m}");
        }
    }
    if conflicts.is_empty() && upstream_markers.is_empty() { 0 } else { 1 }
}

fn bare_git_bytes(bare: &Path, args: &[&str]) -> (i32, Vec<u8>, String) {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("--git-dir").arg(".").args(args).current_dir(bare);
    match cmd.output() {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            o.stdout,
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (-1, Vec::new(), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_xml_parser() {
        let xml = r#"<manifest>
  <refs>
    <image name="DISPLAY.LA.5.0.R1" project="techpack/display/manifest" server="https://x" tag="AU_087" targets="dummy"/>
  </refs>
  <project remote="clo-la" name="platform/vendor/opensource/dataipa" path="vendor/qcom/opensource/dataipa" revision="5f995860e234" upstream="refs/heads/data-kernel.lnx.4.0.r1-rel"/>
</manifest>"#;
        let m = parse_manifest_xml(xml);
        assert_eq!(m.refs["DISPLAY.LA.5.0.R1"].tag, "AU_087");
        let p = &m.projects["vendor/qcom/opensource/dataipa"];
        assert_eq!(p.revision, "5f995860e234");
        assert_eq!(p.upstream, "data-kernel.lnx.4.0.r1-rel");
    }
}
