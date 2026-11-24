use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::Path;
use std::thread;

use crate::util::*;

fn check_trailers_in_head(ctx: &Ctx, trailers: &[String], scoped: &[String]) -> Vec<String> {
    let mut notes = Vec::new();
    let mut seen = HashSet::new();
    for tr in trailers {
        let Some(ref_subj) = parse_quoted_trailer_subj(tr) else {
            continue;
        };
        if !seen.insert(ref_subj.clone()) {
            continue;
        }
        let grep_arg = format!("--grep={ref_subj}");
        let mut args = vec![
            "log",
            "-n",
            "5",
            "--fixed-strings",
            &grep_arg,
            "--format=%h%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b%x1e",
            "--date=short",
        ];
        if let Some(since) = ctx.history_since() {
            args.push(since);
        }
        args.extend(["HEAD", "--"]);
        let srefs: Vec<&str> = scoped.iter().map(|s| s.as_str()).collect();
        args.extend(srefs);
        let out = git(ctx, &args);
        let mut entries = Vec::new();
        for rec in out.split('\x1e') {
            let rec = rec.trim();
            if rec.is_empty() {
                continue;
            }
            let p: Vec<&str> = rec.splitn(5, '\x1f').collect();
            if p.len() == 5 {
                entries.push(p);
            }
        }
        if entries.is_empty() {
            notes.push(format!("!! PREREQ ABSENT in HEAD: \"{ref_subj}\""));
            continue;
        }
        if let Some(rev) = entries.iter().find(|e| e[3].starts_with("Revert ")) {
            let tag = classify_commit(rev[2], rev[3], rev[4]);
            let (why, _) = extract_why(rev[4], 120);
            notes.push(format!("!! PREREQ REVERTED in HEAD: {} ({}) [{}] {}", rev[0], rev[1], tag, rev[3]));
            if !why.is_empty() {
                notes.push(format!("     WHY: {why}"));
            }
        } else {
            let e = &entries[0];
            notes.push(format!("ok prereq in HEAD: {} ({}) {}", e[0], e[1], e[3]));
        }
    }
    notes
}

struct HunkSymCheck {
    missing: Vec<String>,
    present: Vec<String>,
}

fn check_hunk_symbols(
    ctx: &Ctx,
    path: &str,
    hunk: &ConflictHunk,
    non_theirs_lines: &[String],
    file_wo_theirs: &str,
    rel_texts: &[(String, String)],
    enclosing_start_1b: Option<usize>,
    fast_only: bool,
) -> HunkSymCheck {
    let ours_s = hunk.ours.join("\n");
    let theirs_s = hunk.theirs.join("\n");
    let fn_lo = enclosing_start_1b
        .map(|l| l.saturating_sub(1))
        .unwrap_or_else(|| hunk.start_1b.saturating_sub(41));
    let fn_hi = hunk.start_1b.saturating_sub(1).min(non_theirs_lines.len());
    let func_body = if fn_lo < fn_hi {
        non_theirs_lines[fn_lo..fn_hi].join("\n")
    } else {
        String::new()
    };

    let ours_calls: HashSet<String> = hunk.ours.iter().flat_map(|l| extract_calls(l, 3)).collect();
    let theirs_calls: BTreeSet<String> = hunk
        .theirs
        .iter()
        .flat_map(|l| extract_calls(l, 3))
        .filter(|c| !ours_calls.contains(c) && !C_KEYWORDS.contains(&c.as_str()))
        .collect();

    let ours_mems: HashSet<String> = hunk.ours.iter().flat_map(|l| extract_members(l)).collect();
    let theirs_mems: BTreeSet<String> = hunk
        .theirs
        .iter()
        .flat_map(|l| extract_members(l))
        .filter(|m| m.len() >= 3 && !ours_mems.contains(m) && !C_KEYWORDS.contains(&m.as_str()))
        .collect();

    // Check bare identifiers used inside expressions/args in theirs_s
    let ours_idents = extract_bare_idents(&ours_s);
    let theirs_idents = extract_bare_idents(&theirs_s);
    let sub_dir = Path::new(path)
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());

    let mut missing = Vec::new();
    let mut present = Vec::new();

    for c in &theirs_calls {
        if word_in_text(file_wo_theirs, c) || rel_texts.iter().any(|(_, t)| word_in_text(t, c)) {
            present.push(format!("{c}()"));
        } else if !fast_only {
            let (_, out) = rg(&ctx.repo, &["-l", "-w", c, "include", &sub_dir]);
            let hit = out.lines().find(|l| *l != path);
            if let Some(h) = hit {
                present.push(format!("{c}()@{h}"));
            } else {
                missing.push(format!("{c}()"));
            }
        } else {
            missing.push(format!("{c}()"));
        }
    }

    for m in &theirs_mems {
        if word_in_text(file_wo_theirs, m) || rel_texts.iter().any(|(_, t)| word_in_text(t, m)) {
            present.push(format!("->{m}"));
        } else if !fast_only {
            let (_, out) = rg(&ctx.repo, &["-l", "-w", m, "include", &sub_dir]);
            let hit = out.lines().find(|l| *l != path);
            if let Some(h) = hit {
                present.push(format!("->{m}@{h}"));
            } else {
                missing.push(format!("->{m}"));
            }
        } else {
            missing.push(format!("->{m}"));
        }
    }

    // Bare args: only lowercase identifiers >= 2 chars that look like variables
    for v in &theirs_idents {
        if v.len() < 2
            || ours_idents.contains(v)
            || theirs_calls.contains(v)
            || theirs_mems.contains(v)
            || C_KEYWORDS.contains(&v.as_str())
            || v.bytes().all(|c| c.is_ascii_uppercase() || c == b'_' || c.is_ascii_digit())
            || !v.as_bytes()[0].is_ascii_lowercase()
        {
            continue;
        }
        // Heuristic: skip if declared inside theirs_s (e.g. `int foo =` or `struct x *foo`)
        let mut declared_in_theirs = false;
        for ln in &hunk.theirs {
            if let Some(pos) = ln.find(v.as_str()) {
                let left = ln[..pos].trim_end();
                let right = ln[pos + v.len()..].trim_start();
                if (left.ends_with('*') || left.split_whitespace().last().map(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).unwrap_or(false))
                    && (right.starts_with('=') || right.starts_with(';') || right.starts_with(',') || right.starts_with('['))
                    && !left.ends_with("return")
                    && !left.ends_with("goto")
                    && !left.ends_with("case")
                    && !left.contains("if (")
                {
                    declared_in_theirs = true;
                    break;
                }
            }
        }
        if declared_in_theirs {
            continue;
        }
        let in_fn = word_in_text(&func_body, v);
        let in_file = word_in_text(file_wo_theirs, v);
        let in_rel = rel_texts.iter().any(|(_, t)| word_in_text(t, v));
        if !in_fn && !in_file && !in_rel {
            // Only flag bare var if used in call arg / deref / assignment RHS (avoids struct-type false positives)
            let used_as_val = theirs_s.contains(&format!("({v}"))
                || theirs_s.contains(&format!(", {v}"))
                || theirs_s.contains(&format!("&{v}"))
                || theirs_s.contains(&format!("{v}->"));
            if used_as_val {
                missing.push(format!("var:{v}"));
            }
        } else if in_file && !in_fn && enclosing_start_1b.is_some() {
            let lns: Vec<String> = non_theirs_lines
                .iter()
                .enumerate()
                .filter(|(_, l)| word_in_text(l, v))
                .take(3)
                .map(|(k, _)| (k + 1).to_string())
                .collect();
            if !lns.is_empty() {
                present.push(format!("{v}@L{}", lns.join(",")));
            }
        }
    }

    HunkSymCheck { missing, present }
}

pub fn cmd_explain(
    ctx: &Ctx,
    files: &[String],
    commit: Option<&str>,
    show_hunks: bool,
    show_patch: bool,
    summary: bool,
) -> i32 {
    let mid_merge = is_mid_merge(ctx);
    let (left_ref, right_ref, status_map, target_files): (String, String, BTreeMap<String, String>, Vec<String>) =
        if let Some(c) = commit {
            let fl = if files.is_empty() {
                git(ctx, &["diff-tree", "--no-commit-id", "--name-only", "-r", "-c", c])
                    .lines()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                files.to_vec()
            };
            (format!("{c}^1"), format!("{c}^2"), BTreeMap::new(), fl)
        } else if mid_merge {
            let pairs = unmerged_with_status(ctx);
            let smap: BTreeMap<String, String> = pairs.iter().map(|(c, p)| (p.clone(), c.clone())).collect();
            let fl = if files.is_empty() {
                pairs.into_iter().map(|(_, p)| p).collect()
            } else {
                files.to_vec()
            };
            ("HEAD".to_string(), "MERGE_HEAD".to_string(), smap, fl)
        } else {
            if files.is_empty() {
                println!("Not mid-merge. Pass -c <merge_sha> or file path(s), or use `ktool why`.");
                return 1;
            }
            ("HEAD^1".to_string(), "HEAD".to_string(), BTreeMap::new(), files.to_vec())
        };

    if target_files.is_empty() {
        println!("No conflicted files to explain.");
        return 0;
    }

    let mbase = git(ctx, &["merge-base", &left_ref, &right_ref]).trim().to_string();

    if summary {
        return run_explain_summary(ctx, &left_ref, &right_ref, &mbase, &status_map, &target_files);
    }

    // Detailed dossier per file (parallelized across files when multiple given!)
    let reports: Vec<String> = par_map(&target_files, ctx.threads.min(8), |path| {
        explain_one_file(ctx, path, &left_ref, &right_ref, &mbase, status_map.get(path), mid_merge && commit.is_none(), show_hunks, show_patch)
    });
    for rep in reports {
        print!("{rep}");
    }
    0
}

fn run_explain_summary(
    ctx: &Ctx,
    left_ref: &str,
    right_ref: &str,
    mbase: &str,
    status_map: &BTreeMap<String, String>,
    files: &[String],
) -> i32 {
    let range_in = format!("{left_ref}..{right_ref}");
    let range_loc = if mbase.is_empty() {
        String::new()
    } else {
        format!("{mbase}..{left_ref}")
    };

    // 3 batched single-pass git log calls IN PARALLEL (<1s total for 61+ files!)
    let (in_map, loc_map, rev_map) = thread::scope(|s| {
        let h_in = s.spawn(|| {
            let mut args = vec![
                "log", "--no-merges", "--name-only",
                "--format=@@@%h%x1f%s",
                &range_in, "--",
            ];
            args.extend(files.iter().map(|f| f.as_str()));
            parse_batched_name_only(&git(ctx, &args))
        });
        let h_loc = s.spawn(|| {
            if range_loc.is_empty() {
                return BTreeMap::new();
            }
            let mut args = vec![
                "log", "--no-merges", "--name-only",
                "--format=@@@%s",
                &range_loc, "--",
            ];
            args.extend(files.iter().map(|f| f.as_str()));
            parse_batched_name_only(&git(ctx, &args))
        });
        let h_rev = s.spawn(|| {
            let mut args = vec![
                "log", "--grep=^Revert ", "-i", "--name-only",
                "--format=@@@%h%x1f%s",
            ];
            if let Some(since) = ctx.history_since() {
                args.push(since);
            }
            args.extend([left_ref, "--"]);
            args.extend(files.iter().map(|f| f.as_str()));
            parse_batched_name_only(&git(ctx, &args))
        });
        (h_in.join().unwrap(), h_loc.join().unwrap(), h_rev.join().unwrap())
    });

    // Scan working-tree hunks + fast missing-symbol count in parallel across 16 cores (~5ms)
    struct Row {
        built: bool,
        code: String,
        nhunks: usize,
        nin: usize,
        dups: usize,
        has_rev: bool,
        miss_cnt: usize,
        path: String,
        first_s: String,
    }

    let mut rows: Vec<Row> = par_map(files, ctx.threads, |path| {
        let built = is_built_file(ctx, path);
        let code = status_map.get(path).cloned().unwrap_or_else(|| "UU".to_string());
        let (nhunks, miss_cnt) = match fs::read_to_string(ctx.repo.join(path)) {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().collect();
                let hunks = parse_conflict_hunks(&lines);
                let nh = hunks.len();
                let mut mc = 0usize;
                if nh > 0 && is_c_source(path) {
                    let mut non_t: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
                    for h in &hunks {
                        for k in (h.sep_1b - 1)..h.end_1b.min(non_t.len()) {
                            non_t[k].clear();
                        }
                    }
                    let fwo = non_t.join("\n");
                    let rel_texts: Vec<(String, String)> = related_files(ctx, path)
                        .into_iter()
                        .filter_map(|rf| fs::read_to_string(ctx.repo.join(&rf)).ok().map(|t| (rf, t)))
                        .collect();
                    for h in &hunks {
                        let enc = find_enclosing_func(&lines, h.start_1b - 1).map(|(l, _)| l);
                        let chk = check_hunk_symbols(ctx, path, h, &non_t, &fwo, &rel_texts, enc, true);
                        mc += chk.missing.len();
                    }
                }
                (nh, mc)
            }
            Err(_) => (0, 0),
        };
        let in_recs = in_map.get(path).cloned().unwrap_or_default();
        let in_subjs: Vec<&str> = in_recs
            .iter()
            .filter_map(|r| r.split_once('\x1f').map(|(_, s)| s))
            .collect();
        let loc_subjs: HashSet<String> = loc_map
            .get(path)
            .map(|v| v.iter().map(|s| norm_subj(s)).collect())
            .unwrap_or_default();
        let dups = in_subjs.iter().filter(|s| loc_subjs.contains(&norm_subj(s))).count();
        let has_rev = rev_map.contains_key(path);
        let first_s = in_subjs.first().copied().unwrap_or("(none)").to_string();
        Row {
            built,
            code,
            nhunks,
            nin: in_subjs.len(),
            dups,
            has_rev,
            miss_cnt,
            path: path.clone(),
            first_s,
        }
    });

    rows.sort_by(|a, b| b.built.cmp(&a.built).then(a.path.cmp(&b.path)));
    let n_built = rows.iter().filter(|r| r.built).count();
    let n_dup = rows.iter().filter(|r| r.nin > 0 && r.dups == r.nin).count();
    println!(
        "=== EXPLAIN SUMMARY ({} files: {} [BUILT], {} [unbuilt], {} ALL-DUP | {}..{}) ===",
        rows.len(),
        n_built,
        rows.len() - n_built,
        n_dup,
        left_ref,
        right_ref
    );
    for r in &rows {
        let btag = if r.built { "[BUILT]" } else { "[unbuilt]" };
        let mut flags = Vec::new();
        if r.code != "UU" {
            flags.push(format!("GIT:{}", r.code));
        }
        if r.nin > 0 && r.dups == r.nin {
            flags.push("ALL-DUP".to_string());
        } else if r.dups > 0 {
            flags.push(format!("DUP:{}/{}", r.dups, r.nin));
        }
        if r.has_rev {
            flags.push("HAS-REV".to_string());
        }
        if r.miss_cnt > 0 {
            flags.push(format!("MISS:{}", r.miss_cnt));
        }
        let ftxt = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(" "))
        };
        println!(
            "  {btag:<9} h={:<2} in={:<2} {:<48}{ftxt} | {}",
            r.nhunks,
            r.nin,
            r.path,
            truncate_str(&r.first_s, 62)
        );
    }
    0
}

#[allow(clippy::too_many_arguments)]
fn explain_one_file(
    ctx: &Ctx,
    path: &str,
    left_ref: &str,
    right_ref: &str,
    mbase: &str,
    status_code: Option<&String>,
    mid_merge: bool,
    show_hunks: bool,
    show_patch: bool,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let btag = if is_built_file(ctx, path) { "[BUILT]" } else { "[unbuilt]" };
    let st = status_code.map(|s| format!(" ({s})")).unwrap_or_default();
    let _ = writeln!(out, "================ {btag}{st} {path} ================");

    let rel = related_files(ctx, path);
    let mut scoped = vec![path.to_string()];
    scoped.extend(rel.iter().cloned());
    if !rel.is_empty() {
        let _ = writeln!(out, "  related: {}", rel.iter().take(6).cloned().collect::<Vec<_>>().join(", "));
    }

    // 1. Incoming commits
    let range_in = format!("{left_ref}..{right_ref}");
    let in_shas: Vec<String> = git(ctx, &["rev-list", "--no-merges", &range_in, "--", path])
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let mut all_trailers = Vec::new();
    let _ = writeln!(out, "  INCOMING ({} commit(s)):", in_shas.len());
    for sha in in_shas.iter().take(8) {
        if let Some(meta) = commit_meta(ctx, sha) {
            let (why, tr) = extract_why(&meta.body, 145);
            all_trailers.extend(tr.iter().cloned());
            let _ = writeln!(out, "    + {} ({}) {}", &meta.sha[..12.min(meta.sha.len())], meta.date, meta.subj);
            if !why.is_empty() {
                let _ = writeln!(out, "      WHY: {why}");
            }
            for t in tr.iter().take(3) {
                let _ = writeln!(out, "      {t}");
            }
        }
    }
    for note in check_trailers_in_head(ctx, &all_trailers, &scoped) {
        let _ = writeln!(out, "    {note}");
    }

    // 2. Local HEAD divergence
    let loc_shas: Vec<String> = if mbase.is_empty() {
        Vec::new()
    } else {
        let r = format!("{mbase}..{left_ref}");
        git(ctx, &["rev-list", "--no-merges", "-n", "12", &r, "--", path])
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    };
    let _ = writeln!(out, "  LOCAL HEAD DIVERGENCE ({} commit(s) since merge-base):", loc_shas.len());
    for sha in loc_shas.iter().take(6) {
        if let Some(meta) = commit_meta(ctx, sha) {
            let (why, _) = extract_why(&meta.body, 125);
            let _ = writeln!(
                out,
                "    * {} ({}) [{}] {}",
                &meta.sha[..12.min(meta.sha.len())],
                meta.date,
                meta.tag,
                meta.subj
            );
            if meta.tag != "UPSTREAM" && !why.is_empty() {
                let _ = writeln!(out, "      WHY: {why}");
            }
        }
    }

    // Reverts in HEAD history on file + related headers (bounded to 6.6 era so it's instant!)
    let mut rev_args = vec![
        "log", "-n", "5", "--grep=^Revert ", "-i",
        "--format=%h%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b%x1e",
        "--date=short",
    ];
    if let Some(since) = ctx.history_since() {
        rev_args.push(since);
    }
    rev_args.extend([left_ref, "--"]);
    let srefs: Vec<&str> = scoped.iter().map(|s| s.as_str()).collect();
    rev_args.extend(srefs);
    let rev_out = git(ctx, &rev_args);
    let rev_recs: Vec<Vec<&str>> = rev_out
        .split('\x1e')
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(|r| r.splitn(5, '\x1f').collect::<Vec<_>>())
        .filter(|p| p.len() == 5)
        .collect();
    if !rev_recs.is_empty() {
        let _ = writeln!(out, "  REVERTS IN HEAD HISTORY ({path} + related headers):");
        for p in rev_recs.iter().take(4) {
            let tag = classify_commit(p[2], p[3], p[4]);
            let (why, _) = extract_why(p[4], 125);
            let _ = writeln!(out, "    ! {} ({}) [{}] {}", p[0], p[1], tag, p[3]);
            if !why.is_empty() {
                let _ = writeln!(out, "      WHY: {why}");
            }
        }
    }

    // 3. Upstream 3-way intent (:1: vs :3:) when mid-merge!
    if mid_merge && show_patch {
        let s1 = format!(":1:{path}");
        let s3 = format!(":3:{path}");
        let (rc, diff_in, _) = git_rc(ctx, &["diff", "--no-color", &s1, &s3]);
        if rc == 0 && !diff_in.trim().is_empty() {
            let dlines: Vec<&str> = diff_in.lines().collect();
            let _ = writeln!(out, "  UPSTREAM INTENT (git diff :1: :3:, {} lines):", dlines.len());
            for ln in dlines.iter().take(55) {
                let _ = writeln!(out, "    {ln}");
            }
            if dlines.len() > 55 {
                let _ = writeln!(out, "    ... (+{} more lines)", dlines.len() - 55);
            }
        } else if let Some(code) = status_code {
            if code != "UU" {
                let _ = writeln!(out, "  TREE CONFLICT ({code}): check deleted/added side (`git show :1/:2/:3:{path}`)");
            }
        }
    }

    // 4. Conflict hunks + symbol check
    if let Ok(text) = fs::read_to_string(ctx.repo.join(path)) {
        let lines: Vec<&str> = text.lines().collect();
        let hunks = parse_conflict_hunks(&lines);
        if !hunks.is_empty() {
            let mut non_t: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
            for h in &hunks {
                for k in (h.sep_1b - 1)..h.end_1b.min(non_t.len()) {
                    non_t[k].clear();
                }
            }
            let fwo = non_t.join("\n");
            let rel_texts: Vec<(String, String)> = rel
                .iter()
                .filter_map(|rf| fs::read_to_string(ctx.repo.join(rf)).ok().map(|t| (rf.clone(), t)))
                .collect();

            let _ = writeln!(out, "  CONFLICT HUNKS ({}):", hunks.len());
            for (idx, h) in hunks.iter().enumerate() {
                let enc = find_enclosing_func(&lines, h.start_1b - 1);
                let fdesc = match &enc {
                    Some((fl, hdr)) => format!("in `{hdr}` (L{fl})"),
                    None => "(top-level)".to_string(),
                };
                let _ = writeln!(out, "    --- hunk #{} L{}-L{} {fdesc} ---", idx + 1, h.start_1b, h.end_1b);
                if is_c_source(path) {
                    let chk = check_hunk_symbols(
                        ctx,
                        path,
                        h,
                        &non_t,
                        &fwo,
                        &rel_texts,
                        enc.map(|(l, _)| l),
                        false,
                    );
                    if !chk.missing.is_empty() {
                        let _ = writeln!(out, "      !! MISSING SYMBOLS: {}", chk.missing.join(", "));
                    }
                    if !chk.present.is_empty() {
                        let _ = writeln!(
                            out,
                            "      ok symbols: {}",
                            chk.present.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
                        );
                    }
                }
                if show_hunks {
                    let c_start = h.start_1b.saturating_sub(3);
                    let c_end = (h.end_1b + 2).min(lines.len());
                    for k in c_start..c_end {
                        let _ = writeln!(out, "      {:5}| {}", k + 1, lines[k]);
                    }
                }
            }
        }
    }
    let _ = writeln!(out);
    out
}

/// Fast 16-core 3-way duplicate / already-in-HEAD detector for all unmerged files!
pub fn cmd_dup_check(ctx: &Ctx, files: &[String]) -> i32 {
    if !is_mid_merge(ctx) {
        println!("Not mid-merge.");
        return 1;
    }
    let pairs = unmerged_with_status(ctx);
    let targets: Vec<(String, String)> = if files.is_empty() {
        pairs
    } else {
        let want: HashSet<&str> = files.iter().map(|s| s.as_str()).collect();
        pairs.into_iter().filter(|(_, p)| want.contains(p.as_str())).collect()
    };
    if targets.is_empty() {
        println!("No unmerged files.");
        return 0;
    }

    struct Res {
        built: bool,
        verdict: &'static str,
        code: String,
        up_delta: String,
        our_delta: String,
        path: String,
    }

    let tmp_dir = std::env::temp_dir().join(format!("ktool-dup-{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);

    let results: Vec<Res> = par_map(&targets, ctx.threads, |(code, path)| {
        let built = is_built_file(ctx, path);
        if code != "UU" {
            return Res {
                built,
                verdict: "TREE-CONFLICT",
                code: code.clone(),
                up_delta: "-".into(),
                our_delta: "-".into(),
                path: path.clone(),
            };
        }
        let s1 = format!(":1:{path}");
        let s2 = format!(":2:{path}");
        let s3 = format!(":3:{path}");
        let (r_up, patch_up, _) = git_rc(ctx, &["diff", "--no-color", &s1, &s3]);
        let (_, patch_ours, _) = git_rc(ctx, &["diff", "--no-color", &s1, &s2]);
        let (_, diff_23, _) = git_rc(ctx, &["diff", "--quiet", &s2, &s3]);
        let up_delta = count_diff_pm(&patch_up);
        let our_delta = count_diff_pm(&patch_ours);

        if git_rc(ctx, &["diff", "--quiet", &s2, &s3]).0 == 0 && diff_23.is_empty() {
            return Res { built, verdict: "IDENTICAL", code: code.clone(), up_delta, our_delta, path: path.clone() };
        }
        if r_up != 0 || patch_up.trim().is_empty() {
            return Res { built, verdict: "NO-UP-CHANGE", code: code.clone(), up_delta, our_delta, path: path.clone() };
        }

        // Write :2:<path> to isolated temp file and test `git apply --check --reverse -C1`
        let safe = path.replace('/', "__");
        let work = tmp_dir.join(&safe);
        let target_in_work = work.join(path);
        if let Some(par) = target_in_work.parent() {
            let _ = fs::create_dir_all(par);
        }
        let (_, ours_blob, _) = git_rc(ctx, &["show", &s2]);
        if fs::write(&target_in_work, ours_blob.as_bytes()).is_ok() {
            // Rewrite diff header paths to match `path`
            let fixed_patch = rewrite_stage_diff(&patch_up, path);
            let (rc_rev, _, _) = run_cmd("git", &["apply", "--check", "--reverse", "-C1"], &work, Some(fixed_patch.as_bytes()));
            let _ = fs::remove_dir_all(&work);
            if rc_rev == 0 {
                return Res {
                    built,
                    verdict: "ALREADY-IN-HEAD",
                    code: code.clone(),
                    up_delta,
                    our_delta,
                    path: path.clone(),
                };
            }
            // Check if upstream patch applies cleanly with -C1 onto HEAD (only context overlap!)
            let _ = fs::create_dir_all(target_in_work.parent().unwrap());
            let _ = fs::write(&target_in_work, ours_blob.as_bytes());
            let (rc_fwd, _, _) = run_cmd("git", &["apply", "--check", "-C1"], &work, Some(fixed_patch.as_bytes()));
            let _ = fs::remove_dir_all(&work);
            if rc_fwd == 0 {
                return Res {
                    built,
                    verdict: "CONTEXT-ONLY",
                    code: code.clone(),
                    up_delta,
                    our_delta,
                    path: path.clone(),
                };
            }
        }
        Res { built, verdict: "REAL-CONFLICT", code: code.clone(), up_delta, our_delta, path: path.clone() }
    });
    let _ = fs::remove_dir_all(&tmp_dir);

    let mut sorted = results;
    sorted.sort_by(|a, b| {
        let rank = |v: &str| match v {
            "ALREADY-IN-HEAD" | "IDENTICAL" | "NO-UP-CHANGE" => 0,
            "CONTEXT-ONLY" => 1,
            "TREE-CONFLICT" => 2,
            _ => 3,
        };
        rank(a.verdict)
            .cmp(&rank(b.verdict))
            .then(b.built.cmp(&a.built))
            .then(a.path.cmp(&b.path))
    });

    println!("=== DUP-CHECK ({} unmerged files) ===", sorted.len());
    for r in &sorted {
        let btag = if r.built { "[BUILT]" } else { "[unbuilt]" };
        println!(
            "  {:<15} {btag:<9} ({}) up {:<10} head {:<10} {}",
            r.verdict, r.code, r.up_delta, r.our_delta, r.path
        );
    }
    0
}

fn count_diff_pm(diff: &str) -> String {
    let mut a = 0usize;
    let mut d = 0usize;
    for l in diff.lines() {
        if l.starts_with('+') && !l.starts_with("+++") {
            a += 1;
        } else if l.starts_with('-') && !l.starts_with("---") {
            d += 1;
        }
    }
    format!("+{a}/-{d}")
}

fn rewrite_stage_diff(diff: &str, path: &str) -> String {
    let mut out = String::with_capacity(diff.len() + 64);
    for ln in diff.lines() {
        if ln.starts_with("diff --git ") {
            out.push_str(&format!("diff --git a/{path} b/{path}\n"));
        } else if ln.starts_with("--- ") {
            out.push_str(&format!("--- a/{path}\n"));
        } else if ln.starts_with("+++ ") {
            out.push_str(&format!("+++ b/{path}\n"));
        } else {
            out.push_str(ln);
            out.push('\n');
        }
    }
    out
}
