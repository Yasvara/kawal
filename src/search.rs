use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::thread;

use crate::util::*;

/// Parse `file:L` or `file:L1-L2`
fn parse_file_loc(ctx: &Ctx, q: &str) -> Option<(String, usize, usize)> {
    let (fpath, rest) = q.rsplit_once(':')?;
    if !ctx.repo.join(fpath).is_file() {
        return None;
    }
    if let Some((a, b)) = rest.split_once('-') {
        let l1 = a.parse::<usize>().ok()?;
        let l2 = b.parse::<usize>().ok()?;
        Some((fpath.to_string(), l1, l2))
    } else {
        let l1 = rest.parse::<usize>().ok()?;
        Some((fpath.to_string(), l1, l1))
    }
}

pub fn cmd_why(ctx: &Ctx, query: &str, paths: &[String], limit: usize) -> i32 {
    // Mode A: file:line[-end]
    if let Some((fpath, l1, l2)) = parse_file_loc(ctx, query) {
        println!("=== WHY {fpath}:{l1}-{l2} (line history) ===");
        let lim = limit.to_string();
        let lspec = format!("{l1},{l2}:{fpath}");
        let out = git(
            ctx,
            &[
                "log", "-n", &lim, "-s",
                "--format=@@@%H%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b",
                "--date=short", "-L", &lspec,
            ],
        );
        for rec in out.split("@@@") {
            let rec = rec.trim();
            if rec.is_empty() {
                continue;
            }
            let p: Vec<&str> = rec.splitn(5, '\x1f').collect();
            if p.len() < 5 {
                continue;
            }
            let tag = classify_commit(p[2], p[3], p[4]);
            let (why, tr) = extract_why(p[4], 165);
            println!("  {} ({}) [{}] {}", &p[0][..12.min(p[0].len())], p[1], tag, p[3]);
            if !why.is_empty() {
                println!("    WHY: {why}");
            }
            for t in tr.iter().take(2) {
                println!("    {t}");
            }
        }
        return 0;
    }

    // Mode B: Commit SHA / tag / ref
    let looks_rev = paths.is_empty()
        && query.len() >= 7
        && query.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'_' | b'~' | b'^' | b'-'));
    if looks_rev {
        let rev_spec = format!("{query}^{{commit}}");
        let (rc, sha_out, _) = git_rc(ctx, &["rev-parse", "--verify", "--quiet", &rev_spec]);
        if rc == 0 {
            let sha = sha_out.trim();
            if let Some(meta) = commit_meta(ctx, sha) {
                let (why, tr) = extract_why(&meta.body, 240);
                let in_head = git_rc(ctx, &["merge-base", "--is-ancestor", sha, "HEAD"]).0 == 0;
                let files: Vec<String> = git(ctx, &["diff-tree", "--no-commit-id", "--name-only", "-r", sha])
                    .lines()
                    .map(|s| s.to_string())
                    .collect();
                println!("=== WHY COMMIT {} [{}] ===", &sha[..12.min(sha.len())], meta.tag);
                println!("  Subject : {}", meta.subj);
                println!("  Author  : {} ({})", meta.author, meta.date);
                println!("  In HEAD : {}", if in_head { "YES (ancestor)" } else { "NO (not direct ancestor)" });
                if !why.is_empty() {
                    println!("  WHY     : {why}");
                }
                for t in tr.iter().take(4) {
                    println!("  Trailer : {t}");
                }
                let fpreview: Vec<&str> = files.iter().take(8).map(|s| s.as_str()).collect();
                println!(
                    "  Files({}): {}{}",
                    files.len(),
                    fpreview.join(", "),
                    if files.len() > 8 { " ..." } else { "" }
                );

                // Parallel: merged-by / subject-match + follow-up/reverts
                let scope_files: Vec<&str> = files.iter().take(10).map(|s| s.as_str()).collect();
                let (m_info, followups) = thread::scope(|s| {
                    let h1 = s.spawn(|| {
                        if in_head {
                            let rng = format!("{sha}..HEAD");
                            let m = git(ctx, &["log", "--ancestry-path", "--merges", "--reverse", "--format=%h (%ad) %s", "--date=short", &rng]);
                            ("Merged  ", m.lines().take(2).map(|l| l.to_string()).collect::<Vec<_>>())
                        } else {
                            let gp = format!("--grep={}", meta.subj);
                            let mut a = vec!["log", "-n", "5", "--fixed-strings", &gp, "--format=%h (%ad) %s", "--date=short", "HEAD", "--"];
                            a.extend(scope_files.iter().copied());
                            ("SubjHit ", git(ctx, &a).lines().map(|l| l.to_string()).collect())
                        }
                    });
                    let h2 = s.spawn(|| {
                        if scope_files.is_empty() {
                            return Vec::new();
                        }
                        let g1 = format!("--grep={}", &sha[..12.min(sha.len())]);
                        let g2 = format!("--grep=Revert \"{}\"", meta.subj);
                        let mut a1 = vec!["log", "-n", "6", "--fixed-strings", &g1, "--format=%h%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b%x1e", "--date=short", "HEAD", "--"];
                        a1.extend(scope_files.iter().copied());
                        let mut a2 = vec!["log", "-n", "6", "--fixed-strings", &g2, "--format=%h%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b%x1e", "--date=short", "HEAD", "--"];
                        a2.extend(scope_files.iter().copied());
                        let combined = format!("{}\x1e{}", git(ctx, &a1), git(ctx, &a2));
                        let mut seen = HashSet::new();
                        let mut out = Vec::new();
                        for blk in combined.split('\x1e') {
                            let blk = blk.trim();
                            if blk.is_empty() {
                                continue;
                            }
                            let p: Vec<&str> = blk.splitn(5, '\x1f').collect();
                            if p.len() < 5 || p[0].starts_with(&sha[..10.min(sha.len())]) || !seen.insert(p[0].to_string()) {
                                continue;
                            }
                            let ftag = classify_commit(p[2], p[3], p[4]);
                            let (fwhy, _) = extract_why(p[4], 140);
                            out.push((p[0].to_string(), p[1].to_string(), ftag, p[3].to_string(), fwhy));
                        }
                        out
                    });
                    (h1.join().unwrap(), h2.join().unwrap())
                });

                for ln in m_info.1 {
                    println!("  {}: {ln}", m_info.0);
                }
                for (fsha, fdate, ftag, fsubj, fwhy) in followups {
                    println!("  FOLLOW-UP/REVERT: {fsha} ({fdate}) [{ftag}] {fsubj}");
                    if !fwhy.is_empty() {
                        println!("    WHY: {fwhy}");
                    }
                }
                return 0;
            }
        }
    }

    // Mode C: Symbol / string / subject query — run rg + git log -S + git log --grep IN PARALLEL!
    let scope_desc = if paths.is_empty() {
        " (whole repo)".to_string()
    } else {
        format!(" in {}", paths.join(", "))
    };
    println!("=== WHY '{query}'{scope_desc} ===");

    let (rg_hits, pickaxe_out, msg_out) = thread::scope(|s| {
        let h_rg = s.spawn(|| {
            let mut args = vec!["-n", "-F", "--max-count", "3", query];
            args.extend(paths.iter().map(|p| p.as_str()));
            rg(&ctx.repo, &args).1
        });
        let h_s = s.spawn(|| {
            let lim = limit.to_string();
            let mut args = vec![
                "log", "-n", &lim, "-S", query,
                "--format=@@@%H%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b",
                "--date=short", "-p",
            ];
            if !paths.is_empty() {
                args.push("--");
                args.extend(paths.iter().map(|p| p.as_str()));
            }
            git(ctx, &args)
        });
        let h_g = s.spawn(|| {
            let gp = format!("--grep={query}");
            let mut args = vec![
                "log", "-n", "6", "--fixed-strings", &gp,
                "--format=%h%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b%x1e",
                "--date=short",
            ];
            if !paths.is_empty() {
                args.push("--");
                args.extend(paths.iter().map(|p| p.as_str()));
            }
            git(ctx, &args)
        });
        (h_rg.join().unwrap(), h_s.join().unwrap(), h_g.join().unwrap())
    });

    // 1. Current tree hits with enclosing function
    let rg_lines: Vec<&str> = rg_hits.lines().filter(|l| !l.is_empty()).collect();
    println!("  CURRENT TREE: {} match(es){}", rg_lines.len(), if rg_lines.len() >= 8 { " (showing 8)" } else { "" });
    let mut fcache: HashMap<String, Vec<String>> = HashMap::new();
    for ln in rg_lines.iter().take(8) {
        let parts: Vec<&str> = ln.splitn(3, ':').collect();
        if parts.len() == 3 {
            let (f, lno_s, code) = (parts[0], parts[1], parts[2].trim());
            let lno = lno_s.parse::<usize>().unwrap_or(1);
            let fn_tag = enclosing_for_file(ctx, f, lno, &mut fcache)
                .map(|h| format!("   [{}]", truncate_str(&h, 60)))
                .unwrap_or_default();
            println!("    {f}:{lno_s}: {}{fn_tag}", truncate_str(code, 95));
        } else {
            println!("    {}", truncate_str(ln, 120));
        }
    }

    // 2. Pickaxe timeline (-S)
    let recs: Vec<&str> = pickaxe_out.split("@@@").filter(|r| !r.trim().is_empty()).collect();
    let mut seen_shas = HashSet::new();
    println!("  GIT HISTORY (-S, latest {}):", recs.len());
    for rec in recs {
        let p: Vec<&str> = rec.splitn(5, '\x1f').collect();
        if p.len() < 5 {
            continue;
        }
        let (sha, date, author, subj, rest) = (p[0].trim(), p[1].trim(), p[2].trim(), p[3].trim(), p[4]);
        seen_shas.insert(sha[..12.min(sha.len())].to_string());
        let (body, diff) = match rest.find("\ndiff --git ") {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        let mut added = false;
        let mut removed = false;
        let mut tfiles = Vec::new();
        for dl in diff.lines() {
            if let Some(f) = dl.strip_prefix("+++ b/") {
                tfiles.push(f);
            } else if dl.starts_with('+') && !dl.starts_with("+++") && dl.contains(query) {
                added = true;
            } else if dl.starts_with('-') && !dl.starts_with("---") && dl.contains(query) {
                removed = true;
            }
        }
        let op = if subj.starts_with("Revert ") {
            "REVERTED"
        } else if added && removed {
            "MODIFIED"
        } else if added {
            "ADDED   "
        } else {
            "REMOVED "
        };
        let tag = classify_commit(author, subj, body);
        let (why, tr) = extract_why(body, 135);
        println!("    {op} {} ({date}) [{tag:<11}] {subj}", &sha[..12.min(sha.len())]);
        if !tfiles.is_empty() {
            let fp: Vec<&str> = tfiles.into_iter().take(5).collect();
            println!("             files: {}", fp.join(", "));
        }
        if !why.is_empty() {
            println!("             WHY: {why}");
        }
        for t in tr.iter().take(2) {
            println!("             {t}");
        }
    }

    // 3. Commit messages mentioning query
    let extra: Vec<Vec<&str>> = msg_out
        .split('\x1e')
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(|r| r.splitn(5, '\x1f').collect::<Vec<_>>())
        .filter(|p| p.len() == 5 && !seen_shas.contains(&p[0][..12.min(p[0].len())]))
        .collect();
    if !extra.is_empty() {
        println!("  COMMIT MESSAGES MENTIONING '{query}':");
        for p in extra.iter().take(5) {
            let tag = classify_commit(p[2], p[3], p[4]);
            let (why, _) = extract_why(p[4], 125);
            println!("    MSG      {} ({}) [{tag:<11}] {}", p[0], p[1], p[3]);
            if !why.is_empty() {
                println!("             WHY: {why}");
            }
        }
    }
    0
}

fn enclosing_for_file(
    ctx: &Ctx,
    rel_path: &str,
    line_1b: usize,
    cache: &mut HashMap<String, Vec<String>>,
) -> Option<String> {
    if !cache.contains_key(rel_path) {
        let lines = fs::read_to_string(ctx.repo.join(rel_path))
            .ok()
            .map(|s| s.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();
        cache.insert(rel_path.to_string(), lines);
    }
    let lines = cache.get(rel_path)?;
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    find_enclosing_func(&refs, line_1b.saturating_sub(1)).map(|(_, h)| h)
}

pub fn cmd_flow(ctx: &Ctx, symbol: &str, paths: &[String], show_struct: bool) -> i32 {
    println!("=== FLOW {symbol} ===");

    // Regex for definitions: C struct/union/enum, #define, C func def/proto, or Java/Kotlin class/interface/fun
    let def_re = if ctx.is_default_kernel || paths.iter().any(|p| p.ends_with(".c") || p.ends_with(".h")) {
        format!(
            r"(^[ \t]*(struct|union|enum)[ \t]+{s}[ \t]*\{{)|(^[ \t]*#[ \t]*define[ \t]+{s}\b)|(^([A-Za-z_][A-Za-z0-9_ \t\*]*[ \t\*])?{s}[ \t]*\()",
            s = symbol
        )
    } else {
        format!(
            r"(^[ \t]*(struct|union|enum|class|interface|object)[ \t]+{s}\b)|(^[ \t]*#[ \t]*define[ \t]+{s}\b)|(\b(fun|void|int|long|bool|boolean|static|public|private|protected)\b.*{s}[ \t]*\()",
            s = symbol
        )
    };

    let scan_modules = ctx.is_default_kernel && ctx.modules.is_dir() && paths.is_empty();

    // Run definition search, repo references, and modules references IN PARALLEL via rg (SIMD Rust!)
    let (defs_out, refs_out, mod_out) = thread::scope(|s| {
        let h_def = s.spawn(|| {
            let mut a = vec!["-n", "-e", &def_re];
            if ctx.is_default_kernel && paths.is_empty() {
                a.extend(["-g", "*.c", "-g", "*.h"]);
            }
            a.extend(paths.iter().map(|p| p.as_str()));
            rg(&ctx.repo, &a).1
        });
        let h_ref = s.spawn(|| {
            let mut a = vec!["-n", "-w", symbol];
            if ctx.is_default_kernel && paths.is_empty() {
                a.extend(["-g", "*.c", "-g", "*.h"]);
            }
            a.extend(paths.iter().map(|p| p.as_str()));
            rg(&ctx.repo, &a).1
        });
        let h_mod = s.spawn(|| {
            if !scan_modules {
                return String::new();
            }
            rg(&ctx.modules, &["-n", "-w", "-g", "*.c", "-g", "*.h", symbol]).1
        });
        (h_def.join().unwrap(), h_ref.join().unwrap(), h_mod.join().unwrap())
    });

    // 1. Definitions
    let defs: Vec<&str> = defs_out
        .lines()
        .filter(|l| !l.is_empty())
        .filter(|l| !IGNORED_PREFIXES.iter().any(|p| l.starts_with(p)))
        .collect();
    println!("  DEFINITIONS ({}):", defs.len());
    let mut struct_shown = false;
    for d in defs.iter().take(15) {
        let parts: Vec<&str> = d.splitn(3, ':').collect();
        if parts.len() < 3 {
            continue;
        }
        let (f, lno_s, code) = (parts[0], parts[1], parts[2].trim());
        let b = if is_built_file(ctx, f) { "[BUILT]" } else { "[unbuilt]" };
        println!("    {b:<9} {f}:{lno_s}: {code}");
        if show_struct
            && !struct_shown
            && (code.contains(&format!("struct {symbol} {{"))
                || code.contains(&format!("enum {symbol} {{"))
                || code.contains(&format!("union {symbol} {{")))
        {
            struct_shown = true;
            if let Ok(text) = fs::read_to_string(ctx.repo.join(f)) {
                let all_l: Vec<&str> = text.lines().collect();
                let idx = lno_s.parse::<usize>().unwrap_or(1).saturating_sub(1);
                let mut depth = 0i32;
                let mut printed = 0usize;
                for (k, line) in all_l.iter().enumerate().skip(idx).take(65) {
                    depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
                    println!("      {:5}| {line}", k + 1);
                    printed += 1;
                    if depth <= 0 && k > idx {
                        break;
                    }
                }
                if depth > 0 {
                    println!("      ... (truncated after {printed} lines)");
                }
            }
        }
    }

    // 2. References grouped by [BUILT], [MOD], [unbuilt]
    let mut built_refs = Vec::new();
    let mut unbuilt_refs = Vec::new();
    let mut mod_refs = Vec::new();

    for ln in refs_out.lines() {
        let parts: Vec<&str> = ln.splitn(3, ':').collect();
        if parts.len() < 3 {
            continue;
        }
        let (f, lno_s, code) = (parts[0], parts[1], parts[2].trim());
        if IGNORED_PREFIXES.iter().any(|p| f.starts_with(p)) {
            continue;
        }
        let item = (f.to_string(), lno_s.to_string(), code.to_string());
        if is_built_file(ctx, f) {
            built_refs.push(item);
        } else {
            unbuilt_refs.push(item);
        }
    }
    for ln in mod_out.lines() {
        let parts: Vec<&str> = ln.splitn(3, ':').collect();
        if parts.len() == 3 {
            mod_refs.push((parts[0].to_string(), parts[1].to_string(), parts[2].trim().to_string()));
        }
    }

    println!(
        "  REFERENCES: {} [BUILT], {} [MOD], {} [unbuilt]",
        built_refs.len(),
        mod_refs.len(),
        unbuilt_refs.len()
    );

    let mut fcache: HashMap<String, Vec<String>> = HashMap::new();
    let mut mcache: HashMap<String, Vec<String>> = HashMap::new();

    for (f, lno_s, code) in built_refs.iter().take(25) {
        let lno = lno_s.parse::<usize>().unwrap_or(1);
        let fn_tag = enclosing_for_file(ctx, f, lno, &mut fcache)
            .map(|h| format!("  in `{}`", truncate_str(&h, 60)))
            .unwrap_or_default();
        println!("    [BUILT]   {f}:{lno_s}: {}{fn_tag}", truncate_str(code, 90));
    }
    if built_refs.len() > 25 {
        println!("    ... +{} more [BUILT] hit(s)", built_refs.len() - 25);
    }

    for (f, lno_s, code) in mod_refs.iter().take(15) {
        let lno = lno_s.parse::<usize>().unwrap_or(1);
        let fn_tag = enclosing_for_dir(&ctx.modules, f, lno, &mut mcache)
            .map(|h| format!("  in `{}`", truncate_str(&h, 60)))
            .unwrap_or_default();
        println!("    [MOD]     modules/{f}:{lno_s}: {}{fn_tag}", truncate_str(code, 90));
    }
    if mod_refs.len() > 15 {
        println!("    ... +{} more [MOD] hit(s)", mod_refs.len() - 15);
    }

    for (f, lno_s, code) in unbuilt_refs.iter().take(10) {
        let lno = lno_s.parse::<usize>().unwrap_or(1);
        let fn_tag = enclosing_for_file(ctx, f, lno, &mut fcache)
            .map(|h| format!("  in `{}`", truncate_str(&h, 60)))
            .unwrap_or_default();
        println!("    [unbuilt] {f}:{lno_s}: {}{fn_tag}", truncate_str(code, 90));
    }
    if unbuilt_refs.len() > 10 {
        println!("    ... +{} more [unbuilt] hit(s)", unbuilt_refs.len() - 10);
    }
    0
}

fn enclosing_for_dir(
    root: &Path,
    rel_path: &str,
    line_1b: usize,
    cache: &mut HashMap<String, Vec<String>>,
) -> Option<String> {
    if !cache.contains_key(rel_path) {
        let lines = fs::read_to_string(root.join(rel_path))
            .ok()
            .map(|s| s.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();
        cache.insert(rel_path.to_string(), lines);
    }
    let lines = cache.get(rel_path)?;
    let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
    find_enclosing_func(&refs, line_1b.saturating_sub(1)).map(|(_, h)| h)
}
