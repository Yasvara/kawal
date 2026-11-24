use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use crate::backport_sem::{
    analyze_hunk_semantics, detect_extra_callers, detect_struct_impact, find_series_siblings,
    SemanticCache,
};
use crate::merge_intel::{is_clo_soc_path, ACK_PROTECTED_MARKERS};
use crate::preflight;
use crate::util::{
    git, git_in, git_rc, git_stdin, is_built_file, norm_subj, par_map, rg, run_cmd, truncate_str,
    Ctx, BOILERPLATE_PREFIXES, C_KEYWORDS,
};

// ====================================================== Helpers & Diff Parser

#[derive(Debug, Clone)]
pub struct PatchHunk {
    pub header: String,
    pub old_start: usize,
    pub old_count: usize,
    pub func_ctx: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FilePatch {
    pub old_path: String,
    pub new_path: String,
    pub header_lines: Vec<String>,
    pub hunks: Vec<PatchHunk>,
}

impl FilePatch {
    pub fn display_path(&self) -> &str {
        if !self.new_path.is_empty() && self.new_path != "/dev/null" {
            &self.new_path
        } else {
            &self.old_path
        }
    }

    pub fn is_doc_or_ignored(&self) -> bool {
        let p = self.display_path();
        p.starts_with("Documentation/")
            || p.starts_with("tools/testing/")
            || p.starts_with("MAINTAINERS")
    }

    /// Reconstruct a minimal standalone unified diff for a single hunk so `git apply --check` can test it.
    pub fn single_hunk_patch(&self, hunk_idx: usize) -> String {
        let mut out = String::new();
        for l in &self.header_lines {
            out.push_str(l);
            out.push('\n');
        }
        let h = &self.hunks[hunk_idx];
        out.push_str(&h.header);
        out.push('\n');
        for l in &h.lines {
            out.push_str(l);
            out.push('\n');
        }
        out
    }
}

pub fn expand_shas(shas: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for s in shas {
        if let Some(p) = s.strip_prefix('@') {
            if let Ok(txt) = fs::read_to_string(p) {
                for ln in txt.lines() {
                    let tok = ln.split('#').next().unwrap_or("").trim();
                    if !tok.is_empty() {
                        if let Some(first) = tok.split_whitespace().next() {
                            out.push(first.to_string());
                        }
                    }
                }
            }
        } else {
            out.push(s.clone());
        }
    }
    out
}

pub fn parse_hunk_header(hdr: &str) -> (usize, usize, usize, usize, String) {
    // @@ -old_start,old_count +new_start,new_count @@ func_ctx
    let mut old_s = 0usize;
    let mut old_c = 1usize;
    let mut new_s = 0usize;
    let mut new_c = 1usize;
    let mut func = String::new();
    if let Some(rest) = hdr.strip_prefix("@@ ") {
        if let Some(end_at) = rest.find(" @@") {
            let range_part = &rest[..end_at];
            func = rest[end_at + 3..].trim().to_string();
            for tok in range_part.split_whitespace() {
                if let Some(r) = tok.strip_prefix('-') {
                    let mut sp = r.split(',');
                    old_s = sp.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                    old_c = sp.next().and_then(|x| x.parse().ok()).unwrap_or(1);
                } else if let Some(r) = tok.strip_prefix('+') {
                    let mut sp = r.split(',');
                    new_s = sp.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                    new_c = sp.next().and_then(|x| x.parse().ok()).unwrap_or(1);
                }
            }
        }
    }
    (old_s, old_c, new_s, new_c, func)
}

pub fn parse_unified_diff(diff_text: &str) -> Vec<FilePatch> {
    let mut files = Vec::new();
    let mut cur_file: Option<FilePatch> = None;
    let mut cur_hunk: Option<PatchHunk> = None;

    let flush_hunk = |cf: &mut Option<FilePatch>, ch: &mut Option<PatchHunk>| {
        if let (Some(f), Some(h)) = (cf.as_mut(), ch.take()) {
            f.hunks.push(h);
        }
    };
    let flush_file = |files: &mut Vec<FilePatch>, cf: &mut Option<FilePatch>, ch: &mut Option<PatchHunk>| {
        flush_hunk(cf, ch);
        if let Some(f) = cf.take() {
            files.push(f);
        }
    };

    for ln in diff_text.lines() {
        if ln.starts_with("diff --git ") {
            flush_file(&mut files, &mut cur_file, &mut cur_hunk);
            let parts: Vec<&str> = ln.split_whitespace().collect();
            let old_p = parts
                .get(2)
                .and_then(|s| s.strip_prefix("a/"))
                .unwrap_or("")
                .to_string();
            let new_p = parts
                .get(3)
                .and_then(|s| s.strip_prefix("b/"))
                .unwrap_or("")
                .to_string();
            cur_file = Some(FilePatch {
                old_path: old_p,
                new_path: new_p,
                header_lines: vec![ln.to_string()],
                hunks: Vec::new(),
            });
            continue;
        }
        let Some(cf) = cur_file.as_mut() else {
            continue;
        };
        if ln.starts_with("@@ ") {
            flush_hunk(&mut cur_file, &mut cur_hunk);
            let (os, oc, _ns, _nc, fctx) = parse_hunk_header(ln);
            cur_hunk = Some(PatchHunk {
                header: ln.to_string(),
                old_start: os,
                old_count: oc,
                func_ctx: fctx,
                lines: Vec::new(),
            });
            continue;
        }
        if let Some(h) = cur_hunk.as_mut() {
            if ln == "-- " {
                // git format-patch footer
                break;
            }
            if ln.starts_with('+') || ln.starts_with('-') || ln.starts_with(' ') || ln.starts_with('\\') {
                h.lines.push(ln.to_string());
            }
        } else {
            if let Some(p) = ln.strip_prefix("--- a/") {
                cf.old_path = p.to_string();
            } else if let Some(p) = ln.strip_prefix("+++ b/") {
                cf.new_path = p.to_string();
            }
            cf.header_lines.push(ln.to_string());
        }
    }
    flush_file(&mut files, &mut cur_file, &mut cur_hunk);
    files
}

/// Strip `Documentation/` file sections from a `git format-patch` email stream so `git am`
/// can apply code hunks cleanly when only docs conflict.
pub fn strip_doc_sections_from_mbox(mbox: &str) -> String {
    let mut out = String::with_capacity(mbox.len());
    let mut skip_section = false;
    for ln in mbox.lines() {
        if ln.starts_with("diff --git ") {
            skip_section = ln.contains(" a/Documentation/") || ln.contains(" b/Documentation/");
        } else if ln == "-- " {
            skip_section = false;
        }
        if !skip_section {
            out.push_str(ln);
            out.push('\n');
        }
    }
    out
}

/// Normalize whitespace for resilient line matching across minor reformatting/indentation changes.
fn norm_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_ws = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out
}

/// Filter out trivial syntax/comment lines when checking if a patch's code already exists in HEAD.
fn is_meaningful_code_line(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 12 {
        return false;
    }
    if t.starts_with("/*") || t.starts_with('*') || t.starts_with("//") || t.starts_with("*/") {
        return false;
    }
    if matches!(t, "return 0;" | "return ret;" | "return NULL;" | "return false;" | "return true;") {
        return false;
    }
    true
}

/// Extract function identifier from a git `@@ ... @@ <func_ctx>` header, e.g.
/// `static inline int foo_bar(struct a *x)` -> `Some("foo_bar")`.
/// Ignores labels (`foo:`), `enum`/`struct` headers, `EXPORT_SYMBOL*`, and `typedef`.
pub fn extract_func_name(func_ctx: &str) -> Option<String> {
    let trimmed = func_ctx.trim();
    if trimmed.is_empty()
        || trimmed.ends_with(':')
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("struct ")
        || trimmed.starts_with("union ")
        || trimmed.starts_with("typedef ")
        || trimmed.starts_with("EXPORT_SYMBOL")
        || trimmed.starts_with('#')
        || !trimmed.contains('(')
    {
        return None;
    }
    let clean = trimmed.split('(').next()?.trim();
    let tok = clean
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|s| !s.is_empty())
        .next_back()?;
    if tok.len() >= 3
        && !C_KEYWORDS.contains(&tok)
        && !tok.chars().all(|c| c.is_ascii_digit())
    {
        Some(tok.to_string())
    } else {
        None
    }
}

/// Compute how much of a patch's meaningful `+` lines are ALREADY present in local HEAD files
/// AND verify meaningful `-` lines are mostly gone (prevents code-move commits from false-matching).
/// Returns `(matched, total, pct)` across all non-doc C/H files; `pct` is gated to 0 if >40% of
/// deleted meaningful lines still exist in HEAD.
pub fn semantic_already_ratio(ctx: &Ctx, file_patches: &[FilePatch]) -> (usize, usize, usize) {
    let mut matched = 0usize;
    let mut total = 0usize;
    let mut del_gone = 0usize;
    let mut del_total = 0usize;
    for fp in file_patches {
        if fp.is_doc_or_ignored() {
            continue;
        }
        let path = fp.display_path();
        let local_txt = fs::read_to_string(ctx.repo.join(path)).unwrap_or_default();
        if local_txt.is_empty() {
            // Still count meaningful lines so missing files don't falsely look 100% present
            for h in &fp.hunks {
                for l in &h.lines {
                    if let Some(body) = l.strip_prefix('+') {
                        if is_meaningful_code_line(body) {
                            total += 1;
                        }
                    }
                }
            }
            continue;
        }
        let local_norm_lines: HashSet<String> = local_txt.lines().map(norm_ws).collect();
        for h in &fp.hunks {
            let del_set: HashSet<String> = h
                .lines
                .iter()
                .filter_map(|l| l.strip_prefix('-'))
                .map(norm_ws)
                .collect();
            let add_set: HashSet<String> = h
                .lines
                .iter()
                .filter_map(|l| l.strip_prefix('+'))
                .map(norm_ws)
                .collect();
            for l in &h.lines {
                if let Some(body) = l.strip_prefix('+') {
                    if !is_meaningful_code_line(body) {
                        continue;
                    }
                    let nw = norm_ws(body);
                    if del_set.contains(&nw) {
                        continue; // indentation-only rewrap
                    }
                    total += 1;
                    if local_norm_lines.contains(&nw) {
                        matched += 1;
                    }
                } else if let Some(body) = l.strip_prefix('-') {
                    if !is_meaningful_code_line(body) {
                        continue;
                    }
                    let nw = norm_ws(body);
                    if add_set.contains(&nw) {
                        continue;
                    }
                    del_total += 1;
                    if !local_norm_lines.contains(&nw) {
                        del_gone += 1;
                    }
                }
            }
        }
    }
    if total == 0 {
        return (0, 0, 0);
    }
    let add_pct = (matched * 100) / total;
    // If substantial deleted lines are still present in HEAD, this commit is NOT already applied!
    if del_total >= 3 && (del_gone * 100) / del_total < 60 {
        return (matched, total, add_pct.min(50));
    }
    (matched, total, add_pct)
}

/// Check if a single hunk's added meaningful lines are all already present in `local_lines`
/// AND its removed meaningful lines are no longer present in the target window.
fn hunk_already_in_local(h: &PatchHunk, local_norm_set: &HashSet<String>) -> bool {
    let mut adds = Vec::new();
    let mut dels = Vec::new();
    for l in &h.lines {
        if let Some(b) = l.strip_prefix('+') {
            if is_meaningful_code_line(b) {
                adds.push(norm_ws(b));
            }
        } else if let Some(b) = l.strip_prefix('-') {
            if is_meaningful_code_line(b) {
                dels.push(norm_ws(b));
            }
        }
    }
    if adds.is_empty() {
        return false;
    }
    let add_hits = adds.iter().filter(|a| local_norm_set.contains(*a)).count();
    let del_gone = dels.iter().filter(|d| !local_norm_set.contains(*d)).count();
    add_hits * 100 >= adds.len() * 85 && (dels.is_empty() || del_gone * 100 >= dels.len() * 75)
}

/// Find a function definition line (1-based) in a file's lines.
fn find_func_in_lines(lines: &[&str], func_name: &str) -> Option<usize> {
    let needle = format!("{func_name}(");
    let mut fallback = None;
    for (i, ln) in lines.iter().enumerate() {
        if !ln.contains(&needle) {
            continue;
        }
        let t = ln.trim();
        if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        // Prefer definitions (no trailing ';' on signature, or next few lines start with '{')
        let looks_like_def = !t.ends_with(';')
            && !t.starts_with("return ")
            && !t.starts_with("if ")
            && !t.starts_with("if(")
            && !t.contains(" = ")
            && (ln.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                || t.starts_with("static ")
                || t.starts_with("inline ")
                || t.starts_with("__")
                || t.starts_with("noinline "));
        if looks_like_def {
            return Some(i + 1);
        }
        if fallback.is_none() {
            fallback = Some(i + 1);
        }
    }
    fallback
}

/// Search sibling files in the same subsystem for a moved function definition.
fn find_moved_func(ctx: &Ctx, orig_path: &str, func_name: &str) -> Option<(String, usize)> {
    let subdir = Path::new(orig_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let search_root = if subdir.is_empty() { "." } else { &subdir };
    let pat = format!(r"\b{func_name}\s*\(");
    let (rc, out) = rg(&ctx.repo, &["-n", "-g", "*.[ch]", &pat, search_root]);
    if rc != 0 || out.trim().is_empty() {
        return None;
    }
    for ln in out.lines() {
        let mut sp = ln.splitn(3, ':');
        let f = sp.next()?;
        let lno: usize = sp.next()?.parse().ok()?;
        let txt = sp.next().unwrap_or("");
        if f == orig_path {
            continue;
        }
        let t = txt.trim();
        if t.ends_with(';') || t.starts_with('*') || t.starts_with("//") {
            continue;
        }
        if txt.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            || t.starts_with("static ")
            || t.starts_with("inline ")
        {
            return Some((f.to_string(), lno));
        }
    }
    None
}

/// Find the best anchor line (1-based) in `local_lines` matching a hunk's context/removed lines,
/// bounded near `func_line` if available.
fn find_hunk_anchor(
    local_lines: &[&str],
    h: &PatchHunk,
    func_line: Option<usize>,
) -> usize {
    let anchors: Vec<String> = h
        .lines
        .iter()
        .filter_map(|l| l.strip_prefix('-').or_else(|| l.strip_prefix(' ')))
        .map(norm_ws)
        .filter(|s| s.len() >= 10 && !s.starts_with('*') && !s.starts_with("/*") && !s.starts_with("//"))
        .collect();

    let (win_start, win_end) = match func_line {
        Some(fl) => (fl.saturating_sub(5), (fl + 220).min(local_lines.len())),
        None => (0, local_lines.len()),
    };

    if !anchors.is_empty() && win_start < win_end {
        let mut best_line = func_line.unwrap_or(h.old_start.max(1).min(local_lines.len().max(1)));
        let mut best_score = 0usize;
        // Slide over window and score local neighborhoods
        for idx in win_start..win_end {
            let nw = norm_ws(local_lines[idx]);
            if nw.len() < 10 {
                continue;
            }
            if anchors.iter().any(|a| *a == nw) {
                // Score surrounding 15-line window
                let lo = idx.saturating_sub(6);
                let hi = (idx + 14).min(win_end);
                let mut sc = 0usize;
                for j in lo..hi {
                    let jw = norm_ws(local_lines[j]);
                    if anchors.iter().any(|a| *a == jw) {
                        sc += 1;
                    }
                }
                if sc > best_score {
                    best_score = sc;
                    best_line = idx + 1;
                }
            }
        }
        if best_score > 0 {
            return best_line;
        }
    }
    func_line.unwrap_or(h.old_start.max(1).min(local_lines.len().max(1)))
}

fn compact_commit_rationale(up_path: &Path, sha: &str, max_lines: usize) -> Vec<String> {
    let body = git_in(up_path, &["show", "-s", "--format=%b", sha]);
    let mut out = Vec::new();
    for ln in body.lines() {
        let t = ln.trim();
        if t.is_empty() {
            continue;
        }
        let low = t.to_ascii_lowercase();
        if BOILERPLATE_PREFIXES.iter().any(|p| low.starts_with(p)) {
            continue;
        }
        out.push(t.to_string());
        if out.len() >= max_lines {
            break;
        }
    }
    out
}

// ====================================================== 1. `kawal backport-check` (Upgraded!)

pub fn cmd_backport_check(
    ctx: &Ctx,
    upstream_repo: &str,
    shas: &[String],
    apply_clean: bool,
    no_doc: bool,
    deep: bool,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let expanded_shas = expand_shas(shas);
    if expanded_shas.is_empty() {
        eprintln!("usage: kawal backport-check <upstream.git> [--apply-clean] [--no-doc] [--deep] <shas...|@file>");
        return 2;
    }

    let local_log = git(ctx, &["log", "--no-merges", "-n", "20000", "--format=%s", "HEAD"]);
    let local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();
    let batch_full: HashSet<String> = expanded_shas
        .iter()
        .map(|s| git_in(up_path, &["rev-parse", s]).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    struct BpRes {
        sha: String,
        status: String,
        risk: &'static str,
        note: String,
        subj: String,
        files: Vec<String>,
        patch: Vec<u8>,
        nodoc_patch: Vec<u8>,
    }

    let results: Vec<BpRes> = par_map(&expanded_shas, ctx.threads, |sha| {
        let full = git_in(up_path, &["rev-parse", sha]).trim().to_string();
        let subj = git_in(up_path, &["show", "-s", "--format=%s", sha])
            .trim()
            .to_string();
        let files: Vec<String> = git_in(up_path, &["diff-tree", "--no-commit-id", "--name-only", "-r", sha])
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let (rc_p, patch_str, _) = run_cmd("git", &["format-patch", "-1", "--stdout", sha], up_path, None);
        let nodoc_str = strip_doc_sections_from_mbox(&patch_str);
        let patch = patch_str.as_bytes().to_vec();
        let nodoc_patch = nodoc_str.as_bytes().to_vec();
        let has_docs = files.iter().any(|f| f.starts_with("Documentation/"));

        let mut note = String::new();
        let status = if subj.is_empty() || rc_p != 0 {
            "NOT-FOUND".to_string()
        } else if local_subjs.contains(&norm_subj(&subj)) {
            "IN-LOG".to_string()
        } else if git_stdin(ctx, &["apply", "--check", "--reverse"], &patch).0 == 0 {
            "ALREADY".to_string()
        } else if !no_doc && git_stdin(ctx, &["apply", "--check"], &patch).0 == 0 {
            "CLEAN".to_string()
        } else if !no_doc && git_stdin(ctx, &["apply", "--check", "-C1"], &patch).0 == 0 {
            "CLEAN-C1".to_string()
        } else if has_docs && git_stdin(ctx, &["apply", "--check", "-C1"], &nodoc_patch).0 == 0 {
            note = "doc-only conflict".to_string();
            "CLEAN-NODOC".to_string()
        } else {
            // Semantic already-present + moved/missing function diagnosis!
            let fps = parse_unified_diff(&patch_str);
            let (matched, total, pct) = semantic_already_ratio(ctx, &fps);
            if (total >= 2 && pct >= 75) || (total == 1 && matched == 1) {
                note = format!("{matched}/{total} +lines in HEAD ({pct}%)");
                "ALREADY-CODE".to_string()
            } else {
                // Check if target functions moved or are absent in 6.12
                let mut moved_hits = Vec::new();
                let mut missing_fns = Vec::new();
                for fp in &fps {
                    if fp.is_doc_or_ignored() {
                        continue;
                    }
                    let local_txt = fs::read_to_string(ctx.repo.join(fp.display_path())).unwrap_or_default();
                    let llines: Vec<&str> = local_txt.lines().collect();
                    for h in &fp.hunks {
                        if let Some(fnm) = extract_func_name(&h.func_ctx) {
                            if find_func_in_lines(&llines, &fnm).is_none() {
                                if let Some((mf, ml)) = find_moved_func(ctx, fp.display_path(), &fnm) {
                                    moved_hits.push(format!("{fnm}->{mf}:{ml}"));
                                } else {
                                    missing_fns.push(fnm);
                                }
                            }
                        }
                    }
                }
                if !moved_hits.is_empty() {
                    moved_hits.sort();
                    moved_hits.dedup();
                    note = format!("MOVED: {}", moved_hits.join(", "));
                } else if !missing_fns.is_empty() {
                    missing_fns.sort();
                    missing_fns.dedup();
                    note = format!("NO-FN: {}", missing_fns.join(", "));
                }
                "ADAPT".to_string()
            }
        };

        // Optional `--deep` semantic scan even on CLEAN commits (catches silent arity drift, sleep-under-lock, extra callers, series gaps!)
        if deep && matches!(status.as_str(), "CLEAN" | "CLEAN-C1" | "CLEAN-NODOC" | "ADAPT") && !full.is_empty() {
            let fps = parse_unified_diff(&patch_str);
            let mut sem_cache = SemanticCache::default();
            let mut n_drift = 0usize;
            let mut n_undef = 0usize;
            let mut n_sleep = 0usize;
            let mut n_extra = 0usize;
            let mut n_struct = 0usize;
            for fp in &fps {
                if fp.is_doc_or_ignored() {
                    continue;
                }
                let local_txt = fs::read_to_string(ctx.repo.join(fp.display_path())).unwrap_or_default();
                n_extra += detect_extra_callers(ctx, fp, &fps).len();
                n_struct += detect_struct_impact(ctx, fp).len();
                for h in &fp.hunks {
                    let rep = analyze_hunk_semantics(ctx, up_path, &full, fp, h, &local_txt, &mut sem_cache, false);
                    n_drift += rep.api_drifts.len();
                    n_undef += rep.undef_syms.len() + rep.undef_consts.len() + rep.undef_fields.len();
                    n_sleep += rep.atomic_sleeps.len();
                }
            }
            let mut tags = Vec::new();
            if n_drift > 0 {
                tags.push(format!("API-DRIFT({n_drift})"));
            }
            if n_undef > 0 {
                tags.push(format!("UNDEF({n_undef})"));
            }
            if n_sleep > 0 {
                tags.push(format!("ATOMIC-SLEEP({n_sleep})!"));
            }
            if n_extra > 0 {
                tags.push(format!("EXTRA-CALLER({n_extra})"));
            }
            if n_struct > 0 {
                tags.push(format!("STRUCT({n_struct})"));
            }
            if let Some(sinfo) = find_series_siblings(ctx, up_path, &full, &local_subjs, &batch_full) {
                let gaps = sinfo.siblings.iter().filter(|s| s.is_before && matches!(s.state, "MISSING" | "CLEAN")).count();
                if gaps > 0 {
                    tags.push(format!("SERIES-GAP({gaps})"));
                }
            }
            if !tags.is_empty() {
                if !note.is_empty() {
                    note.push_str("; ");
                }
                note.push_str(&tags.join(" "));
            }
        }

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
            note,
            subj,
            files,
            patch,
            nodoc_patch,
        }
    });

    // Track files touched by earlier commits in this batch to flag series dependencies
    let mut seen_files: HashSet<String> = HashSet::new();
    let mut n_clean = 0usize;
    let mut n_already = 0usize;
    let mut n_adapt = 0usize;
    let mut n_applied = 0usize;
    let mut adapt_shas: Vec<String> = Vec::new();

    println!(
        "=== kawal backport-check ({} commits from {}) ===",
        results.len(),
        upstream_repo
    );
    for r in &results {
        let code_files: Vec<&String> = r
            .files
            .iter()
            .filter(|f| !f.starts_with("Documentation/"))
            .collect();
        let series_dep = r.status == "ADAPT"
            && code_files.iter().any(|f| seen_files.contains(f.as_str()));

        match r.status.as_str() {
            "IN-LOG" | "ALREADY" | "ALREADY-CODE" => n_already += 1,
            "CLEAN" | "CLEAN-C1" | "CLEAN-NODOC" => {
                n_clean += 1;
                for f in &code_files {
                    seen_files.insert((*f).clone());
                }
            }
            _ => {
                n_adapt += 1;
                adapt_shas.push(truncate_str(&r.sha, 10).to_string());
                for f in &code_files {
                    seen_files.insert((*f).clone());
                }
            }
        }
        let built_cnt = r.files.iter().filter(|f| is_built_file(ctx, f)).count();
        let btag = if built_cnt > 0 { "[BUILT]" } else { "[unbuilt]" };
        let fpreview = code_files
            .iter()
            .take(2)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let mut extra = r.note.clone();
        if series_dep {
            if !extra.is_empty() {
                extra.push_str("; ");
            }
            extra.push_str("SERIES-DEP");
        }
        let extra_s = if extra.is_empty() {
            String::new()
        } else {
            format!("  [{extra}]")
        };
        println!(
            "  {:<12} {btag:<9} {} {} | {:<32} | {}{}",
            r.status,
            r.risk,
            truncate_str(&r.sha, 10),
            truncate_str(&fpreview, 32),
            truncate_str(&r.subj, 50),
            extra_s
        );
        if apply_clean && matches!(r.status.as_str(), "CLEAN" | "CLEAN-C1" | "CLEAN-NODOC") {
            let (args, bytes): (&[&str], &[u8]) = match r.status.as_str() {
                "CLEAN" => (&["apply"], &r.patch),
                "CLEAN-C1" => (&["apply", "-C1"], &r.patch),
                _ => (&["apply", "-C1"], &r.nodoc_patch),
            };
            if git_stdin(ctx, args, bytes).0 == 0 {
                n_applied += 1;
            } else {
                println!("    !! sequential apply conflicted (overlap): {}", r.sha);
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
    if !adapt_shas.is_empty() && !apply_clean {
        println!(
            "Tip: inspect conflicts cleanly via:\n  kawal backport-ctx {} {}",
            upstream_repo,
            adapt_shas.join(" ")
        );
    }
    0
}

// ====================================================== 2. `kawal backport-apply`

pub fn cmd_backport_apply(
    ctx: &Ctx,
    upstream_repo: &str,
    shas: &[String],
    no_doc: bool,
    sign: bool,
    compile_check: bool,
    stop_on_conflict: bool,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let expanded = expand_shas(shas);
    if expanded.is_empty() {
        eprintln!("usage: kawal backport-apply <upstream.git> [--no-doc] [--no-sign] [--check] [--stop-on-conflict] <shas...|@file>");
        return 2;
    }
    let status_out = git(ctx, &["status", "--porcelain"]);
    if !status_out.trim().is_empty() {
        eprintln!("!! working tree is not clean — commit or stash before backport-apply");
        return 1;
    }

    let local_log = git(ctx, &["log", "--no-merges", "-n", "20000", "--format=%s", "HEAD"]);
    let mut local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut compile_errs = 0usize;
    let mut conflicts: Vec<String> = Vec::new();

    println!(
        "=== kawal backport-apply ({} commits, sign={}, no_doc={}, check={}) ===",
        expanded.len(),
        sign,
        no_doc,
        compile_check
    );

    for sha in &expanded {
        let full = git_in(up_path, &["rev-parse", sha]).trim().to_string();
        if full.is_empty() {
            println!("  NOT-FOUND    {sha}");
            conflicts.push(sha.clone());
            if stop_on_conflict {
                break;
            }
            continue;
        }
        let subj = git_in(up_path, &["show", "-s", "--format=%s", &full])
            .trim()
            .to_string();
        let short = truncate_str(&full, 10);

        if local_subjs.contains(&norm_subj(&subj)) {
            println!("  SKIP(in-log) {short} | {}", truncate_str(&subj, 60));
            skipped += 1;
            continue;
        }

        let (rc_p, patch_str, _) =
            run_cmd("git", &["format-patch", "-1", "--stdout", &full], up_path, None);
        if rc_p != 0 {
            println!("  ERR-PATCH    {short} | {}", truncate_str(&subj, 60));
            conflicts.push(short.to_string());
            if stop_on_conflict {
                break;
            }
            continue;
        }

        if git_stdin(ctx, &["apply", "--check", "--reverse"], patch_str.as_bytes()).0 == 0 {
            println!("  SKIP(rev)    {short} | {}", truncate_str(&subj, 60));
            skipped += 1;
            continue;
        }

        let fps = parse_unified_diff(&patch_str);
        let (matched, total, pct) = semantic_already_ratio(ctx, &fps);

        // Append cherry-pick footer to commit message before `---`
        let add_cp_footer = |raw: &str| -> String {
            let footer = format!("\n(cherry picked from commit {full})\n---");
            if let Some(pos) = raw.find("\n---") {
                let mut s = String::with_capacity(raw.len() + footer.len());
                s.push_str(&raw[..pos]);
                s.push_str(&footer);
                s.push_str(&raw[pos + 4..]);
                s
            } else {
                raw.to_string()
            }
        };

        let try_am = |stream: &str| -> bool {
            let mut am_args = vec!["am", "-C1", "--quiet"];
            if sign {
                am_args.push("-S");
            }
            let (rc, _, _) = git_stdin(ctx, &am_args, stream.as_bytes());
            if rc == 0 {
                true
            } else {
                let _ = git_rc(ctx, &["am", "--abort"]);
                false
            }
        };

        let mut ok = false;
        let mut tag = "APPLIED";
        if !no_doc && try_am(&add_cp_footer(&patch_str)) {
            ok = true;
        } else {
            let nodoc = strip_doc_sections_from_mbox(&patch_str);
            if nodoc.contains("diff --git ") && try_am(&add_cp_footer(&nodoc)) {
                ok = true;
                tag = "APPLIED-ND";
            }
        }

        if ok {
            let mut err_detail: Vec<(String, Vec<String>)> = Vec::new();
            let mut chk_tag = String::new();
            if compile_check {
                let c_files: Vec<String> = fps
                    .iter()
                    .map(|fp| fp.display_path().to_string())
                    .filter(|p| p.ends_with(".c"))
                    .collect();
                let (checked, errs) = preflight::quick_syntax_check(ctx, &c_files);
                if !errs.is_empty() {
                    compile_errs += 1;
                    chk_tag = " [COMPILE-ERR!]".to_string();
                    err_detail = errs;
                } else if checked > 0 {
                    chk_tag = format!(" [cc:{checked} OK]");
                }
            }
            println!("  {:<12} {short} | {}{}", tag, truncate_str(&subj, 55), chk_tag);
            for (f, lines) in &err_detail {
                println!("    !! {f}:");
                for el in lines.iter().take(5) {
                    println!("       {el}");
                }
            }
            local_subjs.insert(norm_subj(&subj));
            applied += 1;
            if !err_detail.is_empty() && stop_on_conflict {
                break;
            }
        } else if (total >= 2 && pct >= 75) || (total == 1 && matched == 1) {
            println!(
                "  SKIP(code)   {short} | {} [{matched}/{total} +lines ({pct}%) in HEAD]",
                truncate_str(&subj, 48)
            );
            skipped += 1;
        } else {
            println!("  CONFLICT     {short} | {}", truncate_str(&subj, 60));
            conflicts.push(short.to_string());
            if stop_on_conflict {
                break;
            }
        }
    }

    println!(
        "Summary: {} applied | {} skipped (already in HEAD) | {} conflict(s){}",
        applied,
        skipped,
        conflicts.len(),
        if compile_errs > 0 {
            format!(" | {} COMPILE-ERR(s)!", compile_errs)
        } else {
            String::new()
        }
    );
    if !conflicts.is_empty() {
        println!(
            "Next (surgical context, token-saving):\n  kawal backport-ctx {} {}",
            upstream_repo,
            conflicts.join(" ")
        );
    }
    0
}

/// Surface immediate upstream prerequisite commits (touching the same file right before `full`
/// and missing from local `HEAD`) so series dependencies aren't missed during manual adaptation.
fn find_prereq_hints(
    ctx: &Ctx,
    up_path: &Path,
    full: &str,
    author: &str,
    file_path: &str,
    local_subjs: &HashSet<String>,
) -> Vec<String> {
    let parent = format!("{full}^");
    let out = git_in(
        up_path,
        &[
            "log",
            "--no-merges",
            "-n",
            "6",
            "--format=%h\t%an\t%s",
            &parent,
            "--",
            file_path,
        ],
    );
    let mut hints = Vec::new();
    for ln in out.lines() {
        let parts: Vec<&str> = ln.splitn(3, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let (psha, pauth, psubj) = (parts[0], parts[1], parts[2]);
        if local_subjs.contains(&norm_subj(psubj)) {
            continue;
        }
        let same_author = pauth == author;
        if !same_author && hints.len() >= 2 {
            continue;
        }
        let (rc_p, ppatch, _) = run_cmd("git", &["format-patch", "-1", "--stdout", psha], up_path, None);
        if rc_p != 0 {
            continue;
        }
        if git_stdin(ctx, &["apply", "--check", "--reverse"], ppatch.as_bytes()).0 == 0 {
            continue;
        }
        let tag = if git_stdin(ctx, &["apply", "--check", "-C1"], ppatch.as_bytes()).0 == 0 {
            "CLEAN"
        } else {
            "ADAPT"
        };
        let auth_tag = if same_author { "same-author" } else { pauth };
        hints.push(format!("{tag:<5} {psha} ({auth_tag}) | {}", truncate_str(psubj, 58)));
        if hints.len() >= 4 {
            break;
        }
    }
    hints
}

// ====================================================== 3. `kawal backport-ctx` & `backport-stage`

pub fn cmd_backport_ctx(
    ctx: &Ctx,
    upstream_repo: &str,
    shas: &[String],
    ctx_lines: usize,
    all_hunks: bool,
    include_doc: bool,
    stage_ok_hunks: bool,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let expanded = expand_shas(shas);
    if expanded.is_empty() {
        eprintln!("usage: kawal backport-ctx <upstream.git> [--ctx N] [--all-hunks] [--doc] <shas...|@file>");
        return 2;
    }
    if stage_ok_hunks && expanded.len() > 1 {
        eprintln!("!! backport-stage operates on 1 commit at a time (got {})", expanded.len());
        return 2;
    }

    let local_log = git(ctx, &["log", "--no-merges", "-n", "20000", "--format=%s", "HEAD"]);
    let local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();
    let batch_full: HashSet<String> = expanded
        .iter()
        .map(|s| git_in(up_path, &["rev-parse", s]).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Cache semantic symbol/signature/upstream lookups across commits
    let mut sem_cache = SemanticCache::default();
    let mut staged_ok = 0usize;
    let mut remaining_conflicts = 0usize;

    for sha in &expanded {
        let full = git_in(up_path, &["rev-parse", sha]).trim().to_string();
        if full.is_empty() {
            println!("=== NOT-FOUND: {sha} ===");
            continue;
        }
        let short = truncate_str(&full, 10);
        let subj = git_in(up_path, &["show", "-s", "--format=%s", &full])
            .trim()
            .to_string();
        let author = git_in(up_path, &["show", "-s", "--format=%an", &full])
            .trim()
            .to_string();
        let diff_str = git_in(up_path, &["show", "--format=", &full]);
        let fps = parse_unified_diff(&diff_str);
        let (matched, total, pct) = semantic_already_ratio(ctx, &fps);

        println!("\n======================================================================");
        println!("COMMIT {short} | {subj}  ({author})");
        if total > 0 && pct >= 60 {
            println!("  [SEMANTIC-HINT] {matched}/{total} meaningful +lines ({pct}%) already appear in HEAD!");
        }
        for line in compact_commit_rationale(up_path, &full, 3) {
            println!("  WHY: {}", truncate_str(&line, 110));
        }
        // Surface upstream mailing-list series siblings (prereqs before & follow-ups after!)
        if let Some(sinfo) = find_series_siblings(ctx, up_path, &full, &local_subjs, &batch_full) {
            let missing_before: Vec<_> = sinfo
                .siblings
                .iter()
                .filter(|s| s.is_before && matches!(s.state, "MISSING" | "CLEAN"))
                .collect();
            let follow_ups: Vec<_> = sinfo
                .siblings
                .iter()
                .filter(|s| !s.is_before && s.state != "SELF" && s.state != "IN-HEAD")
                .collect();
            let pos_lbl = sinfo
                .self_num
                .map(|n| format!("patch #{n} of {}", sinfo.siblings.len()))
                .unwrap_or_else(|| format!("{} patches", sinfo.siblings.len()));
            if !missing_before.is_empty() || !follow_ups.is_empty() {
                println!(
                    "  [SERIES]    {} ({pos_lbl} | {} missing prereq(s), {} follow-up(s)):",
                    sinfo.series_id.trim_end_matches('-'),
                    missing_before.len(),
                    follow_ups.len()
                );
                for s in missing_before.iter().take(6) {
                    let pno = s.patch_num.map(|n| format!("#{n:<2}")).unwrap_or_else(|| "   ".into());
                    println!("    ! PRE-REQ {:<7} {pno} {} | {}", s.state, s.sha, truncate_str(&s.subj, 64));
                }
                if missing_before.len() > 6 {
                    println!("    ! ... (+{} earlier prereq(s))", missing_before.len() - 6);
                }
                for s in follow_ups.iter().take(3) {
                    let pno = s.patch_num.map(|n| format!("#{n:<2}")).unwrap_or_else(|| "   ".into());
                    println!("    ~ FOLLOW  {:<7} {pno} {} | {}", s.state, s.sha, truncate_str(&s.subj, 64));
                }
            }
        }

        for fp in &fps {
            if !include_doc && fp.is_doc_or_ignored() {
                continue;
            }
            let orig_path = fp.display_path();
            let orig_full = ctx.repo.join(orig_path);
            let orig_txt = fs::read_to_string(&orig_full).unwrap_or_default();
            let orig_lines: Vec<&str> = orig_txt.lines().collect();
            let orig_norm_set: HashSet<String> = orig_lines.iter().map(|s| norm_ws(s)).collect();

            println!("--- FILE: {orig_path} ({} hunk(s)) ---", fp.hunks.len());
            for si in detect_struct_impact(ctx, fp) {
                println!("  [STRUCT-MOD] {si}");
            }
            for ec in detect_extra_callers(ctx, fp, &fps) {
                println!("  [EXTRA-CALL] {ec}");
            }
            let mut file_had_conflict = false;

            for (hi, h) in fp.hunks.iter().enumerate() {
                let single_patch = fp.single_hunk_patch(hi);
                let fn_label = extract_func_name(&h.func_ctx)
                    .unwrap_or_else(|| truncate_str(&h.func_ctx, 32).to_string());
                let n_add = h.lines.iter().filter(|l| l.starts_with('+')).count();
                let n_del = h.lines.iter().filter(|l| l.starts_with('-')).count();

                // Run semantic diagnostics even for clean hunks so API-drift / atomic-sleep never hides!
                let is_dup = git_stdin(ctx, &["apply", "--check", "--reverse"], single_patch.as_bytes()).0 == 0
                    || hunk_already_in_local(h, &orig_norm_set);
                let sem = if is_dup {
                    Default::default()
                } else {
                    analyze_hunk_semantics(ctx, up_path, &full, fp, h, &orig_txt, &mut sem_cache, true)
                };
                let has_sem_alert = !sem.api_drifts.is_empty()
                    || !sem.atomic_sleeps.is_empty()
                    || !sem.undef_syms.is_empty()
                    || !sem.undef_consts.is_empty()
                    || !sem.undef_fields.is_empty();

                let print_sem = |sem: &crate::backport_sem::HunkSemReport| {
                    for s in &sem.atomic_sleeps {
                        println!("  [ATOMIC-SLEEP] !! {s}");
                    }
                    for d in &sem.api_drifts {
                        println!("  [API-DRIFT]    !! {d}");
                    }
                    for u in &sem.undef_syms {
                        println!("  [UNDEF-SYM]    {u}");
                    }
                    for c in &sem.undef_consts {
                        println!("  [UNDEF-CONST]  {c}");
                    }
                    for f in &sem.undef_fields {
                        println!("  [UNDEF-FIELD]  {f}");
                    }
                };

                // 1. Test individual hunk against HEAD
                if is_dup {
                    println!("  [HUNK-DUP]  #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> already in HEAD", hi + 1, fp.hunks.len());
                    if !all_hunks {
                        continue;
                    }
                } else if git_stdin(ctx, &["apply", "--check", "-C1"], single_patch.as_bytes()).0 == 0 {
                    if stage_ok_hunks {
                        if git_stdin(ctx, &["apply", "-C1"], single_patch.as_bytes()).0 == 0 {
                            staged_ok += 1;
                            if has_sem_alert {
                                println!("  [APPLIED!]  #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> applied, BUT semantic alert(s) below!", hi + 1, fp.hunks.len());
                                print_sem(&sem);
                            } else {
                                println!("  [APPLIED]   #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> applied to working tree!", hi + 1, fp.hunks.len());
                            }
                            continue;
                        }
                    } else if !has_sem_alert {
                        println!("  [HUNK-OK]   #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> applies cleanly with -C1", hi + 1, fp.hunks.len());
                        if !all_hunks {
                            continue;
                        }
                    } else {
                        println!("  [HUNK-OK!]  #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> applies with -C1, BUT semantic alert(s)!", hi + 1, fp.hunks.len());
                        print_sem(&sem);
                        if !all_hunks {
                            continue;
                        }
                    }
                } else {
                    file_had_conflict = true;
                    remaining_conflicts += 1;
                    println!("  [CONFLICT]  #{}/{} {fn_label}() (+{n_add}/-{n_del})", hi + 1, fp.hunks.len());
                }

                // 2. Print compact upstream hunk
                println!("  [UPSTREAM] {}", h.header);
                for l in &h.lines {
                    println!("    {l}");
                }

                // 3. Locate exact local target (same file or cross-file moved function!)
                let mut target_path = orig_path.to_string();
                let mut target_txt_owned: Option<String> = None;
                let mut func_line = extract_func_name(&h.func_ctx)
                    .and_then(|fnm| find_func_in_lines(&orig_lines, &fnm));

                if func_line.is_none() {
                    if let Some(fnm) = extract_func_name(&h.func_ctx) {
                        if let Some((moved_p, moved_l)) = find_moved_func(ctx, orig_path, &fnm) {
                            println!("  [MOVED-FN]  `{fnm}()` moved -> {moved_p}:{moved_l}");
                            target_path = moved_p.clone();
                            target_txt_owned = fs::read_to_string(ctx.repo.join(&moved_p)).ok();
                            func_line = Some(moved_l);
                        } else if !orig_txt.is_empty() {
                            println!("  [MISSING-FN] `{fnm}()` not found in {orig_path} or subsystem — may be post-6.12!");
                        }
                    }
                }

                let tlines: Vec<&str> = match target_txt_owned.as_deref() {
                    Some(t) => t.lines().collect(),
                    None => orig_lines.clone(),
                };

                if tlines.is_empty() {
                    println!("  [LOCAL]     file missing in HEAD: {target_path}");
                } else {
                    let anchor = find_hunk_anchor(&tlines, h, func_line);
                    let start = anchor.saturating_sub(ctx_lines).max(1);
                    let end = (anchor + ctx_lines + h.old_count.min(18)).min(tlines.len());

                    // Highlight any Android/CLO vendor hooks inside this function slice!
                    let hook_start = func_line.unwrap_or(start);
                    let hook_end = (hook_start + 120).min(tlines.len());
                    let mut hooks = Vec::new();
                    for lno in hook_start..=hook_end {
                        let line = tlines[lno - 1];
                        if line.contains("trace_android_") || line.contains("ANDROID_") {
                            hooks.push(format!("L{lno}: {}", line.trim()));
                        }
                        if lno > hook_start && line.starts_with('}') {
                            break;
                        }
                    }
                    if !hooks.is_empty() {
                        println!("  [HOOKS]     Vendor hooks in enclosing function (PRESERVE!):");
                        for hk in hooks.iter().take(6) {
                            println!("    ! {hk}");
                        }
                    }

                    println!("  [LOCAL {target_path}:L{start}..L{end}]");
                    for lno in start..=end {
                        println!("    {lno:>5}: {}", tlines[lno - 1]);
                    }
                }

                // 4. Print semantic diagnostics (API drift, atomic sleep, missing syms/consts/fields w/ upstream defs!)
                print_sem(&sem);
            }

            if file_had_conflict {
                let prereqs = find_prereq_hints(ctx, up_path, &full, &author, orig_path, &local_subjs);
                if !prereqs.is_empty() {
                    println!("  [PREREQ-HINT] Recent upstream commits on {orig_path} before {short} (missing from HEAD):");
                    for p in &prereqs {
                        println!("    -> {p}");
                    }
                }
            }
        }
    }
    if stage_ok_hunks {
        println!(
            "\n=== backport-stage summary: {staged_ok} clean hunk(s) applied | {remaining_conflicts} conflict hunk(s) left to edit ==="
        );
        if remaining_conflicts == 0 {
            println!("All non-dup hunks applied cleanly! Commit via:\n  kawal backport-commit {upstream_repo} {}", expanded[0]);
        }
    }
    0
}

// ====================================================== 4. `kawal backport-commit`

pub fn cmd_backport_commit(
    ctx: &Ctx,
    upstream_repo: &str,
    sha: &str,
    files: &[String],
    sign: bool,
    compile_check: bool,
    allow_hook_drop: bool,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let full = git_in(up_path, &["rev-parse", sha]).trim().to_string();
    if full.is_empty() {
        eprintln!("!! commit not found in {upstream_repo}: {sha}");
        return 2;
    }
    let author = git_in(up_path, &["show", "-s", "--format=%an <%ae>", &full])
        .trim()
        .to_string();
    let date = git_in(up_path, &["show", "-s", "--format=%ad", &full])
        .trim()
        .to_string();
    let subj = git_in(up_path, &["show", "-s", "--format=%s", &full])
        .trim()
        .to_string();

    if files.is_empty() {
        let (rc, _, err) = git_rc(ctx, &["add", "-u"]);
        if rc != 0 {
            eprintln!("!! git add -u failed: {err}");
            return 1;
        }
    } else {
        let mut add_args = vec!["add", "--"];
        for f in files {
            add_args.push(f.as_str());
        }
        let (rc, _, err) = git_rc(ctx, &add_args);
        if rc != 0 {
            eprintln!("!! git add failed: {err}");
            return 1;
        }
    }

    let staged = git(ctx, &["diff", "--cached"]);
    if staged.trim().is_empty() {
        eprintln!("!! nothing staged to commit for {sha}");
        return 1;
    }

    // Optional fast real clang -fsyntax-only compile gate on staged .c files!
    if compile_check {
        let staged_files: Vec<String> = git(ctx, &["diff", "--cached", "--name-only"])
            .lines()
            .map(str::trim)
            .filter(|s| s.ends_with(".c"))
            .map(str::to_string)
            .collect();
        let (checked, errs) = preflight::quick_syntax_check(ctx, &staged_files);
        if !errs.is_empty() {
            eprintln!("!! COMPILE-CHECK BLOCKED commit for {sha} ({}/{} TU failed):", errs.len(), checked);
            for (f, lines) in &errs {
                eprintln!("  --- {f} ---");
                for el in lines {
                    eprintln!("    {el}");
                }
            }
            return 1;
        }
        if checked > 0 {
            println!("  [cc:{checked} TU OK]");
        }
    }

    // Built-in safety guard: catch accidental deletion of Android vendor hooks or EXPORT_SYMBOL!
    if !allow_hook_drop {
        let mut dropped = Vec::new();
        let added_lines: HashSet<&str> = staged
            .lines()
            .filter_map(|l| l.strip_prefix('+'))
            .map(str::trim)
            .collect();
        for l in staged.lines() {
            if let Some(body) = l.strip_prefix('-') {
                if l.starts_with("---") {
                    continue;
                }
                let t = body.trim();
                if (t.contains("trace_android_") || t.starts_with("EXPORT_SYMBOL"))
                    && !added_lines.contains(t)
                {
                    dropped.push(t.to_string());
                }
            }
        }
        if !dropped.is_empty() {
            eprintln!("!! GUARD BLOCKED: staged diff removes vendor hook / EXPORT_SYMBOL:");
            for d in &dropped {
                eprintln!("   - {d}");
            }
            eprintln!("   Re-verify or pass --allow-hook-drop if intentional.");
            return 1;
        }
    }

    let title = format!("BACKPORT: {subj}");
    let body = format!("(backported from upstream commit {full})");
    let author_flag = format!("--author={author}");
    let date_flag = format!("--date={date}");
    let mut args = vec!["commit", "--quiet"];
    if sign {
        args.push("-S");
    }
    args.extend_from_slice(&[&author_flag, &date_flag, "-m", &title, "-m", &body]);
    let (rc, _, err) = git_rc(ctx, &args);
    if rc != 0 {
        eprintln!("!! git commit failed: {err}");
        return 1;
    }
    let new_head = git(ctx, &["rev-parse", "--short=10", "HEAD"]).trim().to_string();
    println!("COMMITTED {new_head} <- {} | {subj}", truncate_str(&full, 10));
    0
}

// ====================================================== 5. `kawal backport-search`

pub fn cmd_backport_search(
    ctx: &Ctx,
    upstream_repo: &str,
    pattern: &str,
    range: &str,
    paths: &[String],
    limit: usize,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let local_log = git(ctx, &["log", "--no-merges", "-n", "20000", "--format=%s", "HEAD"]);
    let local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();

    let mut args: Vec<String> = vec![
        "log".into(),
        "--no-merges".into(),
        "--oneline".into(),
        "--abbrev=10".into(),
        "-i".into(),
        format!("--grep={pattern}"),
        range.into(),
    ];
    if !paths.is_empty() {
        args.push("--".into());
        args.extend(paths.iter().cloned());
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = git_in(up_path, &arg_refs);
    println!("=== kawal backport-search `{pattern}` in {range} ===");
    let mut shown = 0usize;
    let mut skipped_in_log = 0usize;
    for ln in out.lines() {
        let Some((sha, subj)) = ln.split_once(' ') else {
            continue;
        };
        if local_subjs.contains(&norm_subj(subj)) {
            skipped_in_log += 1;
            continue;
        }
        println!("  {sha} | {subj}");
        shown += 1;
        if shown >= limit {
            break;
        }
    }
    println!("Shown: {shown} missing commit(s) (filtered {skipped_in_log} already in HEAD)");
    0
}

// ====================================================== 6. `kawal backport-series`

/// Topological upstream sorter + series-gap finder + 16-core semantic risk dashboard for an entire
/// backport batch (detects out-of-order SHAs, missing upstream series prerequisites, API arity drift,
/// atomic-sleep traps, extra unpatched callers, and struct layout changes in one shot!).
pub fn cmd_backport_series(ctx: &Ctx, upstream_repo: &str, shas: &[String]) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let expanded = expand_shas(shas);
    if expanded.is_empty() {
        eprintln!("usage: kawal backport-series <upstream.git> <shas...|@file>");
        return 2;
    }

    // Resolve full SHAs & sort in true upstream chronological/topological order!
    let mut resolved: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for s in &expanded {
        let full = git_in(up_path, &["rev-parse", s]).trim().to_string();
        if !full.is_empty() && seen.insert(full.clone()) {
            resolved.push(full);
        } else if full.is_empty() {
            eprintln!("  !! NOT-FOUND in upstream mirror: {s}");
        }
    }
    if resolved.is_empty() {
        return 1;
    }

    // Order by upstream commit timestamp + topological order from v6.12..HEAD
    let batch_set: HashSet<String> = resolved.iter().cloned().collect();
    let topo_out = git_in(up_path, &["rev-list", "--topo-order", "--reverse", "v6.12..HEAD"]);
    let mut ordered: Vec<String> = Vec::with_capacity(resolved.len());
    for ln in topo_out.lines() {
        if batch_set.contains(ln) {
            ordered.push(ln.to_string());
        }
    }
    // Append any SHAs not reachable in v6.12..HEAD (e.g. older commits) in original order
    for r in &resolved {
        if !ordered.contains(r) {
            ordered.push(r.clone());
        }
    }
    let reordered = ordered != resolved;

    let local_log = git(ctx, &["log", "--no-merges", "-n", "20000", "--format=%s", "HEAD"]);
    let local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();

    struct SeriesRow {
        short: String,
        status: String,
        btag: &'static str,
        risk: &'static str,
        file_preview: String,
        subj: String,
        flags: Vec<String>,
        missing_prereqs: Vec<(String, &'static str, Option<u32>, String, String)>, // (sha, state, pnum, subj, series_id)
    }

    let rows: Vec<SeriesRow> = par_map(&ordered, ctx.threads, |full| {
        let short = truncate_str(full, 10).to_string();
        let subj = git_in(up_path, &["show", "-s", "--format=%s", full]).trim().to_string();
        let files: Vec<String> = git_in(up_path, &["diff-tree", "--no-commit-id", "--name-only", "-r", full])
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let code_files: Vec<&String> = files.iter().filter(|f| !f.starts_with("Documentation/")).collect();
        let file_preview = code_files
            .iter()
            .take(2)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let built_cnt = files.iter().filter(|f| is_built_file(ctx, f)).count();
        let btag = if built_cnt > 0 { "[BUILT]" } else { "[unbuilt]" };

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

        let (_, patch_str, _) = run_cmd("git", &["format-patch", "-1", "--stdout", full], up_path, None);
        let nodoc_str = strip_doc_sections_from_mbox(&patch_str);
        let has_docs = files.iter().any(|f| f.starts_with("Documentation/"));
        let fps = parse_unified_diff(&patch_str);

        let status = if local_subjs.contains(&norm_subj(&subj)) {
            "IN-LOG".to_string()
        } else if git_stdin(ctx, &["apply", "--check", "--reverse"], patch_str.as_bytes()).0 == 0 {
            "ALREADY".to_string()
        } else if git_stdin(ctx, &["apply", "--check"], patch_str.as_bytes()).0 == 0 {
            "CLEAN".to_string()
        } else if git_stdin(ctx, &["apply", "--check", "-C1"], patch_str.as_bytes()).0 == 0 {
            "CLEAN-C1".to_string()
        } else if has_docs && git_stdin(ctx, &["apply", "--check", "-C1"], nodoc_str.as_bytes()).0 == 0 {
            "CLEAN-NODOC".to_string()
        } else {
            let (m, t, pct) = semantic_already_ratio(ctx, &fps);
            if (t >= 2 && pct >= 75) || (t == 1 && m == 1) {
                "ALREADY-CODE".to_string()
            } else {
                "ADAPT".to_string()
            }
        };

        let mut flags = Vec::new();
        let mut missing_prereqs = Vec::new();
        if !matches!(status.as_str(), "IN-LOG" | "ALREADY" | "ALREADY-CODE") {
            let mut sem_cache = SemanticCache::default();
            let mut n_drift = 0usize;
            let mut n_undef = 0usize;
            let mut n_sleep = 0usize;
            let mut n_extra = 0usize;
            let mut n_struct = 0usize;
            for fp in &fps {
                if fp.is_doc_or_ignored() {
                    continue;
                }
                let local_txt = fs::read_to_string(ctx.repo.join(fp.display_path())).unwrap_or_default();
                n_extra += detect_extra_callers(ctx, fp, &fps).len();
                n_struct += detect_struct_impact(ctx, fp).len();
                for h in &fp.hunks {
                    let rep = analyze_hunk_semantics(ctx, up_path, full, fp, h, &local_txt, &mut sem_cache, false);
                    n_drift += rep.api_drifts.len();
                    n_undef += rep.undef_syms.len() + rep.undef_consts.len() + rep.undef_fields.len();
                    n_sleep += rep.atomic_sleeps.len();
                }
            }
            if n_sleep > 0 {
                flags.push(format!("SLEEP({n_sleep})!"));
            }
            if n_drift > 0 {
                flags.push(format!("ARITY({n_drift})"));
            }
            if n_undef > 0 {
                flags.push(format!("UNDEF({n_undef})"));
            }
            if n_extra > 0 {
                flags.push(format!("CALLERS({n_extra})"));
            }
            if n_struct > 0 {
                flags.push(format!("STRUCT({n_struct})"));
            }
            if let Some(sinfo) = find_series_siblings(ctx, up_path, full, &local_subjs, &batch_set) {
                let mut gaps = 0usize;
                for s in &sinfo.siblings {
                    if s.is_before && matches!(s.state, "MISSING" | "CLEAN") {
                        gaps += 1;
                        missing_prereqs.push((
                            s.sha.clone(),
                            s.state,
                            s.patch_num,
                            s.subj.clone(),
                            sinfo.series_id.trim_end_matches('-').to_string(),
                        ));
                    }
                }
                if gaps > 0 {
                    flags.push(format!("SER-GAP({gaps})"));
                }
            }
        }

        SeriesRow {
            short,
            status,
            btag,
            risk,
            file_preview,
            subj,
            flags,
            missing_prereqs,
        }
    });

    println!(
        "=== kawal backport-series ({} commits, topo-sorted{}) ===",
        rows.len(),
        if reordered { ", REORDERED from input!" } else { "" }
    );
    let mut n_already = 0usize;
    let mut n_clean = 0usize;
    let mut n_adapt = 0usize;
    let mut clean_shas = Vec::new();
    let mut adapt_shas = Vec::new();
    let mut all_prereqs: BTreeMap<(String, u32, String), (&'static str, Option<u32>, String, Vec<String>)> = BTreeMap::new();

    for (i, r) in rows.iter().enumerate() {
        match r.status.as_str() {
            "IN-LOG" | "ALREADY" | "ALREADY-CODE" => n_already += 1,
            "CLEAN" | "CLEAN-C1" | "CLEAN-NODOC" => {
                n_clean += 1;
                clean_shas.push(r.short.clone());
            }
            _ => {
                n_adapt += 1;
                adapt_shas.push(r.short.clone());
            }
        }
        let flag_s = if r.flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", r.flags.join(" "))
        };
        println!(
            "  {:>2}. {:<12} {:<9} {} {} | {:<28} | {}{}",
            i + 1,
            r.status,
            r.btag,
            r.risk,
            r.short,
            truncate_str(&r.file_preview, 28),
            truncate_str(&r.subj, 46),
            flag_s
        );
        for (psha, pstate, pnum, psubj, sid) in &r.missing_prereqs {
            let key = (sid.clone(), pnum.unwrap_or(999), psha.clone());
            let entry = all_prereqs
                .entry(key)
                .or_insert_with(|| (*pstate, *pnum, psubj.clone(), Vec::new()));
            if !entry.3.contains(&r.short) {
                entry.3.push(r.short.clone());
            }
        }
    }

    if !all_prereqs.is_empty() {
        println!("\n--- MISSING UPSTREAM SERIES PREREQUISITES ({}, grouped by series & patch #) ---", all_prereqs.len());
        let mut last_sid = String::new();
        for ((sid, _, psha), (pstate, pnum, psubj, needed_by)) in &all_prereqs {
            if *sid != last_sid {
                println!("  [series {sid}]");
                last_sid = sid.clone();
            }
            let pno = pnum.map(|n| format!("#{n:<2}")).unwrap_or_else(|| "   ".into());
            println!(
                "    {:<7} {pno} {psha} | {:<50} <- before {}",
                pstate,
                truncate_str(psubj, 50),
                needed_by.join(",")
            );
        }
    }

    println!(
        "\nSummary: {n_already} already/in-log | {n_clean} clean | {n_adapt} adapt | {} missing series prereq(s)",
        all_prereqs.len()
    );
    if !clean_shas.is_empty() {
        println!(
            "Batch apply (w/ live clang check):\n  kawal backport-apply {upstream_repo} --check {}",
            ordered.iter().map(|s| truncate_str(s, 10)).collect::<Vec<_>>().join(" ")
        );
    }
    if !adapt_shas.is_empty() {
        println!(
            "Inspect semantic conflicts:\n  kawal backport-ctx {upstream_repo} {}",
            adapt_shas.join(" ")
        );
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unified_diff_and_hunk_header() {
        let diff = "\
diff --git a/mm/util.c b/mm/util.c
index 1111111..2222222 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -620,7 +620,9 @@ static gfp_t kmalloc_gfp_adjust(gfp_t flags, size_t size)
 \tif (size > PAGE_SIZE) {
-\t\tflags |= __GFP_NORETRY;
+\t\tflags &= ~__GFP_DIRECT_RECLAIM;
 \t}
";
        let fps = parse_unified_diff(diff);
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].display_path(), "mm/util.c");
        assert_eq!(fps[0].hunks.len(), 1);
        assert_eq!(fps[0].hunks[0].old_start, 620);
        assert_eq!(extract_func_name(&fps[0].hunks[0].func_ctx), Some("kmalloc_gfp_adjust".into()));
    }

    #[test]
    fn test_strip_doc_sections() {
        let mbox = "\
From abc
Subject: test

---
diff --git a/Documentation/foo.rst b/Documentation/foo.rst
--- a/Documentation/foo.rst
+++ b/Documentation/foo.rst
@@ -1 +1 @@
-a
+b
diff --git a/fs/f2fs/super.c b/fs/f2fs/super.c
--- a/fs/f2fs/super.c
+++ b/fs/f2fs/super.c
@@ -1 +1 @@
-x
+y
-- 
2.45
";
        let stripped = strip_doc_sections_from_mbox(mbox);
        assert!(!stripped.contains("Documentation/foo.rst"));
        assert!(stripped.contains("fs/f2fs/super.c"));
    }
}
