use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::merge_intel::{is_clo_soc_path, ACK_PROTECTED_MARKERS};
use crate::util::{
    git, git_in, git_rc, git_stdin, is_built_file, norm_subj, par_map, rg, run_cmd, truncate_str,
    Ctx, BOILERPLATE_PREFIXES, C_KEYWORDS, NOT_A_CALL,
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

/// Compute how much of a patch's meaningful `+` lines are ALREADY present in local HEAD files.
/// Returns `(matched, total, pct)` across all non-doc C/H files.
pub fn semantic_already_ratio(ctx: &Ctx, file_patches: &[FilePatch]) -> (usize, usize, usize) {
    let mut matched = 0usize;
    let mut total = 0usize;
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
            // Check both pure additions and net-changed lines
            let del_set: HashSet<String> = h
                .lines
                .iter()
                .filter_map(|l| l.strip_prefix('-'))
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
                }
            }
        }
    }
    let pct = if total == 0 {
        0
    } else {
        (matched * 100) / total
    };
    (matched, total, pct)
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

/// Extract C function call identifiers newly introduced in `+` lines that might not exist in 6.12.
fn extract_new_calls_in_hunk(h: &PatchHunk) -> BTreeSet<String> {
    let mut del_syms = HashSet::new();
    let mut add_syms = BTreeSet::new();
    let scan = |s: &str, out: &mut Vec<String>| {
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_alphabetic() || b[i] == b'_' {
                let st = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let ident = &s[st..i];
                let mut j = i;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len()
                    && b[j] == b'('
                    && ident.len() >= 5
                    && !NOT_A_CALL.contains(&ident)
                    && !C_KEYWORDS.contains(&ident)
                {
                    out.push(ident.to_string());
                }
            } else {
                i += 1;
            }
        }
    };
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('-') {
            let mut v = Vec::new();
            scan(body, &mut v);
            for s in v {
                del_syms.insert(s);
            }
        } else if let Some(body) = l.strip_prefix(' ') {
            let mut v = Vec::new();
            scan(body, &mut v);
            for s in v {
                del_syms.insert(s);
            }
        }
    }
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('+') {
            let t = body.trim();
            if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
                continue;
            }
            let mut v = Vec::new();
            scan(body, &mut v);
            for s in v {
                if !del_syms.contains(&s) {
                    add_syms.insert(s);
                }
            }
        }
    }
    add_syms
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
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let expanded_shas = expand_shas(shas);
    if expanded_shas.is_empty() {
        eprintln!("usage: kawal backport-check <upstream.git> [--apply-clean] [--no-doc] <shas...|@file>");
        return 2;
    }

    let local_log = git(ctx, &["log", "--no-merges", "-n", "20000", "--format=%s", "HEAD"]);
    let local_subjs: HashSet<String> = local_log.lines().map(norm_subj).collect();

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
    stop_on_conflict: bool,
) -> i32 {
    let up_path = Path::new(upstream_repo);
    if !up_path.exists() {
        eprintln!("!! upstream git mirror not found: {upstream_repo}");
        return 2;
    }
    let expanded = expand_shas(shas);
    if expanded.is_empty() {
        eprintln!("usage: kawal backport-apply <upstream.git> [--no-doc] [--no-sign] [--stop-on-conflict] <shas...|@file>");
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
    let mut conflicts: Vec<String> = Vec::new();

    println!(
        "=== kawal backport-apply ({} commits, sign={}, no_doc={}) ===",
        expanded.len(),
        sign,
        no_doc
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
            println!("  {:<12} {short} | {}", tag, truncate_str(&subj, 60));
            local_subjs.insert(norm_subj(&subj));
            applied += 1;
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
        "Summary: {} applied | {} skipped (already in HEAD) | {} conflict(s)",
        applied,
        skipped,
        conflicts.len()
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

    // Cache symbol existence checks across commits to avoid duplicate rg calls
    let mut sym_cache: HashMap<String, bool> = HashMap::new();
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
            let mut file_had_conflict = false;

            for (hi, h) in fp.hunks.iter().enumerate() {
                let single_patch = fp.single_hunk_patch(hi);
                let fn_label = extract_func_name(&h.func_ctx)
                    .unwrap_or_else(|| truncate_str(&h.func_ctx, 32).to_string());
                let n_add = h.lines.iter().filter(|l| l.starts_with('+')).count();
                let n_del = h.lines.iter().filter(|l| l.starts_with('-')).count();

                // 1. Test individual hunk against HEAD
                if git_stdin(ctx, &["apply", "--check", "--reverse"], single_patch.as_bytes()).0 == 0
                    || hunk_already_in_local(h, &orig_norm_set)
                {
                    println!("  [HUNK-DUP]  #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> already in HEAD", hi + 1, fp.hunks.len());
                    if !all_hunks {
                        continue;
                    }
                } else if git_stdin(ctx, &["apply", "--check", "-C1"], single_patch.as_bytes()).0 == 0 {
                    if stage_ok_hunks {
                        if git_stdin(ctx, &["apply", "-C1"], single_patch.as_bytes()).0 == 0 {
                            staged_ok += 1;
                            println!("  [APPLIED]   #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> applied to working tree!", hi + 1, fp.hunks.len());
                            continue;
                        }
                    } else {
                        println!("  [HUNK-OK]   #{}/{} {fn_label}() (+{n_add}/-{n_del}) -> applies cleanly with -C1", hi + 1, fp.hunks.len());
                        if !all_hunks {
                            continue;
                        }
                    }
                } else {
                    file_had_conflict = true;
                    remaining_conflicts += 1;
                    println!("  [CONFLICT]  #{}/{} {fn_label}() (+{n_add}/-{n_del})", hi + 1, fp.hunks.len());
                }

                // 2. Print compact upstream hunk (strip leading/trailing unchanged lines beyond 2)
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

                // 4. Flag any new helper calls introduced in `+` lines that are absent in HEAD
                let new_calls = extract_new_calls_in_hunk(h);
                let mut undef = Vec::new();
                for sym in new_calls {
                    let exists = *sym_cache.entry(sym.clone()).or_insert_with(|| {
                        let pat = format!(r"\b{sym}\b");
                        let (rc, _) = rg(
                            &ctx.repo,
                            &["-q", "-g", "*.[ch]", &pat, "include", "mm", "kernel", "fs", "net", "block", "arch/arm64", "drivers"],
                        );
                        rc == 0
                    });
                    if !exists {
                        undef.push(sym);
                    }
                }
                if !undef.is_empty() {
                    println!("  [UNDEF-SYM] New call(s) NOT found in HEAD: {}", undef.join(", "));
                }
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

    #[test]
    fn test_extract_new_calls_in_hunk() {
        let h = PatchHunk {
            header: "@@ -1,3 +1,4 @@ static void foo(void)".into(),
            old_start: 1,
            old_count: 3,
            func_ctx: "static void foo(void)".into(),
            lines: vec![
                " \told_helper(x);".into(),
                "-\tremove_me(x);".into(),
                "+\tbrand_new_helper(x);".into(),
                "+\tif (unlikely(x)) return;".into(),
            ],
        };
        let calls = extract_new_calls_in_hunk(&h);
        assert!(calls.contains("brand_new_helper"));
        assert!(!calls.contains("old_helper"));
        assert!(!calls.contains("unlikely"));
    }
}
