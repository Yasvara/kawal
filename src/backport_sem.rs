use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::backport::{extract_func_name, FilePatch, PatchHunk};
use crate::util::{
    git_in, git_stdin, is_ident_char, is_ident_start, norm_subj, rg, run_cmd, strip_c_comments,
    truncate_str, Ctx, C_KEYWORDS, GENERIC_MEMBERS, NOT_A_CALL,
};

// ====================================================== 1. Upstream Patch-Series Tracker

#[derive(Debug, Clone)]
pub struct SeriesSibling {
    pub sha: String,
    pub patch_num: Option<u32>,
    pub subj: String,
    pub state: &'static str, // "SELF" | "IN-HEAD" | "IN-BATCH" | "CLEAN" | "MISSING"
    pub is_before: bool,
}

#[derive(Debug, Clone)]
pub struct SeriesInfo {
    pub series_id: String,
    pub self_num: Option<u32>,
    pub siblings: Vec<SeriesSibling>,
}

/// Extract upstream mailing-list series prefix from `Link:` / `Message-Id:` trailers.
/// Example: `https://lkml.kernel.org/r/20250303022425.285971-12-senozhatsky@chromium.org`
///   -> `Some(("20250303022425.285971-", Some(12)))`
pub fn extract_series_id(commit_body: &str) -> Option<(String, Option<u32>)> {
    for ln in commit_body.lines() {
        let t = ln.trim();
        let low = t.to_ascii_lowercase();
        if !low.starts_with("link:") && !low.starts_with("message-id:") {
            continue;
        }
        let payload = if let Some(idx) = t.find("/r/") {
            &t[idx + 3..]
        } else if let Some(idx) = t.find("msgid.link/") {
            &t[idx + 11..]
        } else if let Some(idx) = t.find('<') {
            t[idx + 1..].trim_end_matches('>')
        } else {
            continue;
        };
        let payload = payload.trim().trim_end_matches('/');
        // Match `<8..16 digits>.<digits>-<num>-<rest>` (git send-email / b4 series format)
        let bytes = payload.as_bytes();
        let mut i = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i < 8 || i >= bytes.len() || bytes[i] != b'.' {
            continue;
        }
        let dot = i;
        i += 1;
        let pid_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == pid_start || i >= bytes.len() || bytes[i] != b'-' {
            continue;
        }
        let prefix_end = i + 1; // includes trailing '-'
        i += 1;
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i > num_start && i < bytes.len() && bytes[i] == b'-' {
            let num = payload[num_start..i].parse::<u32>().ok();
            let prefix = payload[..prefix_end].to_string();
            // Reject tiny degenerate dates like 20250101.1-
            if dot >= 8 && prefix.len() >= 12 {
                return Some((prefix, num));
            }
        }
    }
    None
}

/// Find sibling patches in the same upstream mailing-list series and classify whether each
/// preceding/following patch is already in local HEAD, in the user's current batch, or missing.
pub fn find_series_siblings(
    ctx: &Ctx,
    up_path: &Path,
    full_sha: &str,
    local_subjs: &HashSet<String>,
    batch_full_shas: &HashSet<String>,
) -> Option<SeriesInfo> {
    let body = git_in(up_path, &["show", "-s", "--format=%b", full_sha]);
    let (series_id, self_num) = extract_series_id(&body)?;

    // Fast git log grep over v6.12..HEAD of upstream mirror for the exact series msgid prefix
    let grep_arg = format!("--grep={series_id}");
    let out = git_in(
        up_path,
        &[
            "log",
            "--no-merges",
            "--reverse",
            &grep_arg,
            "--format=%H\t%s",
            "v6.12..HEAD",
        ],
    );
    let mut rows: Vec<(String, String)> = Vec::new();
    for ln in out.lines() {
        if let Some((h, s)) = ln.split_once('\t') {
            if !h.is_empty() && !s.is_empty() {
                rows.push((h.to_string(), s.to_string()));
            }
        }
    }
    if rows.len() <= 1 {
        return None;
    }

    let self_pos = rows.iter().position(|(h, _)| h == full_sha).unwrap_or(rows.len());
    let mut siblings = Vec::with_capacity(rows.len());
    for (idx, (h, s)) in rows.into_iter().enumerate() {
        let is_before = idx < self_pos;
        let state = if h == full_sha {
            "SELF"
        } else if local_subjs.contains(&norm_subj(&s)) {
            "IN-HEAD"
        } else if batch_full_shas.contains(&h) {
            "IN-BATCH"
        } else if is_before {
            // Quick reverse-apply check to catch ACK-rebased / differently-titled already-applied commits
            let (rc_p, pstr, _) = run_cmd("git", &["format-patch", "-1", "--stdout", &h], up_path, None);
            if rc_p == 0 && git_stdin(ctx, &["apply", "--check", "--reverse"], pstr.as_bytes()).0 == 0 {
                "IN-HEAD"
            } else if rc_p == 0 && git_stdin(ctx, &["apply", "--check", "-C1"], pstr.as_bytes()).0 == 0 {
                "CLEAN"
            } else {
                "MISSING"
            }
        } else {
            "MISSING"
        };
        let pnum = git_in(up_path, &["show", "-s", "--format=%b", &h]);
        let num = extract_series_id(&pnum).and_then(|(_, n)| n);
        siblings.push(SeriesSibling {
            sha: truncate_str(&h, 10).to_string(),
            patch_num: num,
            subj: s,
            state,
            is_before,
        });
    }
    Some(SeriesInfo {
        series_id,
        self_num,
        siblings,
    })
}

// ====================================================== 2. C Call-Site Arity & Param Parser

/// Parse all C function calls in a code snippet and return `(func_name, Some(arity))`
/// (or `None` if the closing `)` is outside the snippet).
pub fn extract_call_sites_with_arity(code: &str) -> Vec<(String, Option<usize>)> {
    let clean = strip_c_comments(code);
    let bytes = clean.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;

    while i < n {
        // Skip string / char literals
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let q = bytes[i];
            i += 1;
            while i < n {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Skip preprocessor #define lines (macro definitions, not calls)
        if bytes[i] == b'#' {
            let line_start = clean[..i].rfind('\n').map(|p| p + 1).unwrap_or(0);
            if clean[line_start..i].trim().is_empty() {
                let rest = clean[i + 1..].trim_start();
                if rest.starts_with("define ") || rest.starts_with("define\t") {
                    while i < n && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
            }
        }
        if is_ident_start(bytes[i]) {
            let st = i;
            while i < n && is_ident_char(bytes[i]) {
                i += 1;
            }
            let ident = &clean[st..i];
            let mut j = i;
            while j < n && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < n && bytes[j] == b'(' {
                if ident.len() < 4 || NOT_A_CALL.contains(&ident) || C_KEYWORDS.contains(&ident) {
                    continue;
                }
                // Check what precedes `ident` on the same statement to filter out declarations/member-calls
                let before = clean[..st].trim_end();
                if before.ends_with("->") || before.ends_with('.') {
                    continue;
                }
                // Skip function definitions/prototypes: preceded by a type identifier (not `return`/`else`/`case`)
                if looks_like_decl_prefix(before) {
                    continue;
                }
                let arity = count_call_args_from(&clean[j..]);
                out.push((ident.to_string(), arity));
            }
            continue;
        }
        i += 1;
    }
    out
}

fn looks_like_decl_prefix(before: &str) -> bool {
    if before.is_empty() {
        return false;
    }
    // Check if preceded by `*` (e.g. `struct foo *bar(`) or an identifier (e.g. `int bar(`)
    let stripped = before.trim_end_matches(|c: char| c == '*' || c.is_ascii_whitespace());
    if stripped.is_empty() {
        return false;
    }
    let last_ch = stripped.as_bytes()[stripped.len() - 1];
    if !is_ident_char(last_ch) {
        return false;
    }
    let mut k = stripped.len();
    let b = stripped.as_bytes();
    while k > 0 && is_ident_char(b[k - 1]) {
        k -= 1;
    }
    let prev_word = &stripped[k..];
    // `return foo(`, `else foo(`, `case foo(` are calls, NOT declarations!
    if matches!(prev_word, "return" | "else" | "case" | "goto" | "do") {
        return false;
    }
    // If preceded by `*` AND earlier token on same line has assignment/operator (`x = a * foo(`), it's multiplication!
    if before.trim_end().ends_with('*') {
        let line = before.rsplit('\n').next().unwrap_or(before);
        if line.contains('=') || line.contains("return ") || line.contains("if ") || line.contains("if(") {
            return false;
        }
    }
    true
}

/// Given `s` starting at `(`, count the top-level comma-separated arguments until matching `)`.
fn count_call_args_from(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut commas = 0usize;
    let mut has_non_ws = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' {
            has_non_ws = true;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if c == b'(' || c == b'[' || c == b'{' {
            if depth >= 1 {
                has_non_ws = true;
            }
            depth += 1;
        } else if c == b')' || c == b']' || c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(if has_non_ws { commas + 1 } else { 0 });
            }
        } else if c == b',' && depth == 1 {
            commas += 1;
        } else if depth == 1 && !c.is_ascii_whitespace() {
            has_non_ws = true;
        }
        i += 1;
    }
    None
}

/// Count formal parameters in a C function or macro parameter list starting at `(`.
/// Returns `None` for variadic (`...`) or incomplete lists.
pub fn count_fn_params(paren_slice: &str) -> Option<usize> {
    let b = paren_slice.as_bytes();
    if b.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut end = None;
    for (i, &c) in b.iter().enumerate() {
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                end = Some(i);
                break;
            }
        }
    }
    let inner = paren_slice[1..end?].trim();
    if inner.is_empty() || inner == "void" {
        return Some(0);
    }
    if inner.contains("...") {
        return None;
    }
    // Count top-level commas (outside nested parens like `void (*cb)(int, int)`)
    let mut pdepth = 0i32;
    let mut commas = 0usize;
    for &c in inner.as_bytes() {
        match c {
            b'(' | b'[' | b'{' => pdepth += 1,
            b')' | b']' | b'}' => pdepth -= 1,
            b',' if pdepth == 0 => commas += 1,
            _ => {}
        }
    }
    Some(commas + 1)
}

/// Extract `#define SYM(a, b)` or C function signature(s) for `sym` from local tree.
#[derive(Debug, Clone)]
pub struct FnSigMatch {
    pub loc: String,
    pub arity: Option<usize>,
    pub sig_line: String,
}

fn find_local_fn_sigs(ctx: &Ctx, orig_path: &str, sym: &str) -> Vec<FnSigMatch> {
    let subdir = Path::new(orig_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut search_paths: Vec<&str> = vec!["include", "arch/arm64/include"];
    if !subdir.is_empty() && !matches!(subdir.as_str(), "include" | "arch/arm64/include") {
        search_paths.push(&subdir);
    }
    if Path::new(orig_path).extension().and_then(|e| e.to_str()) == Some("c")
        && ctx.repo.join(orig_path).is_file()
        && !search_paths.contains(&orig_path)
    {
        search_paths.insert(0, orig_path);
    }

    let pat = format!(r"(^#define\s+{sym}\s*\(|\b{sym}\s*\()");
    let mut args = vec!["-n", "-A", "5", "-g", "*.[ch]", &pat];
    args.extend_from_slice(&search_paths);
    let (rc, out) = rg(&ctx.repo, &args);
    if rc != 0 || out.trim().is_empty() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let mut seen_loc = HashSet::new();
    // Parse rg `-n -A 5` blocks separated by `--`
    let mut blocks: Vec<Vec<&str>> = vec![Vec::new()];
    for ln in out.lines() {
        if ln == "--" {
            blocks.push(Vec::new());
        } else {
            blocks.last_mut().unwrap().push(ln);
        }
    }

    for blk in blocks {
        if blk.is_empty() {
            continue;
        }
        // First matching line has `file:line:text` (context lines have `file-line-text`)
        let first = blk[0];
        let Some((file, rest)) = first.split_once(':') else { continue };
        let Some((lno, text)) = rest.split_once(':') else { continue };
        if !lno.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let loc = format!("{file}:{lno}");
        if !seen_loc.insert(loc.clone()) {
            continue;
        }
        let t = text.trim();
        // Skip comments
        if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        // Check macro definition: `#define sym(a, b)`
        let macro_pat = format!("#define {sym}(");
        if t.starts_with(&macro_pat) || (t.starts_with("#define") && t.contains(&format!("{sym}("))) {
            if let Some(p) = t.find(&format!("{sym}(")) {
                let slice = &t[p + sym.len()..];
                matches.push(FnSigMatch {
                    loc,
                    arity: count_fn_params(slice),
                    sig_line: truncate_str(t, 110).to_string(),
                });
            }
            continue;
        }
        // Check C function declaration/definition (must have a type before `sym(` and NOT be a call)
        let Some(pos) = text.find(&format!("{sym}(")) else { continue };
        let before = text[..pos].trim();
        let is_def = if before.is_empty() {
            // Return type might be on previous line (only if text starts at col 0 without indent)
            !text.starts_with(' ') && !text.starts_with('\t')
        } else {
            looks_like_decl_prefix(before)
                && !text.trim_start().starts_with("if")
                && !text.trim_start().starts_with("return")
                && !before.contains('=')
        };
        if !is_def {
            continue;
        }
        // Join block text from `(` onward to capture multi-line signatures
        let mut joined = String::from(&text[pos + sym.len()..]);
        for ctx_ln in &blk[1..] {
            // Strip `file-line-` or `file:line:` prefix
            let body = if let Some(p1) = ctx_ln.find('-') {
                ctx_ln[p1 + 1..].split_once('-').map(|(_, r)| r).unwrap_or("")
            } else {
                ""
            };
            joined.push(' ');
            joined.push_str(body.trim());
        }
        let clean_joined = strip_c_comments(&joined);
        // Verify it looks like a real prototype/definition (followed by `{` or `;` after `)`)
        if let Some(ar) = count_fn_params(&clean_joined) {
            let compact: String = clean_joined
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let sig = format!("{before} {sym}{}", truncate_str(&compact, 85));
            matches.push(FnSigMatch {
                loc,
                arity: Some(ar),
                sig_line: truncate_str(sig.trim(), 115).to_string(),
            });
        }
    }
    matches
}

/// Fetch upstream definition snippet AND introducing commit SHA for a missing symbol/constant/field.
fn fetch_upstream_sym_info(
    up_path: &Path,
    full_sha: &str,
    orig_path: &str,
    sym: &str,
) -> (Option<String>, Option<String>) {
    let subdir = Path::new(orig_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut paths = vec!["include/", "arch/arm64/include/", orig_path];
    if !subdir.is_empty() && !matches!(subdir.as_str(), "include" | "arch/arm64/include") {
        paths.push(&subdir);
    }

    // 1. Find definition in upstream at `full_sha`
    let pat = format!(r"(#define[[:space:]]+{sym}\b|\b{sym}[[:space:]]*\(|\b{sym}[[:space:]]*=)");
    let mut gargs = vec!["grep", "-n", "-E", &pat, full_sha, "--"];
    gargs.extend_from_slice(&paths);
    let gout = git_in(up_path, &gargs);
    let mut def_snippet = None;
    for ln in gout.lines() {
        // format: `<sha>:<file>:<lno>:<text>`
        let parts: Vec<&str> = ln.splitn(4, ':').collect();
        if parts.len() < 4 {
            continue;
        }
        let (file, lno_s, txt) = (parts[1], parts[2], parts[3]);
        let t = txt.trim();
        if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        let is_good = t.starts_with("#define")
            || t.contains(&format!("{sym} ="))
            || t.contains(&format!("{sym}="))
            || (!t.starts_with("if") && !t.starts_with("return") && t.find(&format!("{sym}(")).is_some_and(|p| {
                let b = t[..p].trim();
                !b.is_empty() && looks_like_decl_prefix(b)
            }));
        if is_good {
            if let Ok(lno) = lno_s.parse::<usize>() {
                // Grab up to 5 lines from upstream blob for inline wrapper clarity!
                let spec = format!("{full_sha}:{file}");
                let blob = git_in(up_path, &["show", &spec]);
                let blines: Vec<&str> = blob.lines().collect();
                let st = lno.saturating_sub(1);
                let en = (st + 6).min(blines.len());
                let mut snip = format!("{file}:{lno}:");
                for &bl in &blines[st..en] {
                    snip.push_str("\n        ");
                    snip.push_str(bl);
                    if bl.trim() == "}" || (bl.trim().ends_with(';') && !bl.trim().starts_with("static") && bl != blines[st]) {
                        break;
                    }
                }
                def_snippet = Some(snip);
                break;
            }
        }
    }

    // 2. Find which upstream commit in v6.12..full_sha introduced `sym`
    let range = format!("v6.12..{full_sha}");
    let s_flag = format!("-S{sym}");
    let mut largs = vec![
        "log",
        "--no-merges",
        "--reverse",
        "-n",
        "1",
        "--format=%h %s",
        &s_flag,
        &range,
        "--",
    ];
    largs.extend_from_slice(&paths);
    let intro_raw = git_in(up_path, &largs);
    let intro = intro_raw
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| truncate_str(s, 85).to_string());

    (def_snippet, intro)
}

// ====================================================== 3. Semantic Hunk & File Diagnostics

#[derive(Debug, Default)]
pub struct SemanticCache {
    pub sym_exists: HashMap<String, bool>,
    pub local_sigs: HashMap<(String, String), Vec<FnSigMatch>>,
    pub up_sym_info: HashMap<(String, String), (Option<String>, Option<String>)>,
}

#[derive(Debug, Default)]
pub struct HunkSemReport {
    pub api_drifts: Vec<String>,
    pub undef_syms: Vec<String>,
    pub undef_consts: Vec<String>,
    pub undef_fields: Vec<String>,
    pub atomic_sleeps: Vec<String>,
}

/// Extract newly added ALL_CAPS enum/flag constants (e.g. `FPB_RESPECT_WRITE`, `ZRAM_PP_SLOT`)
/// that don't appear in `-` or context lines.
pub fn extract_new_consts_in_hunk(h: &PatchHunk) -> BTreeSet<String> {
    let mut old_set = HashSet::new();
    let mut new_set = BTreeSet::new();
    let scan = |s: &str, out: &mut Vec<String>| {
        let clean = strip_c_comments(s);
        let b = clean.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_uppercase() {
                let st = i;
                while i < b.len() && (b[i].is_ascii_uppercase() || b[i].is_ascii_digit() || b[i] == b'_') {
                    i += 1;
                }
                let tok = &clean[st..i];
                // Must look like a multi-word kernel flag/enum (contains `_`, len >= 6, not followed by `(`)
                let next_is_paren = i < b.len() && b[i] == b'(';
                if tok.len() >= 6
                    && tok.contains('_')
                    && !next_is_paren
                    && !tok.starts_with("CONFIG_")
                    && !tok.starts_with("GFP_")
                    && !tok.starts_with("__GFP_")
                    && !tok.starts_with("PAGE_")
                    && !tok.starts_with("HPAGE_")
                    && !tok.starts_with("PMD_")
                    && !tok.starts_with("PTE_")
                    && !tok.starts_with("EINVAL")
                    && !tok.starts_with("ENOMEM")
                    && !tok.starts_with("EAGAIN")
                    && !tok.starts_with("WARN_")
                    && !tok.starts_with("BUG_")
                    && !tok.starts_with("VM_WARN")
                    && !tok.starts_with("ULL")
                {
                    out.push(tok.to_string());
                }
            } else {
                i += 1;
            }
        }
    };
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('-').or_else(|| l.strip_prefix(' ')) {
            let mut v = Vec::new();
            scan(body, &mut v);
            old_set.extend(v);
        }
    }
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('+') {
            let t = body.trim();
            if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") || t.starts_with("#define") {
                continue;
            }
            let mut v = Vec::new();
            scan(body, &mut v);
            for tok in v {
                if !old_set.contains(&tok) {
                    new_set.insert(tok);
                }
            }
        }
    }
    new_set
}

/// Extract newly introduced `->field` accesses in `+` lines (excluding generic members).
pub fn extract_new_fields_in_hunk(h: &PatchHunk) -> BTreeSet<String> {
    let mut old_set = HashSet::new();
    let mut new_set = BTreeSet::new();
    let scan = |s: &str, out: &mut Vec<String>| {
        let clean = strip_c_comments(s);
        let b = clean.as_bytes();
        let mut i = 0;
        while i + 2 < b.len() {
            if b[i] == b'-' && b[i + 1] == b'>' && is_ident_start(b[i + 2]) {
                let st = i + 2;
                let mut j = st;
                while j < b.len() && is_ident_char(b[j]) {
                    j += 1;
                }
                let fld = &clean[st..j];
                let is_call = j < b.len() && b[j] == b'(';
                if fld.len() >= 4 && !is_call && !GENERIC_MEMBERS.contains(&fld) && !C_KEYWORDS.contains(&fld) {
                    out.push(fld.to_string());
                }
                i = j;
            } else {
                i += 1;
            }
        }
    };
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('-').or_else(|| l.strip_prefix(' ')) {
            let mut v = Vec::new();
            scan(body, &mut v);
            old_set.extend(v);
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
            for fld in v {
                if !old_set.contains(&fld) {
                    new_set.insert(fld);
                }
            }
        }
    }
    new_set
}

/// Analyze a hunk for API arity drift, missing symbols/constants/fields (with upstream definitions!),
/// and atomic-context sleeping bugs.
pub fn analyze_hunk_semantics(
    ctx: &Ctx,
    up_path: &Path,
    full_sha: &str,
    fp: &FilePatch,
    h: &PatchHunk,
    local_file_txt: &str,
    cache: &mut SemanticCache,
    fetch_upstream: bool,
) -> HunkSemReport {
    let mut rep = HunkSemReport::default();
    let orig_path = fp.display_path();

    // 1. Gather contiguous `+` code blocks to preserve multi-line calls
    let mut plus_code = String::new();
    let mut old_calls: HashSet<String> = HashSet::new();
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('+') {
            plus_code.push_str(body);
            plus_code.push('\n');
        } else if let Some(body) = l.strip_prefix('-').or_else(|| l.strip_prefix(' ')) {
            for (c, _) in extract_call_sites_with_arity(body) {
                old_calls.insert(c);
            }
        }
    }

    // Collect functions defined in this commit itself so we don't flag self-added helpers as missing
    let mut patch_defined: HashSet<String> = HashSet::new();
    for ph in &fp.hunks {
        for l in &ph.lines {
            if let Some(body) = l.strip_prefix('+') {
                let t = body.trim();
                if let Some(rest) = t.strip_prefix("#define ") {
                    if let Some(nm) = rest.split(|c: char| !is_ident_char(c as u8)).next() {
                        patch_defined.insert(nm.to_string());
                    }
                } else if let Some(fnm) = extract_func_name(t) {
                    if !t.ends_with(';') || t.starts_with("static ") || t.starts_with("extern ") {
                        patch_defined.insert(fnm);
                    }
                }
            }
        }
    }

    let calls = extract_call_sites_with_arity(&plus_code);
    let mut seen_checked = HashSet::new();
    for (sym, arity_opt) in calls {
        if patch_defined.contains(&sym) {
            continue;
        }
        let key = (sym.clone(), arity_opt);
        if !seen_checked.insert(key) {
            continue;
        }

        // Check symbol existence in target tree
        let exists = *cache.sym_exists.entry(sym.clone()).or_insert_with(|| {
            if local_file_txt.contains(&format!("{sym}(")) {
                return true;
            }
            let pat = format!(r"\b{sym}\b");
            let (rc, _) = rg(
                &ctx.repo,
                &[
                    "-q",
                    "-g",
                    "*.[ch]",
                    &pat,
                    "include",
                    "mm",
                    "kernel",
                    "fs",
                    "net",
                    "block",
                    "arch/arm64",
                    "drivers",
                    "lib",
                ],
            );
            rc == 0
        });

        if !exists {
            if !old_calls.contains(&sym) {
                let mut msg = format!("{sym}() NOT found in HEAD");
                if fetch_upstream {
                    let (def_opt, intro_opt) = cache
                        .up_sym_info
                        .entry((full_sha.to_string(), sym.clone()))
                        .or_insert_with(|| fetch_upstream_sym_info(up_path, full_sha, orig_path, &sym))
                        .clone();
                    if let Some(intro) = intro_opt {
                        msg.push_str(&format!("\n      introduced by: {intro}"));
                    }
                    if let Some(def) = def_opt {
                        msg.push_str(&format!("\n      upstream def: {def}"));
                    }
                }
                rep.undef_syms.push(msg);
            }
            continue;
        }

        // Symbol exists in target — check ARITY DRIFT!
        if let Some(call_ar) = arity_opt {
            let sig_key = (orig_path.to_string(), sym.clone());
            let sigs = cache
                .local_sigs
                .entry(sig_key)
                .or_insert_with(|| find_local_fn_sigs(ctx, orig_path, &sym))
                .clone();
            let known_arities: Vec<usize> = sigs.iter().filter_map(|s| s.arity).collect();
            if !known_arities.is_empty() && !known_arities.contains(&call_ar) {
                let first_sig = &sigs[0];
                let expected = known_arities
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("/");
                let mut msg = format!(
                    "{sym}(): patch passes {call_ar} arg(s), HEAD expects {expected} ({}: {})",
                    first_sig.loc, first_sig.sig_line
                );
                if fetch_upstream {
                    let (def_opt, _) = cache
                        .up_sym_info
                        .entry((full_sha.to_string(), sym.clone()))
                        .or_insert_with(|| fetch_upstream_sym_info(up_path, full_sha, orig_path, &sym))
                        .clone();
                    if let Some(def) = def_opt {
                        let first_ln = def.lines().take(2).collect::<Vec<_>>().join(" ");
                        msg.push_str(&format!("\n      upstream sig: {}", truncate_str(&first_ln, 115)));
                    }
                }
                rep.api_drifts.push(msg);
            }
        }
    }

    // 2. Newly added ALL_CAPS constants/enums missing in HEAD
    for c in extract_new_consts_in_hunk(h) {
        if patch_defined.contains(&c) {
            continue;
        }
        let exists = *cache.sym_exists.entry(c.clone()).or_insert_with(|| {
            if local_file_txt.contains(&c) {
                return true;
            }
            let pat = format!(r"\b{c}\b");
            let (rc, _) = rg(
                &ctx.repo,
                &["-q", "-g", "*.[ch]", &pat, "include", "mm", "kernel", "fs", "net", "block", "arch/arm64", "drivers"],
            );
            rc == 0
        });
        if !exists {
            let mut msg = format!("{c} NOT found in HEAD");
            if fetch_upstream {
                let (def_opt, intro_opt) = cache
                    .up_sym_info
                    .entry((full_sha.to_string(), c.clone()))
                    .or_insert_with(|| fetch_upstream_sym_info(up_path, full_sha, orig_path, &c))
                    .clone();
                if let Some(intro) = intro_opt {
                    msg.push_str(&format!("  (from: {intro})"));
                }
                if let Some(def) = def_opt {
                    let first_ln = def.lines().take(2).collect::<Vec<_>>().join(" ");
                    msg.push_str(&format!("\n      upstream: {}", truncate_str(&first_ln, 115)));
                }
            }
            rep.undef_consts.push(msg);
            if rep.undef_consts.len() >= 4 {
                break;
            }
        }
    }

    // 3. Newly added `->field` accesses missing in HEAD
    for fld in extract_new_fields_in_hunk(h) {
        let key = format!("field:{fld}");
        let exists = *cache.sym_exists.entry(key).or_insert_with(|| {
            if local_file_txt.contains(&fld) {
                return true;
            }
            let subdir = Path::new(orig_path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let pat = format!(r"\b{fld}\b");
            let mut args = vec!["-q", "-g", "*.h", &pat, "include", "arch/arm64/include"];
            if !subdir.is_empty() {
                args.push(&subdir);
            }
            rg(&ctx.repo, &args).0 == 0
        });
        if !exists {
            let mut msg = format!("->{fld} NOT found in HEAD headers");
            if fetch_upstream {
                let (_, intro_opt) = cache
                    .up_sym_info
                    .entry((full_sha.to_string(), fld.clone()))
                    .or_insert_with(|| fetch_upstream_sym_info(up_path, full_sha, orig_path, &fld))
                    .clone();
                if let Some(intro) = intro_opt {
                    msg.push_str(&format!("  (added by: {intro})"));
                }
            }
            rep.undef_fields.push(msg);
            if rep.undef_fields.len() >= 4 {
                break;
            }
        }
    }

    // 4. Atomic-context sleep-under-lock detection!
    rep.atomic_sleeps = detect_atomic_sleep_in_hunk(fp, h, local_file_txt);

    rep
}

// ====================================================== 4. Atomic-Context Sleep Detector

const SLEEP_OPS: &[&str] = &[
    "GFP_KERNEL",
    "GFP_NOIO",
    "GFP_NOFS",
    "GFP_USER",
    "mutex_lock(",
    "mutex_lock_interruptible(",
    "down_read(",
    "down_write(",
    "cond_resched(",
    "might_sleep(",
    "wait_event(",
    "wait_event_interruptible(",
    "msleep(",
    "usleep_range(",
];

const ATOMIC_LOCKS: &[&str] = &[
    "bit_spin_lock(",
    "spin_lock(",
    "spin_lock_irq(",
    "spin_lock_irqsave(",
    "spin_lock_bh(",
    "spin_lock_nested(",
    "raw_spin_lock(",
    "raw_spin_lock_irqsave(",
    "read_lock(",
    "write_lock(",
    "rcu_read_lock(",
    "preempt_disable(",
    "local_irq_disable(",
];

/// Discover file-local helper functions (<= 15 lines) that wrap an atomic lock
/// (e.g. `zram_slot_lock` wrapping `bit_spin_lock`).
pub fn discover_atomic_lock_wrappers(file_txt: &str) -> HashMap<String, String> {
    let mut wrappers = HashMap::new();
    let lines: Vec<&str> = file_txt.lines().collect();
    let n = lines.len();
    let mut i = 0;
    while i < n {
        let ln = lines[i];
        if !ln.is_empty()
            && !ln.as_bytes()[0].is_ascii_whitespace()
            && ln.contains('(')
            && !ln.trim_end().ends_with(';')
            && (ln.contains("_lock(") || ln.contains("lock_"))
            && !ln.contains("unlock")
        {
            if let Some(fnm) = extract_func_name(ln) {
                let end = (i + 15).min(n);
                let mut body = String::new();
                let mut closed = false;
                for &bl in &lines[i..end] {
                    body.push_str(bl);
                    body.push('\n');
                    if bl.starts_with('}') {
                        closed = true;
                        break;
                    }
                }
                if closed {
                    for &al in ATOMIC_LOCKS {
                        if body.contains(al) {
                            wrappers.insert(fnm.clone(), al.trim_end_matches('(').to_string());
                            break;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    wrappers
}

fn unlock_counterpart(lock_name: &str) -> String {
    if let Some(pos) = lock_name.rfind("lock") {
        format!("{}unlock{}", &lock_name[..pos], &lock_name[pos + 4..])
    } else {
        String::new()
    }
}

/// Detect newly added sleepable operations (`GFP_NOIO`, `GFP_KERNEL`, `mutex_lock`, etc.)
/// inside a function whose own body or file-local callers hold an atomic spinlock / bit_spin_lock!
pub fn detect_atomic_sleep_in_hunk(
    fp: &FilePatch,
    h: &PatchHunk,
    local_file_txt: &str,
) -> Vec<String> {
    let mut old_sleeps = HashSet::new();
    let mut new_sleeps = BTreeSet::new();
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('-').or_else(|| l.strip_prefix(' ')) {
            for &op in SLEEP_OPS {
                if body.contains(op) {
                    old_sleeps.insert(op);
                }
            }
        }
    }
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('+') {
            let t = body.trim();
            if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
                continue;
            }
            for &op in SLEEP_OPS {
                if body.contains(op) && !old_sleeps.contains(op) {
                    new_sleeps.insert(op.trim_end_matches('('));
                }
            }
        }
    }
    if new_sleeps.is_empty() || local_file_txt.is_empty() {
        return Vec::new();
    }

    // Identify the function being edited (either from hunk header or modified function def in hunk)
    let mut fn_name = extract_func_name(&h.func_ctx);
    for l in &h.lines {
        if let Some(body) = l.strip_prefix('+').or_else(|| l.strip_prefix('-')) {
            if !body.starts_with(' ') && !body.starts_with('\t') && body.contains('(') {
                if let Some(f) = extract_func_name(body) {
                    fn_name = Some(f);
                    break;
                }
            }
        }
    }
    let Some(fn_name) = fn_name else {
        return Vec::new();
    };

    let wrappers = discover_atomic_lock_wrappers(local_file_txt);
    let mut all_locks: Vec<(String, String)> = ATOMIC_LOCKS
        .iter()
        .map(|s| {
            let nm = s.trim_end_matches('(').to_string();
            (nm.clone(), nm)
        })
        .collect();
    for (w, underlying) in &wrappers {
        all_locks.push((w.clone(), format!("{w} [wraps {underlying}]")));
    }

    let lines: Vec<&str> = local_file_txt.lines().collect();
    let needle = format!("{fn_name}(");
    let mut findings = Vec::new();
    let sleep_list: Vec<&str> = new_sleeps.into_iter().collect();
    let sleep_str = sleep_list.join("/");

    // Check callers of `fn_name(` in the same file: scan up to 40 lines backward for an unclosed atomic lock!
    let mut caller_hits: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, ln) in lines.iter().enumerate() {
        if !ln.contains(&needle) {
            continue;
        }
        let t = ln.trim();
        if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        // Skip definition itself
        if !ln.starts_with(' ') && !ln.starts_with('\t') {
            continue;
        }
        let scan_start = idx.saturating_sub(40);
        for (l_name, l_desc) in &all_locks {
            let l_call = format!("{l_name}(");
            let u_name = unlock_counterpart(l_name);
            let u_call = if u_name.is_empty() {
                String::new()
            } else {
                format!("{u_name}(")
            };
            let mut depth = 0i32;
            // Walk backward until function boundary `{` at col 0
            let mut func_start = scan_start;
            for k in (scan_start..idx).rev() {
                if lines[k].starts_with('{') || lines[k].starts_with('}') {
                    func_start = k;
                    break;
                }
            }
            for &cl in &lines[func_start..idx] {
                let ct = cl.trim();
                if ct.starts_with('*') || ct.starts_with("//") {
                    continue;
                }
                if cl.contains(&l_call) {
                    depth += 1;
                }
                if !u_call.is_empty() && cl.contains(&u_call) {
                    depth -= 1;
                }
                if l_name == "rcu_read_lock" && cl.contains("rcu_read_unlock(") {
                    depth -= 1;
                }
                if l_name == "preempt_disable" && cl.contains("preempt_enable(") {
                    depth -= 1;
                }
                if l_name == "local_irq_disable" && cl.contains("local_irq_enable(") {
                    depth -= 1;
                }
            }
            if depth > 0 {
                caller_hits.entry(l_desc.clone()).or_default().push(idx + 1);
            }
        }
    }

    for (lock_desc, lnos) in caller_hits {
        let loc_str = lnos
            .iter()
            .take(4)
            .map(|n| format!("L{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let extra = if lnos.len() > 4 {
            format!(" (+{} more)", lnos.len() - 4)
        } else {
            String::new()
        };
        findings.push(format!(
            "{fn_name}() adds `{sleep_str}` while caller(s) in {} hold `{lock_desc}` at {loc_str}{extra}!",
            fp.display_path()
        ));
    }

    findings
}

// ====================================================== 5. Extra Unpatched Callers on Signature Change

/// Detect function signatures modified in `fp` and find any target-only callers (including Android/MIUI
/// additions or `sm8735-modules`) that are NOT touched by the upstream patch!
pub fn detect_extra_callers(ctx: &Ctx, fp: &FilePatch, all_fps: &[FilePatch]) -> Vec<String> {
    let orig_path = fp.display_path();
    let local_txt = fs::read_to_string(ctx.repo.join(orig_path)).unwrap_or_default();
    if local_txt.is_empty() {
        return Vec::new();
    }

    // 1. Identify functions whose parameter/return signature changed in this FilePatch
    let mut sig_changed: Vec<(String, bool)> = Vec::new(); // (fn_name, is_static)
    for h in &fp.hunks {
        let mut del_sigs: HashMap<String, (String, bool)> = HashMap::new();
        let mut add_sigs: HashMap<String, String> = HashMap::new();
        for l in &h.lines {
            if let Some(body) = l.strip_prefix('-') {
                if !body.starts_with(' ') && !body.starts_with('\t') && body.contains('(') {
                    if let Some(fnm) = extract_func_name(body) {
                        let is_static = body.trim_start().starts_with("static ");
                        del_sigs.insert(fnm, (body.trim().to_string(), is_static));
                    }
                }
            } else if let Some(body) = l.strip_prefix('+') {
                if !body.starts_with(' ') && !body.starts_with('\t') && body.contains('(') {
                    if let Some(fnm) = extract_func_name(body) {
                        add_sigs.insert(fnm, body.trim().to_string());
                    }
                }
            }
        }
        for (fnm, (dline, is_static)) in del_sigs {
            if let Some(aline) = add_sigs.get(&fnm) {
                if dline != *aline {
                    // Also capture multi-line signature changes (e.g. arg on line 2 changed)
                    sig_changed.push((fnm, is_static));
                }
            }
        }
        // Also check when hunk context is inside a function header (e.g. 2nd param line changed while line 1 stayed in context)
        for (idx, l) in h.lines.iter().enumerate() {
            if let Some(body) = l.strip_prefix(' ') {
                if !body.starts_with(' ') && !body.starts_with('\t') && body.contains('(') && !body.contains(')') {
                    // Check if next 1..3 lines contain a `-`/`+` param line
                    let next_changed = h.lines[idx + 1..(idx + 4).min(h.lines.len())]
                        .iter()
                        .any(|nl| nl.starts_with('-') || nl.starts_with('+'));
                    if next_changed {
                        if let Some(fnm) = extract_func_name(body) {
                            let is_static = body.trim_start().starts_with("static ");
                            if !sig_changed.iter().any(|(n, _)| n == &fnm) {
                                sig_changed.push((fnm, is_static));
                            }
                        }
                    }
                }
            }
        }
    }

    if sig_changed.is_empty() {
        return Vec::new();
    }

    // Collect all enclosing functions already touched by the entire commit (across all FilePatches)
    let mut patched_funcs: HashSet<String> = HashSet::new();
    for p in all_fps {
        for h in &p.hunks {
            if let Some(fnm) = extract_func_name(&h.func_ctx) {
                patched_funcs.insert(fnm);
            }
        }
    }

    let mut findings = Vec::new();
    for (fnm, is_static) in sig_changed {
        let pat = format!(r"\b{fnm}\s*\(");
        let mut search_targets: Vec<(String, String)> = Vec::new();
        if is_static {
            search_targets.push((orig_path.to_string(), local_txt.clone()));
        } else {
            let (rc, out) = rg(&ctx.repo, &["-l", "-g", "*.[ch]", &pat, "mm", "kernel", "fs", "net", "block", "drivers", "arch/arm64", "include"]);
            if rc == 0 {
                for f in out.lines().take(20) {
                    if let Ok(t) = fs::read_to_string(ctx.repo.join(f)) {
                        search_targets.push((f.to_string(), t));
                    }
                }
            }
            if ctx.is_default_kernel && ctx.modules.is_dir() {
                let (rcm, outm) = rg(&ctx.modules, &["-l", "-g", "*.[ch]", &pat]);
                if rcm == 0 {
                    for f in outm.lines().take(10) {
                        if let Ok(t) = fs::read_to_string(ctx.modules.join(f)) {
                            search_targets.push((format!("modules/{f}"), t));
                        }
                    }
                }
            }
        }

        let needle = format!("{fnm}(");
        for (fpath, ftxt) in search_targets {
            let flines: Vec<&str> = ftxt.lines().collect();
            let mut cur_enclosing = String::new();
            for (i, &ln) in flines.iter().enumerate() {
                if !ln.is_empty()
                    && !ln.as_bytes()[0].is_ascii_whitespace()
                    && ln.contains('(')
                    && !ln.trim_end().ends_with(';')
                {
                    if let Some(ef) = extract_func_name(ln) {
                        cur_enclosing = ef;
                    }
                }
                if !ln.contains(&needle) {
                    continue;
                }
                let t = ln.trim();
                if t.starts_with('*') || t.starts_with("//") || t.starts_with("/*") {
                    continue;
                }
                // Skip definition / forward decl itself
                if !ln.starts_with(' ') && !ln.starts_with('\t') {
                    continue;
                }
                if cur_enclosing == fnm {
                    continue;
                }
                // Check if this enclosing function is already modified by the patch
                if !patched_funcs.contains(&cur_enclosing) {
                    let enc_lbl = if cur_enclosing.is_empty() {
                        "top-level".to_string()
                    } else {
                        format!("{cur_enclosing}()")
                    };
                    findings.push(format!(
                        "{fnm}() signature changed — unpatched caller in {enc_lbl} at {fpath}:L{}: {}",
                        i + 1,
                        truncate_str(t, 75)
                    ));
                    if findings.len() >= 8 {
                        return findings;
                    }
                }
            }
        }
    }
    findings
}

// ====================================================== 6. Struct Layout & Module Impact

/// Detect `struct <name>` definitions modified in `fp` and check references in `sm8735-modules`.
pub fn detect_struct_impact(ctx: &Ctx, fp: &FilePatch) -> Vec<String> {
    let mut structs = BTreeSet::new();
    for h in &fp.hunks {
        let hdr = h.func_ctx.trim();
        if hdr.starts_with("struct ") && !hdr.contains('(') {
            let name: String = hdr[7..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                structs.insert(name);
            }
        }
        // Also catch newly added/edited struct definitions inside hunk lines
        for l in &h.lines {
            let body = l.strip_prefix(' ').or_else(|| l.strip_prefix('+')).or_else(|| l.strip_prefix('-')).unwrap_or(l);
            let t = body.trim();
            if t.starts_with("struct ") && t.ends_with('{') && !t.contains('(') {
                let name: String = t[7..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    structs.insert(name);
                }
            }
        }
    }
    if structs.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for s in structs {
        let mut mod_files = Vec::new();
        if ctx.is_default_kernel && ctx.modules.is_dir() {
            let pat = format!(r"\bstruct\s+{s}\b");
            let (rc, rout) = rg(&ctx.modules, &["-l", "-g", "*.[ch]", &pat]);
            if rc == 0 {
                mod_files = rout.lines().map(str::to_string).collect();
            }
        }
        if mod_files.is_empty() {
            out.push(format!("struct {s} modified in {} (0 sm8735-modules refs)", fp.display_path()));
        } else {
            let sample: Vec<&str> = mod_files.iter().take(3).map(String::as_str).collect();
            let extra = if mod_files.len() > 3 {
                format!(" (+{} more)", mod_files.len() - 3)
            } else {
                String::new()
            };
            out.push(format!(
                "struct {s} modified in {} — {} sm8735-modules ref(s): {}{extra}",
                fp.display_path(),
                mod_files.len(),
                sample.join(", ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_series_id() {
        let body = "\
Some description.

Link: https://lkml.kernel.org/r/20250303022425.285971-12-senozhatsky@chromium.org
Signed-off-by: Foo Bar <foo@bar.com>
";
        assert_eq!(
            extract_series_id(body),
            Some(("20250303022425.285971-".to_string(), Some(12)))
        );

        let body2 = "Link: https://lore.kernel.org/r/20250724052301.23844-4-dev.jain@arm.com\n";
        assert_eq!(
            extract_series_id(body2),
            Some(("20250724052301.23844-".to_string(), Some(4)))
        );

        let single = "Link: https://lore.kernel.org/r/87beaec6-a3b0-ce7a-c892-1e1e5bd57aa3@google.com\n";
        assert_eq!(extract_series_id(single), None);
    }

    #[test]
    fn test_extract_call_sites_with_arity() {
        let code = "\
\tnr_batch_ptes = folio_pte_batch(folio, pte, ptent, max_nr_batch_ptes);
\tclear_ptes(mm, addr, pte, nr_batch_ptes);
\tstatic inline void foo_def(int a, int b)
\treturn bar_call(x, baz(1, 2), \"a,b\");
";
        let calls = extract_call_sites_with_arity(code);
        assert!(calls.contains(&("folio_pte_batch".to_string(), Some(4))));
        assert!(calls.contains(&("clear_ptes".to_string(), Some(4))));
        assert!(calls.contains(&("bar_call".to_string(), Some(3))));
        assert!(!calls.iter().any(|(n, _)| n == "foo_def"));
    }

    #[test]
    fn test_count_fn_params() {
        assert_eq!(count_fn_params("(void)"), Some(0));
        assert_eq!(count_fn_params("()"), Some(0));
        assert_eq!(count_fn_params("(struct folio *folio, pte_t *ptep, pte_t pte, int max_nr)"), Some(4));
        assert_eq!(
            count_fn_params("(struct folio *folio, unsigned long addr, pte_t *start_ptep, pte_t pte, int max_nr, fpb_t flags, bool *any_writable, bool *any_young, bool *any_dirty)"),
            Some(9)
        );
        assert_eq!(count_fn_params("(const char *fmt, ...)"), None);
        assert_eq!(count_fn_params("(int (*cb)(int, int), void *ctx)"), Some(2));
    }

    #[test]
    fn test_atomic_sleep_wrapper_detection() {
        let fake_zram = "\
static void zram_slot_lock(struct zram *zram, u32 index)
{
\tbit_spin_lock(ZRAM_LOCK, &zram->table[index].flags);
}

static void place_pp_slot(struct zram *zram, struct zram_pp_ctl *ctl, u32 index)
{
\tlist_add(&pps->entry, &ctl->pp_buckets[bid]);
}

static int scan_slots_for_writeback(struct zram *zram)
{
\tzram_slot_lock(zram, index);
\tif (!zram_allocated(zram, index))
\t\tgoto next;
\tplace_pp_slot(zram, ctl, index);
next:
\tzram_slot_unlock(zram, index);
\treturn 0;
}
";
        let wrappers = discover_atomic_lock_wrappers(fake_zram);
        assert_eq!(wrappers.get("zram_slot_lock").map(String::as_str), Some("bit_spin_lock"));

        let fp = FilePatch {
            old_path: "drivers/block/zram/zram_drv.c".into(),
            new_path: "drivers/block/zram/zram_drv.c".into(),
            header_lines: vec![],
            hunks: vec![],
        };
        let h = PatchHunk {
            header: "@@ -295,5 +295,10 @@ static void place_pp_slot(struct zram *zram)".into(),
            old_start: 295,
            old_count: 5,
            func_ctx: "static void place_pp_slot(struct zram *zram)".into(),
            lines: vec![
                "+\tpps = kmalloc(sizeof(*pps), GFP_NOIO | __GFP_NOWARN);".into(),
            ],
        };
        let sleeps = detect_atomic_sleep_in_hunk(&fp, &h, fake_zram);
        assert_eq!(sleeps.len(), 1);
        assert!(sleeps[0].contains("GFP_NOIO"));
        assert!(sleeps[0].contains("zram_slot_lock [wraps bit_spin_lock]"));
    }
}
