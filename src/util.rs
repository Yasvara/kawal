use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

pub const BINDINGS: &str = "Documentation/devicetree/bindings";

pub const IGNORED_PREFIXES: &[&str] = &[
    "tools/",
    "Documentation/",
    "samples/",
    "scripts/",
    "LICENSES/",
];

pub const NOT_A_CALL: &[&str] = &[
    "if", "for", "while", "switch", "return", "sizeof", "defined", "case",
    "do", "else", "goto", "typeof", "__typeof__", "alignof", "_Alignof",
    "static_assert", "offsetof", "container_of", "min", "max", "min_t",
    "max_t", "clamp", "swap", "ARRAY_SIZE", "BIT", "GENMASK", "BUILD_BUG_ON",
    "unlikely", "likely", "WARN_ON", "WARN_ON_ONCE", "BUG_ON", "WARN",
    "pr_err", "pr_info", "pr_warn", "pr_debug", "dev_err", "dev_warn",
    "dev_info", "dev_dbg", "cpu_to_le32", "le32_to_cpu", "cpu_to_le64",
    "le64_to_cpu", "READ_ONCE", "WRITE_ONCE", "list_for_each_entry",
    "kfree", "kzalloc", "kmalloc", "IS_ERR", "PTR_ERR", "ERR_PTR",
];

pub const GENERIC_MEMBERS: &[&str] = &[
    "next", "prev", "list", "node", "lock", "data", "len", "size", "flags",
    "name", "type", "id", "dev", "parent", "ops", "priv", "count", "state",
    "head", "tail", "addr", "offset", "err", "ret", "val", "buf", "page",
    "mm", "sk", "skb", "file", "inode", "task", "work", "wq", "ref", "kref",
];

pub const C_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "bool", "true", "false", "NULL",
    "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "size_t", "ssize_t",
    "loff_t", "gfp_t", "phys_addr_t", "dma_addr_t", "gpa_t", "pgoff_t",
    "likely", "unlikely", "READ_ONCE", "WRITE_ONCE", "IS_ERR", "PTR_ERR",
    "ERR_PTR", "WARN_ON", "WARN_ON_ONCE", "BUG_ON", "BIT", "GENMASK",
    "ARRAY_SIZE", "container_of", "offsetof", "min", "max", "clamp", "swap",
    "dev_err", "dev_warn", "dev_info", "dev_dbg", "pr_err", "pr_warn",
    "pr_info", "pr_debug", "ENODEV", "EINVAL", "ENOMEM", "EBUSY", "EAGAIN",
    "EPERM", "EACCES", "EFAULT", "ETIMEDOUT", "ENOENT", "ESRCH", "EIO",
];

pub const BOILERPLATE_PREFIXES: &[&str] = &[
    "[ upstream commit",
    "commit ",
    "signed-off-by:",
    "reviewed-by:",
    "acked-by:",
    "tested-by:",
    "reported-by:",
    "suggested-by:",
    "co-developed-by:",
    "cc:",
    "link:",
    "change-id:",
    "bug:",
    "closes:",
    "stable-dep-of:",
    "fixes:",
    "this reverts commit",
    "git-commit:",
    "cherry picked from",
    "upstream commit",
    "(cherry picked",
];

#[derive(Clone)]
pub struct Ctx {
    pub ws_root: PathBuf,
    pub repo: PathBuf,
    pub modules: PathBuf,
    pub devicetrees: PathBuf,
    pub product_out: PathBuf,
    pub kernel_obj: PathBuf,
    pub is_default_kernel: bool,
    pub is_modules_repo: bool,
    pub threads: usize,
}

impl Ctx {
    pub fn new(repo_override: Option<&str>) -> Self {
        let ws_root = detect_ws_root();
        let default_kernel = env::var("YASVARA_KERNEL")
            .map(PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("src/kernel/xiaomi/sm8735"));
        let modules = env::var("YASVARA_MODULES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("src/kernel/xiaomi/sm8735-modules"));
        let devicetrees = env::var("YASVARA_DEVICETREES")
            .map(PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("src/kernel/xiaomi/sm8735-devicetrees"));
        let product_out = env::var("YASVARA_PRODUCT_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("src/out/target/product/onyx"));
        let kernel_obj = env::var("YASVARA_KERNEL_OBJ")
            .map(PathBuf::from)
            .unwrap_or_else(|_| product_out.join("obj/KERNEL_OBJ"));

        let repo = match repo_override {
            Some(p) => fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p)),
            None => default_kernel.clone(),
        };
        let is_default_kernel = fs::canonicalize(&repo).ok() == fs::canonicalize(&default_kernel).ok();
        let is_modules_repo = fs::canonicalize(&repo).ok() == fs::canonicalize(&modules).ok();
        let threads = thread::available_parallelism()
            .map(|n| n.get().min(16))
            .unwrap_or(8);

        Ctx {
            ws_root,
            repo,
            modules,
            devicetrees,
            product_out,
            kernel_obj,
            is_default_kernel,
            is_modules_repo,
            threads,
        }
    }

    /// Fast lower bound for revert/KABI history scans (avoids walking 1.3M commits back to 2005!).
    pub fn history_since(&self) -> Option<&'static str> {
        if self.is_default_kernel {
            Some("--since=2023-10-01")
        } else {
            None
        }
    }
}

fn detect_ws_root() -> PathBuf {
    if let Ok(ws) = env::var("YASVARA_WS") {
        let p = PathBuf::from(ws);
        if p.is_dir() {
            return p;
        }
    }
    // Check from executable path upwards, then current dir upwards
    for start in [
        env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)),
        env::current_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        let mut cur = start.as_path();
        loop {
            if cur.join("src/kernel/xiaomi/sm8735").is_dir() {
                return cur.to_path_buf();
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
    }
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn par_map<T: Sync, R: Send, F: Fn(&T) -> R + Sync>(
    items: &[T],
    workers: usize,
    f: F,
) -> Vec<R> {
    if items.is_empty() {
        return Vec::new();
    }
    let w = workers.max(1).min(items.len());
    if w == 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let buckets: Vec<Vec<(usize, R)>> = thread::scope(|s| {
        let mut handles = Vec::with_capacity(w);
        for _ in 0..w {
            let next_ref = &next;
            let f_ref = &f;
            handles.push(s.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let i = next_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    local.push((i, f_ref(&items[i])));
                }
                local
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut flat: Vec<(usize, R)> = buckets.into_iter().flatten().collect();
    flat.sort_unstable_by_key(|(i, _)| *i);
    flat.into_iter().map(|(_, r)| r).collect()
}

pub fn run_cmd(prog: &str, args: &[&str], cwd: &Path, stdin_data: Option<&[u8]>) -> (i32, String, String) {
    run_cmd_env(prog, args, cwd, stdin_data, &[])
}

pub fn run_cmd_env(
    prog: &str,
    args: &[&str],
    cwd: &Path,
    stdin_data: Option<&[u8]>,
    envs: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = Command::new(prog);
    cmd.args(args).current_dir(cwd).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (-1, String::new(), format!("failed to spawn {prog}: {e}")),
    };
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data);
        }
    }
    match child.wait_with_output() {
        Ok(out) => (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(e) => (-1, String::new(), format!("wait error for {prog}: {e}")),
    }
}

/// Run git in `dir` with `GIT_NO_LAZY_FETCH=1` so partial-clone promisor remotes
/// never silently trigger multi-GB object downloads during local checks.
pub fn git_nolazy(dir: &Path, args: &[&str]) -> (i32, String, String) {
    run_cmd_env("git", args, dir, None, &[("GIT_NO_LAZY_FETCH", "1")])
}

pub fn git(ctx: &Ctx, args: &[&str]) -> String {
    run_cmd("git", args, &ctx.repo, None).1
}

pub fn git_rc(ctx: &Ctx, args: &[&str]) -> (i32, String, String) {
    run_cmd("git", args, &ctx.repo, None)
}

pub fn git_in(dir: &Path, args: &[&str]) -> String {
    run_cmd("git", args, dir, None).1
}

pub fn git_stdin(ctx: &Ctx, args: &[&str], input: &[u8]) -> (i32, String, String) {
    run_cmd("git", args, &ctx.repo, Some(input))
}

pub fn rg(cwd: &Path, args: &[&str]) -> (i32, String) {
    let mut full = Vec::with_capacity(args.len() + 2);
    full.push("--color=never");
    full.push("--no-config");
    full.extend_from_slice(args);
    let (rc, out, _) = run_cmd("rg", &full, cwd, None);
    (rc, out)
}

pub fn is_c_source(path: &str) -> bool {
    if IGNORED_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    path.ends_with(".c") || path.ends_with(".h")
}

pub fn is_built_file(ctx: &Ctx, path: &str) -> bool {
    if ctx.is_modules_repo {
        let mod_obj = ctx.product_out.join("obj/sm8735-modules");
        if !mod_obj.is_dir() {
            return true;
        }
        if let Some(stem) = path.strip_suffix(".c") {
            let p = Path::new(stem);
            let dir = p.parent().unwrap_or(Path::new(""));
            let name = p.file_name().map(|s| s.to_string_lossy()).unwrap_or_default();
            return mod_obj.join(format!("{stem}.o")).is_file()
                || mod_obj.join(dir).join(format!(".{name}.o.cmd")).is_file();
        }
        if path.ends_with(".h") {
            if path.contains("/include/") || path.contains("/inc/") {
                return true;
            }
            let dir = Path::new(path).parent().unwrap_or(Path::new(""));
            if let Ok(rd) = fs::read_dir(mod_obj.join(dir)) {
                for ent in rd.flatten() {
                    let fnm = ent.file_name().to_string_lossy().into_owned();
                    if fnm.ends_with(".o") || fnm.ends_with(".o.cmd") {
                        return true;
                    }
                }
            }
            return false;
        }
        return false;
    }
    if !ctx.is_default_kernel || !ctx.kernel_obj.is_dir() {
        return true;
    }
    if let Some(stem) = path.strip_suffix(".c") {
        if ctx.kernel_obj.join(format!("{stem}.o")).is_file() {
            return true;
        }
        // Unity-build `.c` files (e.g. kernel/sched/topology.c included by build_utility.c)
        let p = Path::new(path);
        if let (Some(dir), Some(fname)) = (p.parent(), p.file_name().and_then(|s| s.to_str())) {
            let needle = format!("\"{fname}\"");
            if let Ok(rd) = fs::read_dir(ctx.repo.join(dir)) {
                for ent in rd.flatten() {
                    let bn = ent.file_name().to_string_lossy().into_owned();
                    if bn.starts_with("build_") && bn.ends_with(".c") {
                        let ustem = bn.trim_end_matches(".c");
                        if ctx.kernel_obj.join(dir).join(format!("{ustem}.o")).is_file() {
                            if let Ok(txt) = fs::read_to_string(ent.path()) {
                                if txt.contains(&needle) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }
    if path.ends_with(".h") {
        if path.starts_with("include/") || path.starts_with("arch/arm64/") {
            return true;
        }
        let dir = Path::new(path).parent().unwrap_or(Path::new(""));
        let obj_dir = ctx.kernel_obj.join(dir);
        if let Ok(rd) = fs::read_dir(obj_dir) {
            for ent in rd.flatten() {
                if ent.file_name().to_string_lossy().ends_with(".o") {
                    return true;
                }
            }
        }
        return false;
    }
    false
}

/// Returns sorted (status_code, path) for all unmerged paths (UU, DU, UD, DD, AA, AU, UA).
pub fn unmerged_with_status(ctx: &Ctx) -> Vec<(String, String)> {
    let out = git(ctx, &["status", "--porcelain", "-uall"]);
    let mut res = Vec::new();
    for ln in out.lines() {
        if ln.len() < 4 {
            continue;
        }
        let code = &ln[0..2];
        let is_unmerged = matches!(code, "UU" | "AA" | "DD" | "DU" | "UD" | "AU" | "UA");
        if is_unmerged {
            let mut path = ln[3..].to_string();
            if path.starts_with('"') && path.ends_with('"') && path.len() >= 2 {
                path = path[1..path.len() - 1].to_string();
            }
            res.push((code.to_string(), path));
        }
    }
    res.sort_by(|a, b| a.1.cmp(&b.1));
    res
}

pub fn is_mid_merge(ctx: &Ctx) -> bool {
    let (_, out, _) = git_rc(ctx, &["rev-parse", "--git-path", "MERGE_HEAD"]);
    let p = out.trim();
    if p.is_empty() {
        return false;
    }
    let full = if Path::new(p).is_absolute() {
        PathBuf::from(p)
    } else {
        ctx.repo.join(p)
    };
    full.exists()
}

pub fn norm_subj(s: &str) -> String {
    let mut t = s.trim();
    for p in ["UPSTREAM: ", "BACKPORT: ", "FROMGIT: ", "FROMLIST: ", "ANDROID: "] {
        if let Some(rest) = t.strip_prefix(p) {
            t = rest;
        }
    }
    t.trim().to_ascii_lowercase()
}

pub fn classify_commit(author: &str, subj: &str, body: &str) -> &'static str {
    let sl = subj.to_ascii_lowercase();
    let bl = body.to_ascii_lowercase();
    let al = author.to_ascii_lowercase();
    if sl.starts_with("revert ") {
        if bl.contains("android kernel abi")
            || bl.contains("kabi")
            || bl.contains("kmi")
            || bl.contains("abi breakage")
            || bl.contains("breaks abi")
        {
            return "REVERT/KABI";
        }
        return "REVERT";
    }
    if al.contains("ireddragonicy") || al.contains("yasvara") || al.contains("drago") {
        return "CUSTOM";
    }
    if al.contains("xiaomi")
        || ["onyx", "mi_disp", "mca_", "si_haptic", "nt36532", "aw882xx"]
            .iter()
            .any(|k| sl.contains(k))
    {
        return "XIAOMI";
    }
    if al.contains("quicinc")
        || al.contains("qualcomm")
        || al.contains("codeaurora")
        || al.contains("qti.")
        || (bl.contains("change-id:")
            && ["msm", "qcom", "kgsl", "ipa", "spmi", "rpmh", "tsens", "dwc3"]
                .iter()
                .any(|k| sl.contains(k)))
    {
        return "QCOM";
    }
    if ["ANDROID:", "UPSTREAM:", "BACKPORT:", "FROMGIT:", "FROMLIST:"]
        .iter()
        .any(|p| subj.starts_with(p))
        || al.contains("google.com")
    {
        return "ANDROID";
    }
    "UPSTREAM"
}

pub fn extract_why(body: &str, max_len: usize) -> (String, Vec<String>) {
    let mut trailers = Vec::new();
    let mut reasons = Vec::new();
    let mut stop_reason = false;
    let mut cur_len = 0usize;

    for raw in body.lines() {
        let ln = raw.trim();
        if ln.is_empty() {
            continue;
        }
        let low = ln.to_ascii_lowercase();
        if low.starts_with("fixes:")
            || low.starts_with("stable-dep-of:")
            || low.starts_with("this reverts commit")
            || low.starts_with("bug:")
        {
            trailers.push(ln.to_string());
            continue;
        }
        if stop_reason {
            continue;
        }
        if BOILERPLATE_PREFIXES.iter().any(|p| low.starts_with(p)) {
            continue;
        }
        if ln.starts_with("---")
            || ln.starts_with("===")
            || ln.starts_with("diff ")
            || ln.starts_with("Call Trace")
            || ln.starts_with("BUG:")
            || ln.starts_with("KASAN:")
        {
            stop_reason = true;
            continue;
        }
        cur_len += ln.len() + 1;
        reasons.push(ln);
        if cur_len >= max_len {
            stop_reason = true;
        }
    }
    let mut summary = reasons.join(" ");
    if summary.len() > max_len {
        let cut = max_len.saturating_sub(3);
        let mut end = cut.min(summary.len());
        while end > 0 && !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
        summary = summary.trim_end().to_string();
        summary.push_str("...");
    }
    (summary, trailers)
}

#[derive(Clone)]
pub struct CommitMeta {
    pub sha: String,
    pub date: String,
    pub author: String,
    pub subj: String,
    pub body: String,
    pub tag: &'static str,
}

pub fn commit_meta(ctx: &Ctx, rev: &str) -> Option<CommitMeta> {
    let out = git(
        ctx,
        &["show", "-s", "--format=%H%x1f%ad%x1f%an <%ae>%x1f%s%x1f%b", "--date=short", rev],
    );
    let mut parts = out.splitn(5, '\x1f');
    let sha = parts.next()?.trim().to_string();
    if sha.is_empty() {
        return None;
    }
    let date = parts.next()?.trim().to_string();
    let author = parts.next()?.trim().to_string();
    let subj = parts.next()?.trim().to_string();
    let body = parts.next().unwrap_or("").trim().to_string();
    let tag = classify_commit(&author, &subj, &body);
    Some(CommitMeta { sha, date, author, subj, body, tag })
}

pub fn parse_quoted_trailer_subj(trailer: &str) -> Option<String> {
    let idx = trailer.find("(\"")?;
    let rest = &trailer[idx + 2..];
    let end = rest.rfind("\")")?;
    let s = &rest[..end];
    if s.len() >= 8 { Some(s.to_string()) } else { None }
}

// ------------------------------------------------ C/Source tokenizers

#[inline]
pub fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

#[inline]
pub fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub fn strip_c_comments(line: &str) -> &str {
    let s = line.split("/*").next().unwrap_or(line);
    s.split("//").next().unwrap_or(s)
}

pub fn word_in_text(haystack: &str, word: &str) -> bool {
    if word.is_empty() || word.len() > haystack.len() {
        return false;
    }
    let hb = haystack.as_bytes();
    let wb = word.as_bytes();
    let mut pos = 0;
    while let Some(rel) = haystack[pos..].find(word) {
        let idx = pos + rel;
        let left_ok = idx == 0 || !is_ident_char(hb[idx - 1]);
        let right_idx = idx + wb.len();
        let right_ok = right_idx >= hb.len() || !is_ident_char(hb[right_idx]);
        if left_ok && right_ok {
            return true;
        }
        pos = idx + 1;
    }
    false
}

pub fn extract_members(line: &str) -> Vec<String> {
    let s = strip_c_comments(line);
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let next_start = if i + 1 < b.len() && b[i] == b'-' && b[i + 1] == b'>' {
            Some(i + 2)
        } else if b[i] == b'.' && (i == 0 || !b[i - 1].is_ascii_digit()) {
            Some(i + 1)
        } else {
            None
        };
        if let Some(mut j) = next_start {
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && is_ident_start(b[j]) {
                let start = j;
                while j < b.len() && is_ident_char(b[j]) {
                    j += 1;
                }
                let tok = &s[start..j];
                if !GENERIC_MEMBERS.contains(&tok)
                    && !tok.bytes().all(|c| !c.is_ascii_lowercase())
                {
                    out.push(tok.to_string());
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn extract_calls(line: &str, min_len: usize) -> Vec<String> {
    let s = strip_c_comments(line);
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if is_ident_start(b[i]) {
            let start = i;
            while i < b.len() && is_ident_char(b[i]) {
                i += 1;
            }
            let tok = &s[start..i];
            let mut j = i;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len()
                && b[j] == b'('
                && tok.len() >= min_len
                && !NOT_A_CALL.contains(&tok)
                && !tok.bytes().all(|c| !c.is_ascii_lowercase())
            {
                out.push(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

pub fn extract_bare_idents(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in text.lines() {
        let s = strip_c_comments(line);
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'"' || b[i] == b'\'' {
                let q = b[i];
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            if is_ident_start(b[i]) {
                let start = i;
                while i < b.len() && is_ident_char(b[i]) {
                    i += 1;
                }
                set.insert(s[start..i].to_string());
            } else {
                i += 1;
            }
        }
    }
    set
}

pub fn related_files(ctx: &Ctx, path: &str) -> Vec<String> {
    let mut rel = BTreeSet::new();
    let p = Path::new(path);
    let dir = p.parent().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let stem_prefix = stem.split('_').next().unwrap_or(&stem);
    let dir_last = dir.rsplit('/').next().unwrap_or("");

    let full = ctx.repo.join(path);
    if let Ok(text) = fs::read_to_string(&full) {
        for ln in text.lines().take(200) {
            let t = ln.trim_start();
            if !t.starts_with('#') {
                continue;
            }
            let after_hash = t[1..].trim_start();
            let Some(rest) = after_hash.strip_prefix("include") else {
                continue;
            };
            let rest = rest.trim_start();
            let inc = if let Some(r) = rest.strip_prefix('"') {
                r.split('"').next()
            } else if let Some(r) = rest.strip_prefix('<') {
                r.split('>').next()
            } else {
                None
            };
            if let Some(inc) = inc {
                let cands = [
                    if dir.is_empty() { inc.to_string() } else { normalize_rel(&format!("{dir}/{inc}")) },
                    format!("include/{inc}"),
                ];
                for c in cands {
                    if ctx.repo.join(&c).is_file()
                        && ((!dir.is_empty() && c.starts_with(&format!("{dir}/")))
                            || (stem_prefix.len() >= 3 && c.contains(stem_prefix))
                            || (dir_last.len() >= 3 && c.contains(dir_last)))
                    {
                        if c != path {
                            rel.insert(c);
                        }
                    }
                }
            }
        }
    }
    // Sibling files sharing prefix (e.g. tsens.c -> tsens.h, tsens-v2.c)
    if !dir.is_empty() {
        let prefix = stem.split(['-', '_']).next().unwrap_or("");
        if prefix.len() >= 3 {
            if let Ok(rd) = fs::read_dir(ctx.repo.join(&dir)) {
                for ent in rd.flatten() {
                    let fname = ent.file_name().to_string_lossy().into_owned();
                    if (fname.ends_with(".c") || fname.ends_with(".h")) && fname.starts_with(prefix) {
                        let cand = format!("{dir}/{fname}");
                        if cand != path {
                            rel.insert(cand);
                        }
                    }
                }
            }
        }
    }
    rel.into_iter().collect()
}

fn normalize_rel(p: &str) -> String {
    let mut parts = Vec::new();
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

pub fn find_enclosing_func(lines: &[&str], line_idx: usize) -> Option<(usize, String)> {
    let start = line_idx.min(lines.len().saturating_sub(1));
    for i in (0..=start).rev() {
        let ln = lines[i];
        if ln.is_empty() {
            continue;
        }
        let first = ln.as_bytes()[0];
        if first.is_ascii_whitespace()
            || matches!(first, b'#' | b'/' | b'*' | b'}' | b'{')
            || ln.starts_with("static_assert")
            || ln.starts_with("DEFINE_")
            || ln.starts_with("EXPORT_")
            || ln.starts_with("MODULE_")
            || ln.starts_with("TRACE_")
        {
            continue;
        }
        if let Some(paren) = ln.find('(') {
            let before = ln[..paren].trim_end();
            if before.ends_with('=') || before.contains(';') {
                continue;
            }
            // Extract function identifier right before '('
            let b = before.as_bytes();
            let mut end = b.len();
            while end > 0 && is_ident_char(b[end - 1]) {
                end -= 1;
            }
            let name = &before[end..];
            if !name.is_empty() && is_ident_start(name.as_bytes()[0]) && !C_KEYWORDS.contains(&name) {
                return Some((i + 1, ln.trim().to_string()));
            }
        }
    }
    None
}

pub struct ConflictHunk {
    pub start_1b: usize,
    pub sep_1b: usize,
    pub end_1b: usize,
    pub ours: Vec<String>,
    pub theirs: Vec<String>,
}

pub fn parse_conflict_hunks(lines: &[&str]) -> Vec<ConflictHunk> {
    let mut hunks = Vec::new();
    let mut i = 0;
    let n = lines.len();
    while i < n {
        if lines[i].starts_with("<<<<<<<") {
            let s = i;
            let mut sep = None;
            let mut j = i + 1;
            while j < n && !lines[j].starts_with(">>>>>>>") {
                if lines[j].starts_with("=======") && sep.is_none() {
                    sep = Some(j);
                }
                j += 1;
            }
            if let (Some(sep_i), true) = (sep, j < n) {
                hunks.push(ConflictHunk {
                    start_1b: s + 1,
                    sep_1b: sep_i + 1,
                    end_1b: j + 1,
                    ours: lines[s + 1..sep_i].iter().map(|x| (*x).to_string()).collect(),
                    theirs: lines[sep_i + 1..j].iter().map(|x| (*x).to_string()).collect(),
                });
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    hunks
}

/// Parse `git log --name-only --format=@@@<fields>` into map: file -> Vec<record_line>.
pub fn parse_batched_name_only(out: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur_hdr: Option<String> = None;
    for ln in out.lines() {
        if let Some(rest) = ln.strip_prefix("@@@") {
            cur_hdr = Some(rest.to_string());
        } else if !ln.trim().is_empty() {
            if let Some(ref hdr) = cur_hdr {
                map.entry(ln.trim().to_string()).or_default().push(hdr.clone());
            }
        }
    }
    map
}

pub fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
