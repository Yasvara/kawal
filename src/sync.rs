use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::clo;
use crate::util::*;

// ====================================================== 1. Natural Version Key & Upstream Endpoints

pub(crate) const CLO_BASE: &str = "https://git.codelinaro.org/clo/la";
const CLO_QSSI_REPO: &str = "https://git.codelinaro.org/clo/la/la/system/manifest.git";
const CLO_VENDOR_REPO: &str = "https://git.codelinaro.org/clo/la/la/vendor/manifest.git";
const CLO_KP_REPO: &str = "https://git.codelinaro.org/clo/la/kernelplatform/manifest.git";
const LINUX_STABLE_REPO: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";
const LINUX_STABLE_FALLBACK_REPO: &str = "https://github.com/gregkh/linux.git";
const AOSP_ACK_REPO: &str = "https://android.googlesource.com/kernel/common";
pub(crate) const AOSP_MANIFEST_REPO: &str = "https://android.googlesource.com/platform/manifest";
const LINEAGE_MANIFEST_REPO: &str = "https://github.com/LineageOS/android.git";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NatPart {
    Num(u64),
    Text(String),
}

/// Natural version comparison key: splits a tag into numeric and ASCII-lowercase text runs so
/// `v6.6.162 > v6.6.99` and `LA.QSSI.17.0.r1-12500-qssi.0 > LA.QSSI.17.0.r1-9700-qssi.0`.
pub fn nat_key(s: &str) -> Vec<NatPart> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let n = s[start..i].parse::<u64>().unwrap_or(0);
            out.push(NatPart::Num(n));
        } else {
            let start = i;
            while i < b.len() && !b[i].is_ascii_digit() {
                i += 1;
            }
            out.push(NatPart::Text(s[start..i].to_ascii_lowercase()));
        }
    }
    out
}

pub(crate) fn run_with_retry<F>(attempts: usize, mut f: F) -> (i32, String, String)
where
    F: FnMut() -> (i32, String, String),
{
    let mut last = (-1, String::new(), String::new());
    for attempt in 0..attempts {
        let res = f();
        if res.0 == 0 {
            return res;
        }
        let err_low = res.2.to_ascii_lowercase();
        let transient = err_low.contains("429")
            || err_low.contains("502")
            || err_low.contains("503")
            || err_low.contains("504")
            || err_low.contains("timed out")
            || err_low.contains("connection reset")
            || err_low.contains("could not resolve")
            || err_low.contains("unable to access");
        last = res;
        if !transient || attempt + 1 >= attempts {
            break;
        }
        let wait_secs = match attempt {
            0 => 2,
            1 => 5,
            _ => 10,
        };
        thread::sleep(Duration::from_secs(wait_secs));
    }
    last
}

/// List remote tags matching `patterns` via `git ls-remote --tags --refs` (with connect timeout & 429 backoff).
pub(crate) fn ls_remote_tags(cwd: &Path, url: &str, patterns: &[&str]) -> Result<Vec<String>, String> {
    let mut args = vec![
        "18",
        "git",
        "-c",
        "http.lowSpeedLimit=100",
        "-c",
        "http.lowSpeedTime=12",
        "ls-remote",
        "--tags",
        "--refs",
        url,
    ];
    args.extend_from_slice(patterns);
    let (rc, out, err) = run_with_retry(3, || run_cmd("timeout", &args, cwd, None));
    if rc == 124 {
        return Err(format!("connection timed out reaching {url}"));
    }
    if rc != 0 {
        return Err(err.lines().last().unwrap_or("git ls-remote failed").trim().to_string());
    }
    let mut tags: Vec<String> = out
        .lines()
        .filter_map(|ln| ln.split_once('\t').map(|(_, r)| r))
        .filter_map(|r| r.strip_prefix("refs/tags/"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    tags.sort_by_key(|t| nat_key(t));
    tags.dedup();
    Ok(tags)
}

fn ls_remote_head(cwd: &Path, url: &str, branch: &str) -> Result<String, String> {
    let (rc, out, err) = run_with_retry(3, || {
        run_cmd(
            "timeout",
            &[
                "18",
                "git",
                "-c",
                "http.lowSpeedLimit=100",
                "-c",
                "http.lowSpeedTime=12",
                "ls-remote",
                "--heads",
                url,
                branch,
            ],
            cwd,
            None,
        )
    });
    if rc == 124 {
        return Err(format!("connection timed out reaching {url}"));
    }
    if rc != 0 {
        return Err(err.lines().last().unwrap_or("git ls-remote failed").trim().to_string());
    }
    out.lines()
        .next()
        .and_then(|ln| ln.split_whitespace().next())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("branch {branch} not found"))
}

/// Pure-Rust base64 decoder for tiny Gitiles `?format=TEXT` responses (e.g. `Makefile`).
pub(crate) fn decode_base64(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => continue,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_makefile_kver(txt: &str) -> Option<String> {
    let (mut ver, mut patch, mut sub) = (String::new(), String::new(), String::new());
    for ln in txt.lines().take(15) {
        let t = ln.trim();
        if let Some(v) = t.strip_prefix("VERSION =") {
            ver = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("PATCHLEVEL =") {
            patch = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("SUBLEVEL =") {
            sub = v.trim().to_string();
        }
    }
    if ver.is_empty() || patch.is_empty() || sub.is_empty() {
        None
    } else {
        Some(format!("v{ver}.{patch}.{sub}"))
    }
}

fn fetch_gitiles_kernel_version(cwd: &Path, repo_url: &str, branch: &str) -> Option<String> {
    let url = format!("{}/+/refs/heads/{branch}/Makefile?format=TEXT", repo_url.trim_end_matches('/'));
    let (rc, body, _) = run_cmd(
        "curl",
        &["-fsSL", "--connect-timeout", "8", "--max-time", "15", &url],
        cwd,
        None,
    );
    if rc != 0 || body.is_empty() {
        return None;
    }
    let decoded = decode_base64(&body);
    parse_makefile_kver(&decoded)
}

// ====================================================== 2. Full Recursive Yasvara Manifest Expander

#[derive(Debug, Clone)]
pub struct FullProject {
    pub path: String,
    pub name: String,
    pub remote: String,
    pub revision: String,
    pub linkfiles: Vec<(String, String)>,
    pub copyfiles: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct ExpandedManifest {
    pub remotes: BTreeMap<String, (String, Option<String>)>, // name -> (fetch, default_rev)
    pub default_remote: String,
    pub default_revision: String,
    pub projects: BTreeMap<String, FullProject>,
    pub removed_by: BTreeMap<String, String>, // path -> xml that removed it
    pub overridden_clo: BTreeMap<String, String>, // path -> xml that replaced a clo.xml project
}

fn xml_attr(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = line.find(&needle)? + needle.len();
    let end = line[start..].find('"')? + start;
    Some(line[start..end].to_string())
}

fn expand_xml_file(
    manifest_dir: &Path,
    rel_name: &str,
    out: &mut ExpandedManifest,
    clo_paths: &mut BTreeSet<String>,
) -> Result<(), String> {
    let full = manifest_dir.join(rel_name);
    let text = fs::read_to_string(&full).map_err(|e| format!("{}: {e}", full.display()))?;
    let mut cur_proj: Option<FullProject> = None;

    for raw in text.lines() {
        let ln = raw.trim();
        if ln.is_empty() || ln.starts_with("<!--") {
            continue;
        }
        if ln.starts_with("<include ") {
            if let Some(inc) = xml_attr(ln, "name") {
                expand_xml_file(manifest_dir, &inc, out, clo_paths)?;
            }
        } else if ln.starts_with("<remote ") {
            if let (Some(name), Some(fetch)) = (xml_attr(ln, "name"), xml_attr(ln, "fetch")) {
                let rev = xml_attr(ln, "revision");
                out.remotes.insert(name, (fetch.trim_end_matches('/').to_string(), rev));
            }
        } else if ln.starts_with("<default ") {
            if let Some(r) = xml_attr(ln, "remote") {
                out.default_remote = r;
            }
            if let Some(rev) = xml_attr(ln, "revision") {
                out.default_revision = rev;
            }
        } else if ln.starts_with("<remove-project ") {
            if let Some(p) = xml_attr(ln, "path") {
                out.projects.remove(&p);
                out.removed_by.insert(p, rel_name.to_string());
            } else if let Some(n) = xml_attr(ln, "name") {
                let victims: Vec<String> = out
                    .projects
                    .iter()
                    .filter(|(_, pr)| pr.name == n)
                    .map(|(k, _)| k.clone())
                    .collect();
                for v in victims {
                    out.projects.remove(&v);
                    out.removed_by.insert(v, rel_name.to_string());
                }
            }
        } else if ln.starts_with("<project ") {
            if let Some(name) = xml_attr(ln, "name") {
                let path = xml_attr(ln, "path").unwrap_or_else(|| name.clone());
                let remote = xml_attr(ln, "remote").unwrap_or_else(|| out.default_remote.clone());
                let (_fetch_base, rem_rev) = out
                    .remotes
                    .get(&remote)
                    .cloned()
                    .unwrap_or_else(|| (String::new(), None));
                let revision = xml_attr(ln, "revision")
                    .or(rem_rev)
                    .unwrap_or_else(|| out.default_revision.clone());

                if rel_name == "clo.xml" {
                    clo_paths.insert(path.clone());
                } else if clo_paths.contains(&path) {
                    out.overridden_clo.insert(path.clone(), rel_name.to_string());
                }

                let proj = FullProject {
                    path: path.clone(),
                    name,
                    remote,
                    revision,
                    linkfiles: Vec::new(),
                    copyfiles: Vec::new(),
                };
                if ln.ends_with("/>") {
                    out.projects.insert(path, proj);
                } else {
                    cur_proj = Some(proj);
                }
            }
        } else if ln.starts_with("<linkfile ") {
            if let (Some(p), Some(s), Some(d)) =
                (cur_proj.as_mut(), xml_attr(ln, "src"), xml_attr(ln, "dest"))
            {
                p.linkfiles.push((s, d));
            }
        } else if ln.starts_with("<copyfile ") {
            if let (Some(p), Some(s), Some(d)) =
                (cur_proj.as_mut(), xml_attr(ln, "src"), xml_attr(ln, "dest"))
            {
                p.copyfiles.push((s, d));
            }
        } else if ln.starts_with("</project>") {
            if let Some(p) = cur_proj.take() {
                out.projects.insert(p.path.clone(), p);
            }
        }
    }
    Ok(())
}

pub fn load_yasvara_manifest(ws_root: &Path) -> Result<ExpandedManifest, String> {
    let manifest_dir = ws_root.join("manifest");
    if !manifest_dir.join("default.xml").is_file() {
        return Err(format!("missing {}", manifest_dir.join("default.xml").display()));
    }
    let mut out = ExpandedManifest::default();
    let mut clo_paths = BTreeSet::new();
    expand_xml_file(&manifest_dir, "default.xml", &mut out, &mut clo_paths)?;
    Ok(out)
}

pub(crate) fn load_pending_projects(ws_root: &Path) -> BTreeMap<String, FullProject> {
    let manifest_dir = ws_root.join("manifest");
    let mut tmp = ExpandedManifest::default();
    tmp.remotes.insert(
        "yasvara".to_string(),
        ("ssh://git@github.com/Yasvara".to_string(), Some("refs/heads/yasvara-17.0".to_string())),
    );
    let mut dummy = BTreeSet::new();
    let _ = expand_xml_file(&manifest_dir, "snippets/pending.xml", &mut tmp, &mut dummy);
    tmp.projects
}

// ====================================================== 3. Local Version Detectors

fn find_first_pattern(text: &str, prefix: &str) -> Option<String> {
    let idx = text.find(prefix)?;
    let rest = &text[idx..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
        .unwrap_or(rest.len());
    let tok = rest[..end].trim_end_matches('.');
    if tok.len() > prefix.len() {
        Some(tok.to_string())
    } else {
        None
    }
}

fn detect_local_qssi_tag(ws_root: &Path) -> String {
    let manifest_dir = ws_root.join("manifest");
    if manifest_dir.join(".git").exists() {
        let log = git_in(&manifest_dir, &["log", "-n", "30", "--format=%s"]);
        for ln in log.lines() {
            if let Some(t) = find_first_pattern(ln, "LA.QSSI.") {
                return t;
            }
        }
    }
    if let Ok(readme) = fs::read_to_string(manifest_dir.join("README.md")) {
        if let Some(t) = find_first_pattern(&readme, "LA.QSSI.") {
            return t;
        }
    }
    "unknown".to_string()
}

fn detect_local_vendor_xml(ws_root: &Path) -> (String, Option<PathBuf>) {
    let dir = ws_root.join("lab/clo-manifests");
    let mut best_num = 0u64;
    let mut best_path: Option<PathBuf> = None;
    let mut best_tag: Option<String> = None;

    if let Ok(rd) = fs::read_dir(&dir) {
        for ent in rd.flatten() {
            let fname = ent.file_name().to_string_lossy().into_owned();
            if !fname.ends_with(".xml") {
                continue;
            }
            if let Some(stem) = fname.strip_suffix(".xml") {
                if let Ok(n) = stem.parse::<u64>() {
                    if n > best_num {
                        best_num = n;
                        best_path = Some(ent.path());
                        best_tag = Some(format!("LA.VENDOR.15.4.0.r1-{n}-pakala.QSSI16.0"));
                    }
                } else if stem.starts_with("LA.VENDOR.") {
                    let cand = stem.to_string();
                    let replace = best_tag
                        .as_ref()
                        .map_or(true, |cur| nat_key(&cand) > nat_key(cur));
                    if replace {
                        best_tag = Some(cand);
                        best_path = Some(ent.path());
                    }
                }
            }
        }
    }
    if let Some(tag) = best_tag {
        return (tag, best_path);
    }
    // Fallback: inspect sm8735-modules git log
    let mods = ws_root.join("src/kernel/xiaomi/sm8735-modules");
    if mods.join(".git").exists() {
        let log = git_in(&mods, &["log", "-n", "30", "--format=%s"]);
        for ln in log.lines() {
            if let Some(t) = find_first_pattern(ln, "LA.VENDOR.") {
                return (t, None);
            }
        }
    }
    ("unknown".to_string(), None)
}

fn detect_local_kp_tag_prefix(ws_root: &Path, prefix: &str) -> String {
    let dir = ws_root.join("lab/clo-manifests");
    let mut best: Option<String> = None;
    if let Ok(rd) = fs::read_dir(&dir) {
        for ent in rd.flatten() {
            let fname = ent.file_name().to_string_lossy().into_owned();
            let cand = if let Some(rest) = fname.strip_prefix("kp-").and_then(|s| s.strip_suffix(".xml")) {
                Some(format!("KERNEL.PLATFORM.4.0.r1-{rest}-kernel.0"))
            } else if fname.starts_with("KERNEL.PLATFORM.") && fname.ends_with(".xml") {
                Some(fname.trim_end_matches(".xml").to_string())
            } else {
                None
            };
            if let Some(tag) = cand {
                if tag.starts_with(prefix) && best.as_ref().map_or(true, |b| nat_key(&tag) > nat_key(b)) {
                    best = Some(tag);
                }
            }
        }
    }
    best.unwrap_or_else(|| "unknown".to_string())
}

fn detect_local_kernel_version(ctx: &Ctx) -> String {
    let mk = ctx.ws_root.join("src/kernel/xiaomi/sm8735/Makefile");
    let Ok(txt) = fs::read_to_string(&mk) else {
        return "unknown".to_string();
    };
    let (mut ver, mut patch, mut sub) = (String::new(), String::new(), String::new());
    for ln in txt.lines().take(15) {
        let t = ln.trim();
        if let Some(v) = t.strip_prefix("VERSION =") {
            ver = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("PATCHLEVEL =") {
            patch = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("SUBLEVEL =") {
            sub = v.trim().to_string();
        }
    }
    if ver.is_empty() {
        "unknown".to_string()
    } else {
        format!("v{ver}.{patch}.{sub}")
    }
}

fn detect_local_aosp_tag(ws_root: &Path) -> String {
    for rel in ["manifest/snippets/lineage.xml", "src/.repo/manifests/default.xml"] {
        if let Ok(txt) = fs::read_to_string(ws_root.join(rel)) {
            for ln in txt.lines() {
                if ln.contains("name=\"aosp\"") {
                    if let Some(rev) = xml_attr(ln, "revision") {
                        return rev.trim_start_matches("refs/tags/").to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

fn detect_local_lineage_head(ws_root: &Path) -> (String, String) {
    let dir = ws_root.join("src/.repo/manifests");
    if !dir.join(".git").exists() {
        return ("unknown".to_string(), String::new());
    }
    let sha = git_in(&dir, &["rev-parse", "HEAD"]).trim().to_string();
    let subj = git_in(&dir, &["show", "-s", "--format=%s", "HEAD"]).trim().to_string();
    (sha, subj)
}

// ====================================================== 4. `kawal sync fetch <tag>`

/// Map any CLO tag to `(manifest_repo_path, xml_filename)` under `https://git.codelinaro.org/clo/la`.
pub fn clo_tag_to_repo_and_file(tag: &str) -> Option<(String, String)> {
    if tag.starts_with("LA.QSSI.") {
        return Some(("la/system/manifest".to_string(), format!("{tag}.xml")));
    }
    if tag.starts_with("LA.VENDOR.") || tag.starts_with("LA.UM.") {
        return Some(("la/vendor/manifest".to_string(), format!("{tag}.xml")));
    }
    if tag.starts_with("KERNEL.PLATFORM.") || tag.starts_with("AU_LINUX_KERNEL.PLATFORM.") {
        return Some(("kernelplatform/manifest".to_string(), format!("{tag}.xml")));
    }
    if let Some(rest) = tag.strip_prefix("AU_TECHPACK_") {
        let family = rest.split('.').next().unwrap_or("");
        let tp = match family {
            "AUDIO_HANDSET" | "AUDIO" => "audio",
            "BTFM" => "btfm",
            "CAMERA" => "camera",
            "CV" => "cv",
            "DISPLAY" => "display",
            "GRAPHICS" => "graphics",
            "SENSORS" => "sensors",
            "VIDEO" => "video",
            "WLAN" => "wlan",
            _ => return None,
        };
        return Some((format!("techpack/{tp}/manifest"), format!("{tag}.xml")));
    }
    None
}

fn fetch_clo_xml_inner(
    ws_root: &Path,
    project: &str,
    tag: &str,
    dest: &Path,
) -> Result<usize, String> {
    if let Some(par) = dest.parent() {
        let _ = fs::create_dir_all(par);
    }
    let urls = [
        format!("{CLO_BASE}/{project}/-/raw/{tag}/{tag}.xml"),
        format!("{CLO_BASE}/{project}/-/raw/{tag}/default.xml"),
    ];
    let mut last_err = String::new();
    for url in &urls {
        let (rc, body, err) = run_with_retry(4, || {
            run_cmd(
                "curl",
                &["-fsSL", "--connect-timeout", "15", "--max-time", "60", url],
                ws_root,
                None,
            )
        });
        if rc == 0 && body.contains("<manifest") && body.contains("<project") {
            fs::write(dest, body.as_bytes()).map_err(|e| e.to_string())?;
            return Ok(body.len());
        }
        last_err = if !err.trim().is_empty() {
            err.trim().to_string()
        } else {
            format!("non-manifest response from {url}")
        };
    }
    Err(last_err)
}

pub fn cmd_sync_fetch(ctx: &Ctx, tag: &str, out_opt: Option<&Path>, with_techpacks: bool) -> i32 {
    let Some((repo_path, file_name)) = clo_tag_to_repo_and_file(tag) else {
        eprintln!(
            "!! unrecognized CLO tag format `{tag}`\n   supported: LA.QSSI.*, LA.VENDOR.*, KERNEL.PLATFORM.*, AU_TECHPACK_*"
        );
        return 2;
    };
    let dest = out_opt
        .map(PathBuf::from)
        .unwrap_or_else(|| ctx.ws_root.join("lab/clo-manifests").join(&file_name));

    println!("=== sync fetch: {tag} ===");
    println!("  source : {CLO_BASE}/{repo_path}");
    println!("  dest   : {}", dest.display());

    match fetch_clo_xml_inner(&ctx.ws_root, &repo_path, tag, &dest) {
        Ok(bytes) => {
            let txt = fs::read_to_string(&dest).unwrap_or_default();
            let parsed = clo::parse_manifest_xml(&txt);
            println!(
                "  ok     : saved {} bytes ({} projects, {} <refs> techpacks)",
                bytes,
                parsed.projects.len(),
                parsed.refs.len()
            );
            if with_techpacks && !parsed.refs.is_empty() {
                let tp_dir = ctx.ws_root.join("lab/clo-manifests/tp");
                println!("\nFetching {} referenced techpack XML(s) (rate-limited, 2 workers)...", parsed.refs.len());
                let items: Vec<clo::ManifestRef> = parsed.refs.values().cloned().collect();
                let results = par_map(&items, 2, |r| {
                    let out_p = tp_dir.join(format!("{}_{}.xml", tag, r.name));
                    let res = fetch_clo_xml_inner(&ctx.ws_root, &r.project, &r.tag, &out_p);
                    (r.name.clone(), r.tag.clone(), res)
                });
                for (name, t, res) in results {
                    match res {
                        Ok(n) => println!("  [OK ] {:<26} {} ({} B)", name, t, n),
                        Err(e) => println!("  [ERR] {:<26} {} ({})", name, t, e),
                    }
                }
            }
            if tag.starts_with("LA.QSSI.") {
                println!("\nNext: kawal sync plan {}", dest.display());
            }
            0
        }
        Err(e) => {
            eprintln!("  !! fetch failed: {e}");
            1
        }
    }
}

// ====================================================== 5. `kawal sync latest`

struct TrackSpec {
    label: String,
    local: String,
    url: String,
    fallback_url: Option<String>,
    patterns: Vec<String>,
    /// Optional repo project path under CLO_BASE for `--fetch-xml`.
    fetch_project: Option<String>,
    /// True if querying branch HEAD instead of tags.
    is_branch: bool,
    /// True if branch HEAD should also resolve `vX.Y.Z` from Gitiles `Makefile`.
    gitiles_kver: bool,
}

struct TrackResult {
    label: String,
    local: String,
    is_branch: bool,
    resolved_ver: Option<String>,
    used_mirror: bool,
    latest: Result<(String, Vec<String>), String>, // (latest_tag_or_sha, newer_tags_list)
    fetch_project: Option<String>,
}

fn check_track(cwd: &Path, spec: &TrackSpec) -> TrackResult {
    if spec.is_branch {
        let br = spec.patterns.first().map(|s| s.as_str()).unwrap_or("main");
        let latest = ls_remote_head(cwd, &spec.url, br).map(|sha| (sha, Vec::new()));
        let resolved_ver = if spec.gitiles_kver && latest.is_ok() {
            fetch_gitiles_kernel_version(cwd, &spec.url, br)
        } else {
            None
        };
        return TrackResult {
            label: spec.label.clone(),
            local: spec.local.clone(),
            is_branch: true,
            resolved_ver,
            used_mirror: false,
            latest,
            fetch_project: None,
        };
    }
    let pats: Vec<&str> = spec.patterns.iter().map(|s| s.as_str()).collect();
    let mut used_mirror = false;
    let raw_tags = match ls_remote_tags(cwd, &spec.url, &pats) {
        Ok(t) => Ok(t),
        Err(e) => {
            if let Some(ref fb) = spec.fallback_url {
                used_mirror = true;
                ls_remote_tags(cwd, fb, &pats).map_err(|fe| format!("{e}; mirror: {fe}"))
            } else {
                Err(e)
            }
        }
    };
    let res = raw_tags.map(|tags| {
        // Filter out non-release tags like `-rc` for linux stable
        let clean: Vec<String> = tags
            .into_iter()
            .filter(|t| !t.contains("-rc") && !t.ends_with("^{}"))
            .collect();
        let latest = clean.last().cloned().unwrap_or_else(|| "none".to_string());
        let newer: Vec<String> = if spec.local != "unknown" {
            let loc_k = nat_key(&spec.local);
            clean
                .iter()
                .filter(|t| nat_key(t) > loc_k)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        (latest, newer)
    });
    TrackResult {
        label: spec.label.clone(),
        local: spec.local.clone(),
        is_branch: false,
        resolved_ver: None,
        used_mirror,
        latest: res,
        fetch_project: spec.fetch_project.clone(),
    }
}

#[derive(Default)]
pub struct LatestOpts {
    pub qssi: bool,
    pub vendor: bool,
    pub kernel: bool,
    pub techpacks: bool,
    pub aosp: bool,
    pub lineage: bool,
    pub fetch_xml: bool,
}

impl LatestOpts {
    pub fn any_selected(&self) -> bool {
        self.qssi || self.vendor || self.kernel || self.techpacks || self.aosp || self.lineage
    }
}

pub fn cmd_sync_latest(ctx: &Ctx, mut opts: LatestOpts) -> i32 {
    if !opts.any_selected() {
        // Default radar: Framework (CLO QSSI) + Vendor (Pakala) + Kernel (KP + 6.6 LTS) + AOSP + Lineage
        opts.qssi = true;
        opts.vendor = true;
        opts.kernel = true;
        opts.aosp = true;
        opts.lineage = true;
    }

    let mut specs: Vec<TrackSpec> = Vec::new();
    let (local_vendor_tag, local_vendor_xml) = detect_local_vendor_xml(&ctx.ws_root);

    if opts.qssi {
        let loc = detect_local_qssi_tag(&ctx.ws_root);
        specs.push(TrackSpec {
            label: "Framework (CLO QSSI 17.0)".to_string(),
            local: loc,
            url: CLO_QSSI_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["LA.QSSI.17.0.r1-*".to_string()],
            fetch_project: Some("la/system/manifest".to_string()),
            is_branch: false,
            gitiles_kver: false,
        });
    }
    if opts.vendor {
        specs.push(TrackSpec {
            label: "Vendor (CLO Pakala 15.4)".to_string(),
            local: local_vendor_tag.clone(),
            url: CLO_VENDOR_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["LA.VENDOR.15.4.0.r1-*pakala*".to_string()],
            fetch_project: Some("la/vendor/manifest".to_string()),
            is_branch: false,
            gitiles_kver: false,
        });
    }
    if opts.kernel {
        let local_kver = detect_local_kernel_version(ctx);
        specs.push(TrackSpec {
            label: "Kernel (CLO KP 4.0 / 6.6)".to_string(),
            local: detect_local_kp_tag_prefix(&ctx.ws_root, "KERNEL.PLATFORM.4.0."),
            url: CLO_KP_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["KERNEL.PLATFORM.4.0.r1-*".to_string()],
            fetch_project: Some("kernelplatform/manifest".to_string()),
            is_branch: false,
            gitiles_kver: false,
        });
        specs.push(TrackSpec {
            label: "Kernel (CLO KP 5.0 / 6.12)".to_string(),
            local: detect_local_kp_tag_prefix(&ctx.ws_root, "KERNEL.PLATFORM.5.0."),
            url: CLO_KP_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["KERNEL.PLATFORM.5.0.r1-*".to_string()],
            fetch_project: Some("kernelplatform/manifest".to_string()),
            is_branch: false,
            gitiles_kver: false,
        });
        specs.push(TrackSpec {
            label: "Kernel (Linux 6.6 LTS)".to_string(),
            local: local_kver.clone(),
            url: LINUX_STABLE_REPO.to_string(),
            fallback_url: Some(LINUX_STABLE_FALLBACK_REPO.to_string()),
            patterns: vec!["v6.6.*".to_string()],
            fetch_project: None,
            is_branch: false,
            gitiles_kver: false,
        });
        specs.push(TrackSpec {
            label: "Kernel (Linux 6.12 LTS)".to_string(),
            local: local_kver.clone(),
            url: LINUX_STABLE_REPO.to_string(),
            fallback_url: Some(LINUX_STABLE_FALLBACK_REPO.to_string()),
            patterns: vec!["v6.12.*".to_string()],
            fetch_project: None,
            is_branch: false,
            gitiles_kver: false,
        });
        specs.push(TrackSpec {
            label: "Kernel (ACK 16-6.12-lts)".to_string(),
            local: local_kver.clone(),
            url: AOSP_ACK_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["android16-6.12-lts".to_string()],
            fetch_project: None,
            is_branch: true,
            gitiles_kver: true,
        });
        specs.push(TrackSpec {
            label: "Kernel (ACK 16-6.12)".to_string(),
            local: local_kver,
            url: AOSP_ACK_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["android16-6.12".to_string()],
            fetch_project: None,
            is_branch: true,
            gitiles_kver: true,
        });
    }
    if opts.aosp {
        let loc = detect_local_aosp_tag(&ctx.ws_root);
        specs.push(TrackSpec {
            label: "AOSP 17 (Main+Security)".to_string(),
            local: loc,
            url: AOSP_MANIFEST_REPO.to_string(),
            fallback_url: None,
            patterns: vec![
                "android-17.0.0_r*".to_string(),
                "android-security-17.0.0_r*".to_string(),
            ],
            fetch_project: None,
            is_branch: false,
            gitiles_kver: false,
        });
    }
    if opts.lineage {
        let (sha, _subj) = detect_local_lineage_head(&ctx.ws_root);
        specs.push(TrackSpec {
            label: "LineageOS 24.0 manifest".to_string(),
            local: truncate_str(&sha, 12).to_string(),
            url: LINEAGE_MANIFEST_REPO.to_string(),
            fallback_url: None,
            patterns: vec!["lineage-24.0".to_string()],
            fetch_project: None,
            is_branch: true,
            gitiles_kver: false,
        });
    }
    if opts.techpacks {
        if let Some(ref vxml) = local_vendor_xml {
            if let Ok(txt) = fs::read_to_string(vxml) {
                let m = clo::parse_manifest_xml(&txt);
                for r in m.refs.values() {
                    if r.project.starts_with("techpack/") {
                        // Trailing `.` prevents `R1*` from false-matching `R10`/`R11`/`R12` OEM branches!
                        let pat = format!("AU_TECHPACK_{}.*", r.name);
                        specs.push(TrackSpec {
                            label: format!("TP {}", r.name),
                            local: r.tag.clone(),
                            url: format!("{CLO_BASE}/{}.git", r.project),
                            fallback_url: None,
                            patterns: vec![pat],
                            fetch_project: Some(r.project.clone()),
                            is_branch: false,
                            gitiles_kver: false,
                        });
                    }
                }
            }
        } else {
            eprintln!("!! --techpacks requires a local vendor manifest in lab/clo-manifests/");
        }
    }

    println!("==========================================================================================");
    println!("kawal sync latest: upstream release radar (rate-limited 2 workers w/ 429 backoff)");
    println!("==========================================================================================");

    // Keep concurrency <= 2 to avoid git.codelinaro.org HTTP 429 rate limits!
    let results = par_map(&specs, 2, |s| check_track(&ctx.ws_root, s));

    let mut updates_avail = 0usize;
    let mut errors = 0usize;
    let mut to_fetch: Vec<(String, String)> = Vec::new();

    for r in &results {
        match &r.latest {
            Ok((latest, newer)) => {
                let short_or_tag = if latest.len() == 40 && latest.chars().all(|c| c.is_ascii_hexdigit()) {
                    truncate_str(latest, 12).to_string()
                } else {
                    latest.clone()
                };
                let latest_disp = if let Some(ref kv) = r.resolved_ver {
                    format!("{kv} ({short_or_tag})")
                } else if r.used_mirror {
                    format!("{short_or_tag} [mirror]")
                } else {
                    short_or_tag.clone()
                };
                let status = if r.local == "unknown" {
                    "INFO  ".to_string()
                } else if let Some(ref kv) = r.resolved_ver {
                    if nat_key(kv) <= nat_key(&r.local) {
                        "UP2DAT".to_string()
                    } else {
                        updates_avail += 1;
                        "UPDATE".to_string()
                    }
                } else if r.is_branch {
                    if short_or_tag == r.local {
                        "UP2DAT".to_string()
                    } else {
                        updates_avail += 1;
                        "MOVED ".to_string()
                    }
                } else if short_or_tag == r.local || (newer.is_empty() && nat_key(&short_or_tag) <= nat_key(&r.local)) {
                    "UP2DAT".to_string()
                } else {
                    updates_avail += 1;
                    if newer.is_empty() {
                        "UPDATE".to_string()
                    } else {
                        format!("+{} NEW", newer.len())
                    }
                };
                println!("  [{:<6}] {:<26} local: {:<38} latest: {}", status, r.label, r.local, latest_disp);
                if !newer.is_empty() && newer.len() <= 8 {
                    println!("           intermediate -> {}", newer.join(", "));
                } else if newer.len() > 8 {
                    let head: Vec<&str> = newer.iter().take(3).map(|s| s.as_str()).collect();
                    let tail: Vec<&str> = newer[newer.len() - 3..].iter().map(|s| s.as_str()).collect();
                    println!("           intermediate -> {} ... {}", head.join(", "), tail.join(", "));
                }
                if opts.fetch_xml && status != "UP2DAT" {
                    if let Some(ref proj) = r.fetch_project {
                        if latest != "none" {
                            to_fetch.push((proj.clone(), latest.clone()));
                        }
                    }
                }
            }
            Err(e) => {
                errors += 1;
                println!("  [ERR   ] {:<26} local: {:<38} err: {}", r.label, r.local, e);
            }
        }
    }

    println!("------------------------------------------------------------------------------------------");
    println!(
        "Summary: {} track(s) checked | {} update(s) available | {} error(s)",
        results.len(),
        updates_avail,
        errors
    );
    if !opts.techpacks {
        println!("Tip: run `kawal sync latest --techpacks` for all Pakala techpacks, or add `--fetch-xml` to download latest XMLs.");
    }

    if opts.fetch_xml && !to_fetch.is_empty() {
        println!("\nDownloading {} updated manifest XML(s) into lab/clo-manifests/...", to_fetch.len());
        for (proj, tag) in to_fetch {
            let dest = ctx.ws_root.join("lab/clo-manifests").join(format!("{tag}.xml"));
            match fetch_clo_xml_inner(&ctx.ws_root, &proj, &tag, &dest) {
                Ok(n) => println!("  [SAVED] {} ({} B)", dest.display(), n),
                Err(e) => println!("  [ERR  ] {tag}: {e}"),
            }
        }
    }
    if errors > 0 { 1 } else { 0 }
}

// ====================================================== 6. `kawal sync status` (16-Core ROM Dashboard)

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RepoBucket {
    YasvaraPorted,
    YasvaraLegacy,
    CloClean,
    CloDrift,
    Lineage,
    Aosp,
    Pending,
    Missing,
}

impl RepoBucket {
    fn tag(self) -> &'static str {
        match self {
            RepoBucket::YasvaraPorted => "PORTED ",
            RepoBucket::YasvaraLegacy => "YAS-24 ",
            RepoBucket::CloClean => "CLO-OK ",
            RepoBucket::CloDrift => "CLO-DRF",
            RepoBucket::Lineage => "LINEAGE",
            RepoBucket::Aosp => "AOSP   ",
            RepoBucket::Pending => "PENDING",
            RepoBucket::Missing => "MISSING",
        }
    }
}

struct RepoRow {
    path: String,
    bucket: RepoBucket,
    branch: String,
    head_short: String,
    dirty_cnt: usize,
    ahead: String,
}

fn inspect_repo(src_root: &Path, proj: &FullProject, is_pending: bool) -> RepoRow {
    let dir = src_root.join(&proj.path);
    if !dir.join(".git").exists() {
        return RepoRow {
            path: proj.path.clone(),
            bucket: if is_pending { RepoBucket::Pending } else { RepoBucket::Missing },
            branch: "-".to_string(),
            head_short: "-".to_string(),
            dirty_cnt: 0,
            ahead: String::new(),
        };
    }

    let head = git_in(&dir, &["rev-parse", "HEAD"]).trim().to_string();
    let head_short = truncate_str(&head, 10).to_string();
    let branch = git_in(&dir, &["branch", "--show-current"]).trim().to_string();
    let has_yas17 = run_cmd("git", &["rev-parse", "-q", "--verify", "refs/heads/yasvara-17.0"], &dir, None).0 == 0;
    let st = git_in(&dir, &["status", "--porcelain"]);
    let dirty_cnt = st.lines().filter(|l| !l.trim().is_empty()).count();

    let bucket = if is_pending {
        RepoBucket::Pending
    } else if has_yas17 || branch == "yasvara-17.0" {
        RepoBucket::YasvaraPorted
    } else if proj.remote == "yasvara" {
        RepoBucket::YasvaraLegacy
    } else if proj.remote == "lineage" {
        RepoBucket::Lineage
    } else if proj.remote == "aosp" {
        RepoBucket::Aosp
    } else if proj.remote == "clo-la" {
        if head == proj.revision {
            RepoBucket::CloClean
        } else {
            RepoBucket::CloDrift
        }
    } else {
        RepoBucket::CloDrift
    };

    let ahead = if proj.remote == "clo-la" && !head.is_empty() && head != proj.revision {
        let c = git_in(&dir, &["rev-list", "--count", &format!("{}..HEAD", proj.revision)]);
        let t = c.trim();
        if !t.is_empty() && t.chars().all(|ch| ch.is_ascii_digit()) {
            format!("+{t}")
        } else {
            "diverged".to_string()
        }
    } else {
        String::new()
    };

    RepoRow {
        path: proj.path.clone(),
        bucket,
        branch: if branch.is_empty() { "detached".to_string() } else { branch },
        head_short,
        dirty_cnt,
        ahead,
    }
}

pub fn cmd_sync_status(
    ctx: &Ctx,
    filter: Option<&str>,
    only_dirty: bool,
    only_ported: bool,
    only_drift: bool,
) -> i32 {
    let manifest = match load_yasvara_manifest(&ctx.ws_root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("!! {e}");
            return 2;
        }
    };
    let pending = load_pending_projects(&ctx.ws_root);
    let src_root = ctx.ws_root.join("src");
    let flt = filter.map(|s| s.to_ascii_lowercase());

    let mut work: Vec<(FullProject, bool)> = Vec::new();
    for p in manifest.projects.values() {
        if let Some(ref f) = flt {
            if !p.path.to_ascii_lowercase().contains(f) && !p.name.to_ascii_lowercase().contains(f) {
                continue;
            }
        }
        work.push((p.clone(), false));
    }
    for p in pending.values() {
        if manifest.projects.contains_key(&p.path) {
            continue;
        }
        if let Some(ref f) = flt {
            if !p.path.to_ascii_lowercase().contains(f) && !p.name.to_ascii_lowercase().contains(f) {
                continue;
            }
        }
        work.push((p.clone(), true));
    }

    let rows = par_map(&work, ctx.threads, |(p, is_pend)| inspect_repo(&src_root, p, *is_pend));

    let mut counts: BTreeMap<RepoBucket, usize> = BTreeMap::new();
    let mut dirty_total = 0usize;
    for r in &rows {
        *counts.entry(r.bucket).or_insert(0) += 1;
        if r.dirty_cnt > 0 {
            dirty_total += 1;
        }
    }

    let qssi = detect_local_qssi_tag(&ctx.ws_root);
    println!("==========================================================================================");
    println!("kawal sync status: Yasvara ROM workspace ({} repos scanned, QSSI={qssi})", rows.len());
    println!("==========================================================================================");
    println!(
        "  PORTED(yasvara-17.0): {:<4} | YAS-24(legacy): {:<4} | CLO-CLEAN: {:<4} | CLO-DRIFT: {:<4}",
        counts.get(&RepoBucket::YasvaraPorted).copied().unwrap_or(0),
        counts.get(&RepoBucket::YasvaraLegacy).copied().unwrap_or(0),
        counts.get(&RepoBucket::CloClean).copied().unwrap_or(0),
        counts.get(&RepoBucket::CloDrift).copied().unwrap_or(0),
    );
    println!(
        "  LINEAGE-FORKS/ONLY  : {:<4} | AOSP-ONLY     : {:<4} | PENDING  : {:<4} | MISSING  : {:<4} | DIRTY: {}",
        counts.get(&RepoBucket::Lineage).copied().unwrap_or(0),
        counts.get(&RepoBucket::Aosp).copied().unwrap_or(0),
        counts.get(&RepoBucket::Pending).copied().unwrap_or(0),
        counts.get(&RepoBucket::Missing).copied().unwrap_or(0),
        dirty_total
    );

    let show_all = only_dirty || only_ported || only_drift || filter.is_some();
    let mut printed = 0usize;
    println!();
    for r in &rows {
        if only_dirty && r.dirty_cnt == 0 {
            continue;
        }
        if only_ported && !matches!(r.bucket, RepoBucket::YasvaraPorted | RepoBucket::YasvaraLegacy) {
            continue;
        }
        if only_drift && r.bucket != RepoBucket::CloDrift {
            continue;
        }
        if !show_all
            && !matches!(
                r.bucket,
                RepoBucket::YasvaraPorted | RepoBucket::YasvaraLegacy | RepoBucket::CloDrift | RepoBucket::Pending
            )
            && r.dirty_cnt == 0
        {
            continue;
        }
        let dirty_tag = if r.dirty_cnt > 0 {
            format!(" DIRTY({})", r.dirty_cnt)
        } else {
            String::new()
        };
        let ahead_tag = if !r.ahead.is_empty() {
            format!(" [{}]", r.ahead)
        } else {
            String::new()
        };
        println!(
            "  [{}] {:<48} {:<16} {}{}{}",
            r.bucket.tag(),
            r.path,
            truncate_str(&r.branch, 16),
            r.head_short,
            ahead_tag,
            dirty_tag
        );
        printed += 1;
    }
    if !show_all {
        println!(
            "\n(Showing {} notable repos: PORTED, YAS-24, CLO-DRIFT, PENDING, DIRTY. Pass `--filter <pat>` / `--dirty` / `--ported` / `--drift` to slice.)",
            printed
        );
    }
    0
}

// ====================================================== 7. `kawal sync plan` & `kawal sync apply`

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanKind {
    ManualMerge,
    AutoFf,
    ShadowedLineage,
    PrebuiltSkip,
    TrimmedSkip,
    MissingClone,
}

pub(crate) struct PlanEntry {
    pub path: String,
    pub name: String,
    pub old_rev: String,
    pub new_rev: String,
    pub upstream: String,
    pub kind: PlanKind,
    pub note: String,
}

pub(crate) fn build_sync_plan(
    ctx: &Ctx,
    old_xml: &Path,
    new_xml: &Path,
    filter: Option<&str>,
    include_prebuilts: bool,
) -> Result<(Vec<PlanEntry>, Vec<clo::ManifestProject>, Vec<clo::ManifestProject>, usize), String> {
    let old_txt = fs::read_to_string(old_xml).map_err(|e| format!("{}: {e}", old_xml.display()))?;
    let new_txt = fs::read_to_string(new_xml).map_err(|e| format!("{}: {e}", new_xml.display()))?;
    let old_m = clo::parse_manifest_xml(&old_txt);
    let new_m = clo::parse_manifest_xml(&new_txt);
    let expanded = load_yasvara_manifest(&ctx.ws_root).unwrap_or_default();
    let src_root = ctx.ws_root.join("src");
    let flt = filter.map(|s| s.to_ascii_lowercase());

    let all_keys: BTreeSet<&String> = old_m.projects.keys().chain(new_m.projects.keys()).collect();
    let mut unchanged = 0usize;
    let mut changed_raw: Vec<(clo::ManifestProject, clo::ManifestProject)> = Vec::new();
    let mut added = Vec::new();
    let mut removed = Vec::new();

    for k in all_keys {
        if let Some(ref f) = flt {
            let p_low = k.to_ascii_lowercase();
            let n_low = new_m
                .projects
                .get(k)
                .or_else(|| old_m.projects.get(k))
                .map(|p| p.name.to_ascii_lowercase())
                .unwrap_or_default();
            if !p_low.contains(f) && !n_low.contains(f) {
                continue;
            }
        }
        match (old_m.projects.get(k), new_m.projects.get(k)) {
            (Some(a), Some(b)) if a.revision == b.revision => unchanged += 1,
            (Some(a), Some(b)) => changed_raw.push((a.clone(), b.clone())),
            (None, Some(b)) => added.push(b.clone()),
            (Some(a), None) => removed.push(a.clone()),
            (None, None) => {}
        }
    }

    let entries = par_map(&changed_raw, ctx.threads, |(a, b)| {
        let p = &b.path;
        if expanded.removed_by.get(p).map(|s| s.as_str()) == Some("snippets/trim.xml") {
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::TrimmedSkip,
                note: "trimmed by trim.xml".to_string(),
            };
        }
        if let Some(over) = expanded.overridden_clo.get(p) {
            if over == "snippets/lineage.xml" {
                return PlanEntry {
                    path: p.clone(),
                    name: b.name.clone(),
                    old_rev: a.revision.clone(),
                    new_rev: b.revision.clone(),
                    upstream: b.upstream.clone(),
                    kind: PlanKind::ShadowedLineage,
                    note: "overridden by snippets/lineage.xml (decouple candidate!)".to_string(),
                };
            }
        }
        let dir = src_root.join(p);
        if !include_prebuilts && p.starts_with("prebuilts/") && dir.is_dir() {
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::PrebuiltSkip,
                note: "prebuilt kept (pass --include-prebuilts to sync)".to_string(),
            };
        }
        if !dir.join(".git").exists() {
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::MissingClone,
                note: "not present locally".to_string(),
            };
        }
        let branch = git_in(&dir, &["branch", "--show-current"]).trim().to_string();
        let has_yas17 =
            run_cmd("git", &["rev-parse", "-q", "--verify", "refs/heads/yasvara-17.0"], &dir, None).0 == 0;
        let head = git_in(&dir, &["rev-parse", "HEAD"]).trim().to_string();
        let dirty_cnt = git_in(&dir, &["status", "--porcelain"])
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();

        if has_yas17 || branch == "yasvara-17.0" || expanded.overridden_clo.get(p).map(|s| s.as_str()) == Some("snippets/yasvara.xml") {
            let ahead = git_nolazy(&dir, &["rev-list", "--count", &format!("{}..HEAD", a.revision)]).1;
            let ahead_s = ahead.trim();
            let mut note = format!("branch={}", if branch.is_empty() { "yasvara-17.0" } else { &branch });
            if !ahead_s.is_empty() && ahead_s.chars().all(|c| c.is_ascii_digit()) {
                note.push_str(&format!(" +{ahead_s} local"));
            }
            if dirty_cnt > 0 {
                note.push_str(&format!(" DIRTY({dirty_cnt})"));
            }
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::ManualMerge,
                note,
            };
        }
        if dirty_cnt > 0 {
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::ManualMerge,
                note: format!("DIRTY({dirty_cnt}) on {}", if branch.is_empty() { "detached" } else { &branch }),
            };
        }
        if head == b.revision {
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::AutoFf,
                note: "already at target".to_string(),
            };
        }
        if head != a.revision && !branch.is_empty() {
            return PlanEntry {
                path: p.clone(),
                name: b.name.clone(),
                old_rev: a.revision.clone(),
                new_rev: b.revision.clone(),
                upstream: b.upstream.clone(),
                kind: PlanKind::ManualMerge,
                note: format!("custom branch={branch} head={}", truncate_str(&head, 10)),
            };
        }
        PlanEntry {
            path: p.clone(),
            name: b.name.clone(),
            old_rev: a.revision.clone(),
            new_rev: b.revision.clone(),
            upstream: b.upstream.clone(),
            kind: PlanKind::AutoFf,
            note: "clean CLO fast-forward".to_string(),
        }
    });

    Ok((entries, added, removed, unchanged))
}

pub fn cmd_sync_plan(
    ctx: &Ctx,
    new_xml: &Path,
    old_xml_opt: Option<&Path>,
    filter: Option<&str>,
    with_commits: bool,
) -> i32 {
    let old_default = ctx.ws_root.join("manifest/clo.xml");
    let old_xml = old_xml_opt.unwrap_or(&old_default);

    let (entries, added, removed, unchanged) =
        match build_sync_plan(ctx, old_xml, new_xml, filter, false) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("!! {e}");
                return 2;
            }
        };

    let manual: Vec<&PlanEntry> = entries.iter().filter(|e| e.kind == PlanKind::ManualMerge).collect();
    let auto_ff: Vec<&PlanEntry> = entries.iter().filter(|e| e.kind == PlanKind::AutoFf).collect();
    let shadowed: Vec<&PlanEntry> = entries.iter().filter(|e| e.kind == PlanKind::ShadowedLineage).collect();
    let prebuilts: Vec<&PlanEntry> = entries.iter().filter(|e| e.kind == PlanKind::PrebuiltSkip).collect();
    let trimmed: Vec<&PlanEntry> = entries.iter().filter(|e| e.kind == PlanKind::TrimmedSkip).collect();
    let missing: Vec<&PlanEntry> = entries.iter().filter(|e| e.kind == PlanKind::MissingClone).collect();

    println!("==========================================================================================");
    println!("kawal sync plan: {} -> {}", old_xml.display(), new_xml.display());
    println!("==========================================================================================");
    println!(
        "  unchanged: {} | MANUAL-MERGE: {} | AUTO-FF: {} | SHADOWED-LINEAGE: {} | PREBUILT: {} | TRIMMED: {} | MISSING: {} | +{} ADD / -{} DEL",
        unchanged,
        manual.len(),
        auto_ff.len(),
        shadowed.len(),
        prebuilts.len(),
        trimmed.len(),
        missing.len(),
        added.len(),
        removed.len()
    );

    if !manual.is_empty() {
        println!("\n[1] MANUAL-MERGE ({} ported / dirty / local repos — merge with ktool!):", manual.len());
        let src_root = ctx.ws_root.join("src");
        for e in &manual {
            let mut commit_note = String::new();
            if with_commits {
                let dir = src_root.join(&e.path);
                let url = format!("{CLO_BASE}/{}.git", e.name);
                let tip_arg = format!("--negotiation-tip={}", e.old_rev);
                let have_new = git_nolazy(&dir, &["cat-file", "-e", &format!("{}^{{commit}}", e.new_rev)]).0 == 0;
                let rc = if have_new {
                    0
                } else {
                    let have_old = git_nolazy(&dir, &["cat-file", "-e", &format!("{}^{{commit}}", e.old_rev)]).0 == 0;
                    run_with_retry(3, || {
                        if have_old {
                            run_cmd_env(
                                "git",
                                &["fetch", "-q", "--no-tags", "--filter=blob:none", &tip_arg, &url, &e.new_rev],
                                &dir,
                                None,
                                &[("GIT_NO_LAZY_FETCH", "1")],
                            )
                        } else {
                            run_cmd_env(
                                "git",
                                &["fetch", "-q", "--no-tags", "--filter=blob:none", "--depth=80", &url, &e.new_rev],
                                &dir,
                                None,
                                &[("GIT_NO_LAZY_FETCH", "1")],
                            )
                        }
                    })
                    .0
                };
                if rc == 0 {
                    let rng = format!("{}..{}", e.old_rev, e.new_rev);
                    let log = git_nolazy(&dir, &["log", "--no-merges", "--format=%s", &rng]).1;
                    let cnt = log.lines().filter(|l| !l.trim().is_empty()).count();
                    let sec = log
                        .lines()
                        .filter(|l| {
                            let s = l.to_ascii_lowercase();
                            s.contains("cve") || s.contains("security") || s.contains("uaf") || s.contains("overflow")
                        })
                        .count();
                    commit_note = format!(" | incoming: {cnt} commits{}", if sec > 0 { format!(" ({sec} SEC!)") } else { String::new() });
                }
            }
            println!(
                "  [MERGE] {:<44} {} -> {} ({}) [{}]{}",
                e.path,
                truncate_str(&e.old_rev, 10),
                truncate_str(&e.new_rev, 10),
                e.upstream,
                e.note,
                commit_note
            );
        }
    }

    if !shadowed.is_empty() {
        println!("\n[2] SHADOWED BY LINEAGE ({} CLO updates hidden by snippets/lineage.xml — decouple candidates!):", shadowed.len());
        for e in &shadowed {
            println!(
                "  [SHADW] {:<44} {} -> {} ({})",
                e.path,
                truncate_str(&e.old_rev, 10),
                truncate_str(&e.new_rev, 10),
                e.upstream
            );
        }
    }

    if !auto_ff.is_empty() {
        println!("\n[3] AUTO-FF CLEAN CLO ({} repos safe for `kawal sync apply`):", auto_ff.len());
        for e in auto_ff.iter().take(40) {
            println!(
                "  [FF   ] {:<44} {} -> {} ({})",
                e.path,
                truncate_str(&e.old_rev, 10),
                truncate_str(&e.new_rev, 10),
                e.note
            );
        }
        if auto_ff.len() > 40 {
            println!("  ... and {} more clean CLO repos", auto_ff.len() - 40);
        }
    }

    if !added.is_empty() {
        println!("\n[4] ADDED IN NEW MANIFEST ({}):", added.len());
        for p in added.iter().take(25) {
            println!("  [ADD  ] {:<44} {} ({})", p.path, truncate_str(&p.revision, 10), p.name);
        }
        if added.len() > 25 {
            println!("  ... and {} more added", added.len() - 25);
        }
    }
    if !removed.is_empty() {
        println!("\n[5] REMOVED IN NEW MANIFEST ({}):", removed.len());
        for p in removed.iter().take(25) {
            println!("  [DEL  ] {:<44} {}", p.path, p.name);
        }
    }

    println!("\nNext steps:");
    println!("  1. Preview auto fast-forward : kawal sync apply {} --dry-run", new_xml.display());
    println!("  2. Apply clean CLO bumps     : kawal sync apply {} -j 4", new_xml.display());
    println!("  3. Merge each MANUAL-MERGE repo with `kawal -R src/<path> merge <rev>` + `kawal explain -s`");
    0
}

pub fn cmd_sync_apply(
    ctx: &Ctx,
    new_xml: &Path,
    old_xml_opt: Option<&Path>,
    filter: Option<&str>,
    dry_run: bool,
    jobs: usize,
    include_prebuilts: bool,
    update_manifest: bool,
) -> i32 {
    let old_default = ctx.ws_root.join("manifest/clo.xml");
    let old_xml = old_xml_opt.unwrap_or(&old_default);

    let (entries, _added, _removed, _unchanged) =
        match build_sync_plan(ctx, old_xml, new_xml, filter, include_prebuilts) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("!! {e}");
                return 2;
            }
        };

    let auto_ff: Vec<PlanEntry> = entries
        .iter()
        .filter(|e| e.kind == PlanKind::AutoFf)
        .map(|e| PlanEntry {
            path: e.path.clone(),
            name: e.name.clone(),
            old_rev: e.old_rev.clone(),
            new_rev: e.new_rev.clone(),
            upstream: e.upstream.clone(),
            kind: e.kind,
            note: e.note.clone(),
        })
        .collect();
    let manual_cnt = entries.iter().filter(|e| e.kind == PlanKind::ManualMerge).count();

    println!(
        "=== sync apply ({}): {} AUTO-FF repos ({} MANUAL-MERGE untouched) ===",
        if dry_run { "DRY-RUN" } else { "APPLY" },
        auto_ff.len(),
        manual_cnt
    );

    if dry_run {
        for e in &auto_ff {
            println!(
                "  [DRY-FF] {:<46} {} -> {}",
                e.path,
                truncate_str(&e.old_rev, 10),
                truncate_str(&e.new_rev, 10)
            );
        }
        if update_manifest {
            println!("  [DRY-CP] {} -> manifest/clo.xml", new_xml.display());
        }
        return 0;
    }

    let src_root = ctx.ws_root.join("src");
    // Cap network fetch workers to avoid CodeLinaro 429 rate-limits.
    let workers = jobs.clamp(1, 6);
    let results = par_map(&auto_ff, workers, |e| {
        let dir = src_root.join(&e.path);
        let head = git_in(&dir, &["rev-parse", "HEAD"]).trim().to_string();
        if head == e.new_rev {
            return (e.path.clone(), Ok("same".to_string()));
        }
        if !git_in(&dir, &["status", "--porcelain"]).trim().is_empty() {
            return (e.path.clone(), Err("DIRTY (skipped)".to_string()));
        }
        let url = format!("{CLO_BASE}/{}", e.name);
        let (rc, _, err) = run_with_retry(4, || {
            run_cmd("git", &["fetch", "-q", "--no-tags", "--depth=1", &url, &e.new_rev], &dir, None)
        });
        if rc != 0 {
            return (
                e.path.clone(),
                Err(format!("fetch failed: {}", err.lines().last().unwrap_or("").trim())),
            );
        }
        let (rc2, _, err2) = run_cmd("git", &["checkout", "-q", "--detach", "FETCH_HEAD"], &dir, None);
        if rc2 != 0 {
            return (
                e.path.clone(),
                Err(format!("checkout failed: {}", err2.lines().last().unwrap_or("").trim())),
            );
        }
        (e.path.clone(), Ok("moved".to_string()))
    });

    let (mut moved, mut same, mut failed) = (0usize, 0usize, Vec::new());
    for (p, r) in results {
        match r {
            Ok(s) if s == "same" => same += 1,
            Ok(_) => {
                moved += 1;
                println!("  [OK  ] {p}");
            }
            Err(e) => {
                println!("  [FAIL] {p}: {e}");
                failed.push((p, e));
            }
        }
    }

    if update_manifest && failed.is_empty() {
        let dst = ctx.ws_root.join("manifest/clo.xml");
        match fs::copy(new_xml, &dst) {
            Ok(_) => println!("  [MANIFEST] updated {}", dst.display()),
            Err(e) => eprintln!("  !! failed to update manifest/clo.xml: {e}"),
        }
    }

    println!(
        "\nResult: {} moved, {} already-same, {} failed | {} MANUAL-MERGE repo(s) remaining",
        moved,
        same,
        failed.len(),
        manual_cnt
    );
    if failed.is_empty() { 0 } else { 1 }
}

// ====================================================== 8. `kawal decouple` (LineageOS Decoupling Audit)

const UNUSED_SOC_TOKENS: &[&str] = &[
    "msm8953", "sdm660", "sm7250", "sm8150", "sm8250", "sm8350",
    "sm8450", "sm8550", "sm8650", "sm8850", "knowles/athletico",
];

const CORE_LINEAGE_PATHS: &[&str] = &[
    "vendor/lineage",
    "lineage-sdk",
    "device/lineage/sepolicy",
    "hardware/lineage/compat",
    "hardware/lineage/generic-ims",
    "hardware/lineage/interfaces",
    "packages/overlays/Lineage",
    "prebuilts/extract-tools",
    "prebuilts/tools-lineage",
    "tools/extract-utils",
    "hardware/qcom-caf/common",
    "hardware/qcom-caf/bootctrl",
    "hardware/qcom-caf/thermal",
    "hardware/qcom-caf/thermal-legacy-um",
    "hardware/qcom-caf/wlan",
    "hardware/qcom-caf/sm8750",
    "device/qcom/sepolicy_vndr/sm8750",
    "device/qcom/sepolicy_vndr/legacy-um",
    "device/qcom/sepolicy-legacy-um",
];

fn is_unused_soc_path(path: &str) -> bool {
    UNUSED_SOC_TOKENS.iter().any(|t| path.contains(t))
        || path.starts_with("lineage/")
        || path == "android"
        || path == "vendor/crowdin"
        || path == "device/lineage/atv"
        || path == "device/lineage/car"
}

fn is_core_lineage_path(path: &str) -> bool {
    CORE_LINEAGE_PATHS.iter().any(|p| path == *p || path.starts_with(&format!("{p}/")))
        || path.starts_with("vendor/qcom/opensource/")
        || path == "vendor/codeaurora/telephony"
}

pub fn cmd_decouple(ctx: &Ctx, filter: Option<&str>, scan_refs: bool, check_delta: bool) -> i32 {
    let manifest = match load_yasvara_manifest(&ctx.ws_root) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("!! {e}");
            return 2;
        }
    };
    let flt = filter.map(|s| s.to_ascii_lowercase());
    let src_root = ctx.ws_root.join("src");

    let mut unused_soc = Vec::new();
    let mut clo_overrides = Vec::new();
    let mut yas_legacy = Vec::new();
    let mut lineage_apps = Vec::new();
    let mut core_infra = Vec::new();

    for p in manifest.projects.values() {
        if let Some(ref f) = flt {
            if !p.path.to_ascii_lowercase().contains(f) && !p.name.to_ascii_lowercase().contains(f) {
                continue;
            }
        }
        if p.remote == "yasvara" && p.revision.contains("lineage-") {
            yas_legacy.push(p.clone());
            continue;
        }
        if p.remote != "lineage" {
            continue;
        }
        if is_unused_soc_path(&p.path) {
            unused_soc.push(p.clone());
        } else if manifest.overridden_clo.contains_key(&p.path) {
            clo_overrides.push(p.clone());
        } else if is_core_lineage_path(&p.path) {
            core_infra.push(p.clone());
        } else {
            lineage_apps.push(p.clone());
        }
    }

    let total_los = unused_soc.len() + clo_overrides.len() + lineage_apps.len() + core_infra.len();
    println!("==========================================================================================");
    println!("kawal decouple: LineageOS dependency audit (manifest/snippets/lineage.xml + yasvara.xml)");
    println!("==========================================================================================");
    println!(
        "  Total Lineage remote repos: {} | Yasvara forks still on lineage-24.0: {}",
        total_los,
        yas_legacy.len()
    );
    println!(
        "  [P1] UNUSED-SOC / INFRA (drop immediately): {}",
        unused_soc.len()
    );
    println!(
        "  [P2] CLO-OVERRIDE (shadows clo.xml)       : {}",
        clo_overrides.len()
    );
    println!(
        "  [P3] LINEAGE APPS & CLI EXTRAS            : {}",
        lineage_apps.len()
    );
    println!(
        "  [P4] CORE INFRA / QCOM-CAF COUPLING       : {}",
        core_infra.len()
    );
    println!(
        "  [P5] YASVARA REPOS ON `lineage-24.0`      : {}",
        yas_legacy.len()
    );

    if !unused_soc.is_empty() {
        println!("\n[P1] UNUSED-SOC / NON-TARGET HALs & INFRA ({} — safe to drop for onyx+grus):", unused_soc.len());
        for p in &unused_soc {
            let present = if src_root.join(&p.path).exists() { "on-disk" } else { "absent " };
            println!("  [DROP ] ({present}) {:<50} ({})", p.path, p.name);
        }
    }

    if !clo_overrides.is_empty() {
        println!("\n[P2] CLO-OVERRIDE FORKS ({} — already exist in manifest/clo.xml!):", clo_overrides.len());
        // Optionally inspect local branch/commits in parallel
        let notes = par_map(&clo_overrides, ctx.threads, |p| {
            let dir = src_root.join(&p.path);
            if !dir.join(".git").exists() {
                return "not cloned".to_string();
            }
            let br = git_in(&dir, &["branch", "--show-current"]).trim().to_string();
            let dirty = !git_in(&dir, &["status", "--porcelain"]).trim().is_empty();
            let mut s = format!("branch={}", if br.is_empty() { "detached" } else { &br });
            if check_delta {
                let cnt = git_in(&dir, &["rev-list", "--count", "--no-merges", "-n", "50", "HEAD"]);
                let last = git_in(&dir, &["show", "-s", "--format=%s", "HEAD"]);
                s.push_str(&format!(" commits={} last=`{}`", cnt.trim(), truncate_str(last.trim(), 42)));
            }
            if dirty {
                s.push_str(" DIRTY");
            }
            s
        });
        for (p, note) in clo_overrides.iter().zip(notes.iter()) {
            println!("  [CLO? ] {:<44} [{}]", p.path, note);
        }
    }

    if !lineage_apps.is_empty() {
        println!("\n[P3] LINEAGE APPS & CLI EXTRAS ({}):", lineage_apps.len());
        // Check whether each package leaf name appears in onyx/grus/vendor makefiles
        let search_dirs = [
            src_root.join("device/xiaomi/onyx"),
            src_root.join("device/xiaomi/grus"),
            src_root.join("vendor/yasvara"),
            src_root.join("vendor/lineage"),
        ];
        let existing_dirs: Vec<PathBuf> = search_dirs.into_iter().filter(|d| d.is_dir()).collect();
        let usage = par_map(&lineage_apps, ctx.threads, |p| {
            let leaf = p.path.rsplit('/').next().unwrap_or(&p.path);
            let mut hits = Vec::new();
            for d in &existing_dirs {
                let (rc, out) = rg(d, &["-l", "-F", leaf]);
                if rc == 0 && !out.trim().is_empty() {
                    let tag = d.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                    hits.push(tag);
                }
            }
            hits
        });
        for (p, hits) in lineage_apps.iter().zip(usage.iter()) {
            let tag = if hits.is_empty() {
                "UNUSED".to_string()
            } else {
                format!("used:{}", hits.join(","))
            };
            println!("  [APP  ] {:<44} [{}]", p.path, tag);
        }
    }

    if !core_infra.is_empty() {
        println!("\n[P4] CORE INFRASTRUCTURE & QCOM-CAF COUPLING ({}):", core_infra.len());
        for p in &core_infra {
            println!("  [CORE ] {:<44} rev={} ({})", p.path, truncate_str(&p.revision, 22), p.name);
        }
    }

    if !yas_legacy.is_empty() {
        println!("\n[P5] YASVARA REPOS STILL ON `lineage-24.0` ({} — migrate to `yasvara-17.0` / fold into vendor/yasvara):", yas_legacy.len());
        for p in &yas_legacy {
            println!("  [YAS24] {:<44} rev={} ({})", p.path, p.revision, p.name);
        }
    }

    if scan_refs {
        println!("\n==========================================================================================");
        println!("LIVE BUILD & CODE REFERENCE SCAN (hard LineageOS coupling hotspots)");
        println!("==========================================================================================");
        let targets = [
            "device/xiaomi/onyx",
            "device/xiaomi/grus",
            "device/xiaomi/sdm710-common",
            "vendor/yasvara",
            "frameworks/base",
            "packages/apps/Settings",
            "packages/apps/Pentas",
        ];
        let patterns = [
            ("vendor/lineage mk", r"vendor/lineage/"),
            ("lineage-sdk/org.lineageos", r"org\.lineageos\.|lineageos\.providers|lineage-sdk"),
            ("vendor.lineage HALs", r"vendor\.lineage\.|hardware/lineage/"),
            ("device/lineage/sepolicy", r"device/lineage/sepolicy"),
            ("LINEAGE_* / ro.lineage.*", r"\bLINEAGE_[A-Z0-9_]+|ro\.lineage\.|persist\.lineage\."),
            ("hardware/qcom-caf", r"hardware/qcom-caf/"),
        ];
        for t in targets {
            let dir = src_root.join(t);
            if !dir.is_dir() {
                continue;
            }
            let mut parts = Vec::new();
            for (lbl, pat) in patterns {
                let (rc, out) = rg(&dir, &["-c", "--no-heading", pat]);
                if rc == 0 {
                    let files = out.lines().filter(|l| !l.trim().is_empty()).count();
                    let matches: usize = out
                        .lines()
                        .filter_map(|l| l.rsplit(':').next()?.trim().parse::<usize>().ok())
                        .sum();
                    if matches > 0 {
                        parts.push(format!("{lbl}={matches}({files}f)"));
                    }
                }
            }
            if parts.is_empty() {
                println!("  [CLEAN] {:<30} 0 LineageOS references!", t);
            } else {
                println!("  [REFS ] {:<30} {}", t, parts.join(" | "));
            }
        }
    } else {
        println!("\nTip: pass `--scan-refs` to audit exact LineageOS references in onyx/grus/vendor/yasvara/frameworks, or `--check-delta` for P2 commit summaries.");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_key_ordering() {
        assert!(nat_key("v6.6.162") > nat_key("v6.6.99"));
        assert!(nat_key("LA.QSSI.17.0.r1-12500-qssi.0") > nat_key("LA.QSSI.17.0.r1-12300-qssi.0"));
        assert!(nat_key("LA.QSSI.17.0.r1-10300-qssi.0") > nat_key("LA.QSSI.17.0.r1-9700-qssi.0"));
        assert!(nat_key("android-security-17.0.0_r3") > nat_key("android-security-17.0.0_r2"));
        assert!(nat_key("AU_TECHPACK_DISPLAY.LA.5.0.R1.00.00.00.000.100") > nat_key("AU_TECHPACK_DISPLAY.LA.5.0.R1.00.00.00.000.087"));
    }

    #[test]
    fn test_base64_and_makefile_kver() {
        // "VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 117\n"
        let b64 = "VkVSU0lPTiA9IDYKUEFUQ0hMRVZFTCA9IDEyClNVQkxFVkVMID0gMTE3Cg==";
        let dec = decode_base64(b64);
        assert_eq!(parse_makefile_kver(&dec), Some("v6.12.117".to_string()));
    }

    #[test]
    fn test_clo_tag_mapping() {
        assert_eq!(
            clo_tag_to_repo_and_file("LA.QSSI.17.0.r1-12500-qssi.0"),
            Some(("la/system/manifest".into(), "LA.QSSI.17.0.r1-12500-qssi.0.xml".into()))
        );
        assert_eq!(
            clo_tag_to_repo_and_file("LA.VENDOR.15.4.0.r1-21700-pakala.QSSI16.0"),
            Some(("la/vendor/manifest".into(), "LA.VENDOR.15.4.0.r1-21700-pakala.QSSI16.0.xml".into()))
        );
        assert_eq!(
            clo_tag_to_repo_and_file("KERNEL.PLATFORM.4.0.r1-18600-kernel.0"),
            Some(("kernelplatform/manifest".into(), "KERNEL.PLATFORM.4.0.r1-18600-kernel.0.xml".into()))
        );
        assert_eq!(
            clo_tag_to_repo_and_file("AU_TECHPACK_DISPLAY.LA.5.0.R1.00.00.00.000.087"),
            Some(("techpack/display/manifest".into(), "AU_TECHPACK_DISPLAY.LA.5.0.R1.00.00.00.000.087.xml".into()))
        );
        assert_eq!(
            clo_tag_to_repo_and_file("AU_TECHPACK_AUDIO_HANDSET.LA.10.0.R1.00.00.00.000.082"),
            Some(("techpack/audio/manifest".into(), "AU_TECHPACK_AUDIO_HANDSET.LA.10.0.R1.00.00.00.000.082.xml".into()))
        );
        assert_eq!(clo_tag_to_repo_and_file("unknown-tag"), None);
    }

    #[test]
    fn test_unused_soc_classifier() {
        assert!(is_unused_soc_path("hardware/qcom-caf/sm8650/display"));
        assert!(is_unused_soc_path("device/qcom/sepolicy_vndr/sm8850"));
        assert!(is_unused_soc_path("lineage/wiki"));
        assert!(!is_unused_soc_path("hardware/qcom-caf/sm8750/display/hal"));
        assert!(!is_unused_soc_path("device/qcom/sepolicy_vndr/sm8750"));
        assert!(!is_unused_soc_path("vendor/lineage"));
    }
}
