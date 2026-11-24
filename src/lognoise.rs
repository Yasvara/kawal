//! Live logcat noise hunter & prebuilt Xiaomi/QCOM ELF silence planner:
//!   - `ktool log-noise [-s <serial>] [--lines N] [--min N] [--level V,D,I,W,E] [--all] [--no-blobs] [--json]`
//!
//! Pulls recent logcat + live `/proc/<pid>/{exe,maps}` + active `log.tag.*` props in a
//! single ADB shell round-trip, attributes noisy V/D/I/W/E tags back to the exact owning
//! prebuilt ELF binary/library in `src/vendor/xiaomi/onyx/proprietary/`, checks its
//! imported `liblog` symbols (`__android_log_print`, `__android_log_is_loggable`, etc.),
//! and classifies each noisy log into `ELF-PATCH` vs `PROP` vs `SOURCE` vs `REVIEW`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use crate::device::{json_escape, parse_getprop, parse_sections, run_adb_probe, select_adb_device};
use crate::util::*;

#[derive(Clone, Debug)]
pub struct LogNoiseOpts {
    pub serial: Option<String>,
    pub lines: usize,
    pub min_hits: usize,
    pub include_all: bool,
    pub levels: BTreeSet<char>,
    pub resolve_blobs: bool,
    pub json: bool,
}

impl Default for LogNoiseOpts {
    fn default() -> Self {
        let mut levels = BTreeSet::new();
        for c in ['V', 'D', 'I', 'W'] {
            levels.insert(c);
        }
        Self {
            serial: None,
            lines: 8000,
            min_hits: 5,
            include_all: false,
            levels,
            resolve_blobs: true,
            json: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitterOrigin {
    PrebuiltOdm,
    PrebuiltVendor,
    OssVendor,
    System,
    App,
    Unknown,
}

impl EmitterOrigin {
    fn label(self) -> &'static str {
        match self {
            EmitterOrigin::PrebuiltOdm => "ODM-BLOB",
            EmitterOrigin::PrebuiltVendor => "VND-BLOB",
            EmitterOrigin::OssVendor => "OSS-VND",
            EmitterOrigin::System => "SYSTEM",
            EmitterOrigin::App => "APP",
            EmitterOrigin::Unknown => "UNKNOWN",
        }
    }

    fn is_vendor_or_blob(self) -> bool {
        matches!(
            self,
            EmitterOrigin::PrebuiltOdm | EmitterOrigin::PrebuiltVendor | EmitterOrigin::OssVendor
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SilenceAction {
    ElfPatch,
    Prop,
    Source,
    ReviewWarn,
    KeepErr,
}

impl SilenceAction {
    fn label(self) -> &'static str {
        match self {
            SilenceAction::ElfPatch => "ELF-PATCH",
            SilenceAction::Prop => "PROP",
            SilenceAction::Source => "SOURCE",
            SilenceAction::ReviewWarn => "REVIEW",
            SilenceAction::KeepErr => "KEEP-ERR",
        }
    }
}

#[derive(Clone, Debug)]
struct ProcInfo {
    uid: u32,
    user: String,
    name: String,
    args: String,
    exe: String,
    maps: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ParsedLogLine {
    pub ts_sec: Option<f64>,
    pub pid: u32,
    pub level: char,
    pub tag: String,
    pub msg: String,
}

#[derive(Clone, Debug)]
struct ElfProfile {
    device_path: String,
    rel_path: String,
    is_proprietary: bool,
    in_extract_files: bool,
    log_imports: Vec<&'static str>,
    has_is_loggable: bool,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct NoiseRecord {
    tag: String,
    pid: u32,
    proc_name: String,
    exe: String,
    origin: EmitterOrigin,
    total_hits: usize,
    rate_per_min: f64,
    level_counts: BTreeMap<char, usize>,
    top_norm_msg: String,
    top_raw_msg: String,
    static_anchor: String,
    attributed_elf: Option<String>,
    match_confidence: &'static str,
    elf_in_extract: bool,
    elf_log_imports: Vec<&'static str>,
    elf_has_is_loggable: bool,
    action: SilenceAction,
    reason: String,
    suggestion: String,
}

// ====================================================== Parsing helpers

/// Parse Android `logcat -v threadtime` line:
/// `11-22 11:05:25.436  1656  1656 I [AIDL] TouchFeatureSensor: onEvent: send hand detect result 0`
pub fn parse_threadtime_line(line: &str) -> Option<ParsedLogLine> {
    let mut it = line.split_whitespace();
    let _date = it.next()?;
    let time_s = it.next()?;
    let pid_s = it.next()?;
    let _tid_s = it.next()?;
    let lvl_s = it.next()?;

    if lvl_s.len() != 1 {
        return None;
    }
    let level = lvl_s.chars().next()?;
    if !matches!(level, 'V' | 'D' | 'I' | 'W' | 'E' | 'F') {
        return None;
    }
    let pid: u32 = pid_s.parse().ok()?;

    // Parse HH:MM:SS.mmm into seconds-of-day for span calculation
    let ts_sec = parse_hms_seconds(time_s);

    // Find `<level> ` after pid/tid safely
    let lvl_pat = format!(" {level} ");
    let pid_pos = line.find(pid_s)?;
    let rel_lvl = line[pid_pos..].find(&lvl_pat)?;
    let after_lvl = &line[pid_pos + rel_lvl + lvl_pat.len()..];
    let (tag_raw, msg_raw) = after_lvl.split_once(':')?;
    let tag = tag_raw.trim().to_string();
    if tag.is_empty() {
        return None;
    }
    Some(ParsedLogLine {
        ts_sec,
        pid,
        level,
        tag,
        msg: msg_raw.trim().to_string(),
    })
}

fn parse_hms_seconds(t: &str) -> Option<f64> {
    let mut p = t.split(':');
    let h: f64 = p.next()?.parse().ok()?;
    let m: f64 = p.next()?.parse().ok()?;
    let s: f64 = p.next()?.parse().ok()?;
    Some(h * 3600.0 + m * 60.0 + s)
}

pub fn normalize_msg_signature(msg: &str) -> String {
    let mut norm = String::with_capacity(msg.len().min(110));
    let mut chars = msg.chars().peekable();
    let mut prev_eq = false;
    while let Some(ch) = chars.next() {
        if norm.chars().count() >= 100 {
            break;
        }
        if ch == '0' && matches!(chars.peek(), Some('x' | 'X')) {
            chars.next();
            norm.push_str("0x*");
            while matches!(chars.peek(), Some(c) if c.is_ascii_hexdigit()) {
                chars.next();
            }
            prev_eq = false;
        } else if ch.is_ascii_digit() {
            let mut num = String::new();
            num.push(ch);
            while matches!(chars.peek(), Some(c) if c.is_ascii_digit() || *c == '.') {
                num.push(chars.next().unwrap());
            }
            if num.len() >= 2 || prev_eq {
                norm.push('#');
            } else {
                norm.push_str(&num);
            }
            prev_eq = false;
        } else {
            prev_eq = ch == '=';
            norm.push(ch);
        }
    }
    norm.trim().to_string()
}

/// Extract the longest stable literal substring (no digits / hex / format-filled vars)
/// from a sample log message for matching against prebuilt ELF `.rodata` format strings.
pub fn extract_static_anchor(msg: &str) -> String {
    let mut best = "";
    let mut cur_start: Option<usize> = None;

    for (i, c) in msg.char_indices() {
        let is_good = c.is_ascii_alphabetic()
            || matches!(c, ' ' | '_' | '-' | ':' | '/' | '.' | '[' | ']' | '(' | ')');
        if is_good {
            if cur_start.is_none() {
                cur_start = Some(i);
            }
        } else if let Some(s) = cur_start.take() {
            let cand = msg[s..i].trim();
            if cand.len() > best.len() && cand.bytes().filter(|x| x.is_ascii_alphabetic()).count() >= 6 {
                best = cand;
            }
        }
    }
    if let Some(s) = cur_start {
        let cand = msg[s..].trim();
        if cand.len() > best.len() && cand.bytes().filter(|x| x.is_ascii_alphabetic()).count() >= 6 {
            best = cand;
        }
    }
    let trimmed = best.trim_matches(|c: char| matches!(c, ' ' | ':' | '=' | ',' | '-' | '(' | '['));
    truncate_str(trimmed, 44).to_string()
}

/// Extract colon/delimited sub-anchors from a formatted log line so `printf("%s: %s: lit", ...)`
/// still matches the exact `.rodata` literal even when prefixes come from `__func__` or helper wrappers.
fn extract_msg_anchors(msg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let full = extract_static_anchor(msg);
    if full.len() >= 10 {
        out.push(full);
    }
    for seg in msg.split(':') {
        let a = extract_static_anchor(seg);
        if a.len() >= 10 && !out.iter().any(|x| x == &a) {
            out.push(a);
        }
    }
    out
}

pub fn is_valid_prop_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 31
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn level_rank(c: char) -> u8 {
    match c {
        'V' => 2,
        'D' => 3,
        'I' => 4,
        'W' => 5,
        'E' => 6,
        'F' | 'A' => 7,
        'S' => 8,
        _ => 0,
    }
}

fn parse_prop_level_rank(val: &str) -> u8 {
    match val.trim().to_ascii_uppercase().as_str() {
        "V" | "VERBOSE" => 2,
        "D" | "DEBUG" => 3,
        "I" | "INFO" => 4,
        "W" | "WARN" | "WARNING" => 5,
        "E" | "ERROR" => 6,
        "A" | "ASSERT" | "F" | "FATAL" => 7,
        "S" | "SILENT" | "SUPPRESS" => 8,
        _ => 0,
    }
}

fn is_critical_warning(msg: &str) -> bool {
    let low = msg.to_ascii_lowercase();
    for kw in [
        "panic",
        "abort",
        "corrupt",
        "watchdog",
        "fatal",
        "tombstone",
        "selinux",
        "avc: denied",
        "thermal shutdown",
        "out of memory",
        "dead_object",
        "sigsegv",
        "sigabrt",
    ] {
        if low.contains(kw) {
            return true;
        }
    }
    false
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let first = needle[0];
    let last = needle[needle.len() - 1];
    let nlen = needle.len();
    let mut off = 0usize;
    let limit = haystack.len() - nlen;
    while off <= limit {
        let Some(rel) = haystack[off..=limit].iter().position(|&b| b == first) else {
            return false;
        };
        let pos = off + rel;
        if haystack[pos + nlen - 1] == last && &haystack[pos..pos + nlen] == needle {
            return true;
        }
        off = pos + 1;
    }
    false
}

fn is_generic_runtime_lib(dev_path: &str) -> bool {
    let base = dev_path.rsplit('/').next().unwrap_or(dev_path);
    if base.starts_with("android.hardware.") && base.ends_with("-ndk.so") {
        return true;
    }
    if base.starts_with("android.frameworks.") && base.ends_with("-ndk.so") {
        return true;
    }
    matches!(
        base,
        "libc.so"
            | "libm.so"
            | "libdl.so"
            | "libc++.so"
            | "libbase.so"
            | "libutils.so"
            | "libcutils.so"
            | "liblog.so"
            | "libhidlbase.so"
            | "libbinder.so"
            | "libbinder_ndk.so"
            | "libxml2.so"
            | "libtinyxml2.so"
            | "libtinyxml2-v34.so"
            | "libjsoncpp.so"
            | "libz.so"
            | "libstagefright_foundation.so"
            | "libvndksupport.so"
            | "libprocessgroup.so"
    )
}

// ====================================================== ADB Probe & Process Parsing

fn build_lognoise_probe(lines: usize, include_all: bool) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("LC_ALL=C\n");
    s.push_str("echo '@@SEC:META@@'\n");
    s.push_str("echo \"uid=$(id -u)\"\n");
    s.push_str("echo '@@SEC:LOGCAT@@'\n");
    s.push_str(&format!(
        "logcat -d -b main -b system -b radio -v threadtime -t {lines} 2>/dev/null || true\n"
    ));
    s.push_str("echo '@@SEC:PS@@'\n");
    s.push_str("ps -A -o PID,UID,USER,NAME,ARGS 2>/dev/null || true\n");
    s.push_str("echo '@@SEC:LOGPROPS@@'\n");
    s.push_str("getprop 2>/dev/null | grep -iE 'log\\.tag\\.|persist\\.vendor\\..*log|debug\\..*log' || true\n");
    s.push_str("echo '@@SEC:PROCMAPS@@'\n");
    // Collect exe + mapped /odm & /vendor .so for vendor/odm (or system) daemons in one fast pass
    let exe_case = if include_all {
        "/vendor/*|/odm/*|/system_ext/*|/system/bin/*"
    } else {
        "/vendor/*|/odm/*|/system_ext/*"
    };
    s.push_str("for d in /proc/[0-9]*; do\n");
    s.push_str("  pid=${d#/proc/}\n");
    s.push_str("  exe=$(readlink \"$d/exe\" 2>/dev/null) || continue\n");
    s.push_str(&format!("  case \"$exe\" in\n    {exe_case})\n"));
    s.push_str("      case \"$exe\" in /system/bin/app_process*) continue;; esac\n");
    s.push_str("      echo \"@@PID:$pid:$exe@@\"\n");
    s.push_str("      awk '/\\/(vendor|odm|system_ext)\\/.*\\.so$/ {print $NF}' \"$d/maps\" 2>/dev/null | sort -u\n");
    s.push_str("      ;;\n");
    s.push_str("  esac\n");
    s.push_str("done\n");
    s.push_str("echo '@@SEC:END@@'\n");
    s
}

fn parse_ps_and_maps(ps_text: &str, maps_text: &str) -> HashMap<u32, ProcInfo> {
    let mut procs: HashMap<u32, ProcInfo> = HashMap::new();
    for ln in ps_text.lines().skip(1) {
        let mut it = ln.split_whitespace();
        let Some(pid_s) = it.next() else { continue };
        let Ok(pid) = pid_s.parse::<u32>() else { continue };
        let uid: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let user = it.next().unwrap_or("").to_string();
        let name = it.next().unwrap_or("").to_string();
        let args = it.collect::<Vec<_>>().join(" ");
        procs.insert(
            pid,
            ProcInfo {
                uid,
                user,
                name,
                args,
                exe: String::new(),
                maps: Vec::new(),
            },
        );
    }

    let mut cur_pid: Option<u32> = None;
    for ln in maps_text.lines() {
        if let Some(rest) = ln.strip_prefix("@@PID:") {
            if let Some(inner) = rest.strip_suffix("@@") {
                if let Some((pid_s, exe)) = inner.split_once(':') {
                    if let Ok(pid) = pid_s.parse::<u32>() {
                        cur_pid = Some(pid);
                        let ent = procs.entry(pid).or_insert_with(|| ProcInfo {
                            uid: 0,
                            user: String::new(),
                            name: exe.rsplit('/').next().unwrap_or(exe).to_string(),
                            args: exe.to_string(),
                            exe: exe.to_string(),
                            maps: Vec::new(),
                        });
                        ent.exe = exe.to_string();
                    }
                }
            }
        } else if let Some(pid) = cur_pid {
            let p = ln.trim();
            if p.starts_with('/') && p.ends_with(".so") {
                if let Some(ent) = procs.get_mut(&pid) {
                    ent.maps.push(p.to_string());
                }
            }
        }
    }
    procs
}

fn classify_proc_origin(proc_info: Option<&ProcInfo>, prop_root: &Path) -> EmitterOrigin {
    let Some(p) = proc_info else {
        return EmitterOrigin::Unknown;
    };
    if p.uid >= 10000 || p.user.starts_with("u0_a") {
        return EmitterOrigin::App;
    }
    let exe = p.exe.as_str();
    if let Some(rel) = exe.strip_prefix('/') {
        if prop_root.join(rel).is_file() {
            if rel.starts_with("odm/") {
                return EmitterOrigin::PrebuiltOdm;
            }
            return EmitterOrigin::PrebuiltVendor;
        }
    }
    if exe.starts_with("/odm/") {
        return EmitterOrigin::PrebuiltOdm;
    }
    if exe.starts_with("/vendor/")
        || p.name.contains("vendor.")
        || p.name.contains("qcril")
        || p.name.contains("mi_")
        || p.name.contains("audiohal")
    {
        return EmitterOrigin::OssVendor;
    }
    EmitterOrigin::System
}

// ====================================================== Local Prebuilt ELF Attribution

fn load_elf_profiles(
    ctx: &Ctx,
    dev_paths: &BTreeSet<String>,
    prop_root: &Path,
    extract_text: &str,
) -> HashMap<String, ElfProfile> {
    let paths_vec: Vec<String> = dev_paths
        .iter()
        .filter(|p| !is_generic_runtime_lib(p))
        .cloned()
        .collect();
    let profiles: Vec<Option<ElfProfile>> = par_map(&paths_vec, ctx.threads, |dev_p| {
        let rel = dev_p.trim_start_matches('/');
        let prop_cand = prop_root.join(rel);
        let (local_path, is_proprietary) = if prop_cand.is_file() {
            (prop_cand, true)
        } else {
            let out_cand = ctx.product_out.join(rel);
            if out_cand.is_file() {
                (out_cand, false)
            } else {
                return None;
            }
        };
        let Ok(meta) = fs::metadata(&local_path) else {
            return None;
        };
        // Skip huge ML model/runtime blobs (> 24 MiB) that aren't normal HAL binaries
        if meta.len() > 24 * 1024 * 1024 {
            return None;
        }
        let Ok(bytes) = fs::read(&local_path) else {
            return None;
        };
        if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
            return None;
        }
        let mut log_imports = Vec::new();
        for sym in [
            "__android_log_print",
            "__android_log_vprint",
            "__android_log_buf_print",
            "__android_log_write",
            "__android_log_buf_write",
        ] {
            if contains_bytes(&bytes, sym.as_bytes()) {
                log_imports.push(sym);
            }
        }
        let has_is_loggable = contains_bytes(&bytes, b"__android_log_is_loggable")
            || contains_bytes(&bytes, b"android_log_is_loggable");
        let in_extract_files = extract_text.contains(rel);

        Some(ElfProfile {
            device_path: dev_p.clone(),
            rel_path: rel.to_string(),
            is_proprietary,
            in_extract_files,
            log_imports,
            has_is_loggable,
            bytes,
        })
    });

    let mut map = HashMap::new();
    for p in profiles.into_iter().flatten() {
        map.insert(p.device_path.clone(), p);
    }
    map
}

fn attribute_tag_to_elf<'a>(
    tag: &str,
    anchors: &[String],
    proc_info: Option<&ProcInfo>,
    profiles: &'a HashMap<String, ElfProfile>,
) -> (Option<&'a ElfProfile>, &'static str) {
    let Some(p) = proc_info else {
        return (None, "none");
    };
    let mut candidates: Vec<&str> = Vec::new();
    if !p.exe.is_empty() {
        candidates.push(p.exe.as_str());
    }
    for m in &p.maps {
        candidates.push(m.as_str());
    }

    let mut null_tag_null = Vec::with_capacity(tag.len() + 2);
    null_tag_null.push(0);
    null_tag_null.extend_from_slice(tag.as_bytes());
    null_tag_null.push(0);

    let mut tag_null = Vec::with_capacity(tag.len() + 1);
    tag_null.extend_from_slice(tag.as_bytes());
    tag_null.push(0);

    let mut best_score: i32 = -100;
    let mut best_prof: Option<&ElfProfile> = None;
    let mut best_conf: &'static str = "EXE";

    for dev_p in candidates {
        let Some(prof) = profiles.get(dev_p) else {
            continue;
        };
        let mut score: i32 = 0;
        let tag_exact = contains_bytes(&prof.bytes, &null_tag_null);
        let tag_tail = !tag_exact && contains_bytes(&prof.bytes, &tag_null);
        let msg_hits = anchors
            .iter()
            .filter(|a| a.len() >= 10 && contains_bytes(&prof.bytes, a.as_bytes()))
            .count();
        let msg_hit = msg_hits > 0;

        if tag_exact {
            score += 10;
        } else if tag_tail {
            score += 5;
        }
        if msg_hit {
            score += 14 + ((msg_hits.min(3) - 1) as i32 * 4);
        }
        if !prof.log_imports.is_empty() {
            score += 4;
        }
        if prof.is_proprietary {
            score += 3;
        }
        if is_generic_runtime_lib(dev_p) {
            score -= 12;
        }
        // Prefer specific library match over generic exe when scores tie and msg/tag matched
        if dev_p != p.exe && (tag_exact || msg_hit) {
            score += 1;
        }

        if score > best_score {
            best_score = score;
            best_prof = Some(prof);
            best_conf = if (tag_exact || tag_tail) && msg_hit {
                "EXACT"
            } else if msg_hit {
                "MSG"
            } else if tag_exact || tag_tail {
                "TAG"
            } else {
                "EXE"
            };
        }
    }

    // If best had neither tag nor msg match, fall back cleanly to the process exe profile if available
    if best_conf == "EXE" {
        if let Some(exe_prof) = profiles.get(&p.exe) {
            return (Some(exe_prof), "EXE");
        }
    }
    (best_prof, best_conf)
}

fn decide_silence_plan(
    tag: &str,
    levels: &BTreeMap<char, usize>,
    sample_msg: &str,
    origin: EmitterOrigin,
    active_prop: Option<&str>,
    elf: Option<&ElfProfile>,
) -> (SilenceAction, String, String) {
    let has_e = levels.get(&'E').copied().unwrap_or(0) > 0 || levels.get(&'F').copied().unwrap_or(0) > 0;
    let has_w = levels.get(&'W').copied().unwrap_or(0) > 0;
    let lowest_lvl = ['V', 'D', 'I', 'W', 'E', 'F']
        .into_iter()
        .find(|c| levels.get(c).copied().unwrap_or(0) > 0)
        .unwrap_or('I');
    let highest_non_e = ['W', 'I', 'D', 'V']
        .into_iter()
        .find(|c| levels.get(c).copied().unwrap_or(0) > 0);

    // Pure error/fatal lines should be investigated, not silenced blindly
    if has_e && highest_non_e.is_none() {
        return (
            SilenceAction::KeepErr,
            "error-level log (fix root cause)".into(),
            "investigate error".into(),
        );
    }
    if has_w && is_critical_warning(sample_msg) {
        return (
            SilenceAction::ReviewWarn,
            "warning contains critical keyword".into(),
            "review before muting".into(),
        );
    }

    let prop_safe = is_valid_prop_tag(tag);
    let prop_already_stricter = active_prop.is_some_and(|pv| {
        let pr = parse_prop_level_rank(pv);
        pr > 0 && pr > level_rank(lowest_lvl)
    });

    let is_prop_blob = elf.is_some_and(|e| e.is_proprietary)
        || matches!(origin, EmitterOrigin::PrebuiltOdm | EmitterOrigin::PrebuiltVendor);

    let suggested_prop_lvl = if has_w { "E" } else { "W" };

    if is_prop_blob {
        let rel = elf.map(|e| e.rel_path.as_str()).unwrap_or("(prebuilt blob)");
        if prop_already_stricter {
            return (
                SilenceAction::ElfPatch,
                format!("ignores active prop `{}`", active_prop.unwrap_or("")),
                format!("patch {rel}"),
            );
        }
        if !prop_safe {
            return (
                SilenceAction::ElfPatch,
                "non-prop-safe tag (brackets/spaces/len)".into(),
                format!("patch {rel}"),
            );
        }
        if let Some(e) = elf {
            if !e.log_imports.is_empty() && !e.has_is_loggable {
                return (
                    SilenceAction::ElfPatch,
                    format!("raw {} (no is_loggable)", e.log_imports[0]),
                    format!("patch {rel}"),
                );
            }
            // Note: AOSP liblog's __android_log_print does NOT filter I/W unless caller checks is_loggable
            if (has_w || levels.get(&'I').copied().unwrap_or(0) > 0) && !e.has_is_loggable {
                return (
                    SilenceAction::ElfPatch,
                    "unfiltered I/W in prebuilt blob".into(),
                    format!("patch {rel}"),
                );
            }
            if e.has_is_loggable && prop_safe {
                return (
                    SilenceAction::Prop,
                    "blob imports is_loggable (try prop first, fallback ELF)".into(),
                    format!("persist.log.tag.{tag}={suggested_prop_lvl}"),
                );
            }
        }
        return (
            SilenceAction::ElfPatch,
            "prebuilt vendor/odm blob".into(),
            format!("patch {rel}"),
        );
    }

    if origin == EmitterOrigin::OssVendor {
        if prop_safe && !prop_already_stricter {
            return (
                SilenceAction::Prop,
                "OSS vendor daemon (prop or source)".into(),
                format!("persist.log.tag.{tag}={suggested_prop_lvl}"),
            );
        }
        return (
            SilenceAction::Source,
            "OSS vendor daemon (fix in source)".into(),
            "gate/remove log in source".into(),
        );
    }

    if prop_safe && !prop_already_stricter {
        (
            SilenceAction::Prop,
            "prop-safe tag".into(),
            format!("persist.log.tag.{tag}={suggested_prop_lvl}"),
        )
    } else {
        (
            SilenceAction::Source,
            "system/app emitter".into(),
            "reduce log level in source".into(),
        )
    }
}

// ====================================================== Compact helper for `ktool health`

/// Summarize top vendor/ODM V/D/I/W log noise from an already-captured `logcat` + `ps` slice
/// (used inside `ktool health` section `[9]` with zero extra ADB round-trips).
pub fn summarize_vendor_noise_inline(logcat_text: &str, ps_text: &str, limit: usize) -> Vec<(usize, char, String, String, String)> {
    let mut pid_meta: HashMap<u32, (u32, String)> = HashMap::new();
    for ln in ps_text.lines().skip(1) {
        let mut it = ln.split_whitespace();
        let Some(pid_s) = it.next() else { continue };
        let Ok(pid) = pid_s.parse::<u32>() else { continue };
        // `ps -A -o PID,USER,NAME,ARGS` in health has USER in col 2, NAME in col 3
        let user = it.next().unwrap_or("");
        let name = it.next().unwrap_or("").to_string();
        let is_app = user.starts_with("u0_a") || user.starts_with("u10_a");
        pid_meta.insert(pid, (if is_app { 10000 } else { 1000 }, name));
    }

    // (tag, level, proc_name) -> (count, sample_msg)
    let mut map: BTreeMap<(String, char, String), (usize, String)> = BTreeMap::new();
    for ln in logcat_text.lines() {
        let Some(p) = parse_threadtime_line(ln) else { continue };
        if !matches!(p.level, 'V' | 'D' | 'I' | 'W') {
            continue;
        }
        let (uid_est, pname) = pid_meta
            .get(&p.pid)
            .cloned()
            .unwrap_or_else(|| (0, format!("pid:{}", p.pid)));
        if uid_est >= 10000 {
            continue;
        }
        let looks_vendor = pname.contains("vendor.")
            || pname.contains("xiaomi")
            || pname.contains("qti")
            || pname.contains("audiohal")
            || pname.contains("qcril")
            || pname.contains("mi_")
            || pname.contains("touch")
            || pname.contains("media.hwcodec")
            || pname.contains("media.audio")
            || pname.contains("display")
            || pname.contains("sensors")
            || pname.contains("camera")
            || pname.contains("thermal")
            || p.tag.starts_with("[THP")
            || p.tag.starts_with("[AIDL]")
            || p.tag == "SnapAlloc"
            || p.tag == "qdgralloc"
            || p.tag == "SRE"
            || p.tag == "IGCDither"
            || p.tag == "PAL"
            || p.tag == "AGM";
        if !looks_vendor {
            continue;
        }
        let key = (p.tag, p.level, pname);
        map.entry(key)
            .and_modify(|(c, _)| *c += 1)
            .or_insert_with(|| (1, normalize_msg_signature(&p.msg)));
    }

    let mut ranked: Vec<(usize, char, String, String, String)> = map
        .into_iter()
        .filter(|(_, (c, _))| *c >= 4)
        .map(|((tag, lvl, proc_n), (cnt, msg))| (cnt, lvl, tag, proc_n, msg))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.2.cmp(&b.2)));
    ranked.truncate(limit);
    ranked
}

// ====================================================== Main `ktool log-noise`

pub fn cmd_log_noise(ctx: &Ctx, opts: &LogNoiseOpts) -> i32 {
    let dev = match select_adb_device(ctx, opts.serial.as_deref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("!! ktool log-noise: {e}");
            return 1;
        }
    };

    let script = build_lognoise_probe(opts.lines, opts.include_all);
    let raw = match run_adb_probe(ctx, &dev.serial, &script) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("!! ktool log-noise: {e}");
            return 1;
        }
    };

    let secs = parse_sections(&raw);
    let log_text = secs.get("LOGCAT").map(|s| s.as_str()).unwrap_or("");
    let ps_text = secs.get("PS").map(|s| s.as_str()).unwrap_or("");
    let maps_text = secs.get("PROCMAPS").map(|s| s.as_str()).unwrap_or("");
    let props_map = parse_getprop(secs.get("LOGPROPS").map(|s| s.as_str()).unwrap_or(""));

    let procs = parse_ps_and_maps(ps_text, maps_text);
    let prop_root = ctx.ws_root.join("src/vendor/xiaomi/onyx/proprietary");
    let extract_path = ctx.ws_root.join("src/device/xiaomi/onyx/extract-files.py");
    let extract_text = fs::read_to_string(&extract_path).unwrap_or_default();

    // Parse logcat & aggregate per (tag, pid)
    struct Agg {
        total: usize,
        levels: BTreeMap<char, usize>,
        // norm_msg -> (count, first_raw_msg)
        msgs: HashMap<String, (usize, String)>,
    }

    let mut aggs: HashMap<(String, u32), Agg> = HashMap::new();
    let mut parsed_lines = 0usize;
    let mut first_ts: Option<f64> = None;
    let mut last_ts: Option<f64> = None;
    let mut vol_by_origin: BTreeMap<&'static str, usize> = BTreeMap::new();

    for ln in log_text.lines() {
        let Some(p) = parse_threadtime_line(ln) else {
            continue;
        };
        parsed_lines += 1;
        if let Some(ts) = p.ts_sec {
            if first_ts.is_none() {
                first_ts = Some(ts);
            }
            last_ts = Some(ts);
        }
        let orig = classify_proc_origin(procs.get(&p.pid), &prop_root);
        *vol_by_origin.entry(orig.label()).or_insert(0) += 1;

        if !opts.levels.contains(&p.level) {
            continue;
        }
        let ent = aggs.entry((p.tag, p.pid)).or_insert_with(|| Agg {
            total: 0,
            levels: BTreeMap::new(),
            msgs: HashMap::new(),
        });
        ent.total += 1;
        *ent.levels.entry(p.level).or_insert(0) += 1;
        let norm = normalize_msg_signature(&p.msg);
        ent.msgs
            .entry(norm)
            .and_modify(|(c, _)| *c += 1)
            .or_insert_with(|| (1, p.msg));
    }

    let span_sec = match (first_ts, last_ts) {
        (Some(a), Some(b)) => {
            let mut d = b - a;
            if d < 0.0 {
                d += 86400.0;
            }
            d.max(1.0)
        }
        _ => 60.0,
    };
    let span_min = (span_sec / 60.0).max(0.05);

    // Filter candidate items before loading ELFs so we only scan relevant binaries
    let mut prelim: Vec<((String, u32), Agg, EmitterOrigin)> = aggs
        .into_iter()
        .filter_map(|((tag, pid), agg)| {
            if agg.total < opts.min_hits {
                return None;
            }
            let orig = classify_proc_origin(procs.get(&pid), &prop_root);
            if !opts.include_all && !orig.is_vendor_or_blob() {
                return None;
            }
            Some(((tag, pid), agg, orig))
        })
        .collect();
    prelim.sort_by(|a, b| b.1.total.cmp(&a.1.total).then_with(|| a.0.0.cmp(&b.0.0)));

    // Collect candidate ELF paths from the emitting PIDs
    let profiles = if opts.resolve_blobs {
        let mut dev_paths = BTreeSet::new();
        for ((_, pid), _, orig) in &prelim {
            if !orig.is_vendor_or_blob() && !opts.include_all {
                continue;
            }
            if let Some(pr) = procs.get(pid) {
                if !pr.exe.is_empty() {
                    dev_paths.insert(pr.exe.clone());
                }
                for m in &pr.maps {
                    dev_paths.insert(m.clone());
                }
            }
        }
        load_elf_profiles(ctx, &dev_paths, &prop_root, &extract_text)
    } else {
        HashMap::new()
    };

    // Build final attributed NoiseRecords
    let mut records: Vec<NoiseRecord> = Vec::with_capacity(prelim.len());
    for ((tag, pid), agg, mut origin) in prelim {
        let proc_info = procs.get(&pid);
        let proc_name = proc_info
            .map(|p| {
                if !p.name.is_empty() {
                    p.name.clone()
                } else {
                    p.args.clone()
                }
            })
            .unwrap_or_else(|| format!("pid:{pid}"));
        let exe = proc_info.map(|p| p.exe.clone()).unwrap_or_default();

        let (top_norm, (_, top_raw)) = agg
            .msgs
            .into_iter()
            .max_by_key(|(_, (c, _))| *c)
            .unwrap_or_else(|| (String::new(), (0, String::new())));
        let anchors = extract_msg_anchors(&top_raw);
        let anchor = anchors.first().cloned().unwrap_or_default();

        let active_prop = props_map
            .get(&format!("persist.log.tag.{tag}"))
            .or_else(|| props_map.get(&format!("log.tag.{tag}")))
            .cloned();

        let (elf_prof, conf) = if opts.resolve_blobs {
            attribute_tag_to_elf(&tag, &anchors, proc_info, &profiles)
        } else {
            (None, "skip")
        };

        // Upgrade origin if exact emitting `.so` is a prebuilt proprietary blob (e.g. odm/lib64/libdither.so
        // loaded inside a /vendor/bin/hw/... service!)
        if let Some(ep) = elf_prof {
            if ep.is_proprietary {
                origin = if ep.rel_path.starts_with("odm/") {
                    EmitterOrigin::PrebuiltOdm
                } else {
                    EmitterOrigin::PrebuiltVendor
                };
            }
        }

        let (action, reason, suggestion) = decide_silence_plan(
            &tag,
            &agg.levels,
            &top_raw,
            origin,
            active_prop.as_deref(),
            elf_prof,
        );

        records.push(NoiseRecord {
            tag,
            pid,
            proc_name,
            exe,
            origin,
            total_hits: agg.total,
            rate_per_min: agg.total as f64 / span_min,
            level_counts: agg.levels,
            top_norm_msg: top_norm,
            top_raw_msg: top_raw,
            static_anchor: anchor,
            attributed_elf: elf_prof.map(|e| e.rel_path.clone()),
            match_confidence: conf,
            elf_in_extract: elf_prof.is_some_and(|e| e.in_extract_files),
            elf_log_imports: elf_prof.map(|e| e.log_imports.clone()).unwrap_or_default(),
            elf_has_is_loggable: elf_prof.is_some_and(|e| e.has_is_loggable),
            action,
            reason,
            suggestion,
        });
    }

    // Group prebuilt ELF-PATCH worklist by exact blob path
    struct BlobWorkItem {
        rel_path: String,
        in_extract: bool,
        log_imports: Vec<&'static str>,
        has_is_loggable: bool,
        total_hits: usize,
        tags: Vec<(String, String, usize, String)>, // (tag, levels_str, hits, anchor)
    }
    let mut blob_map: BTreeMap<String, BlobWorkItem> = BTreeMap::new();
    let mut prop_cands: BTreeMap<String, (String, usize, String)> = BTreeMap::new(); // prop_line -> (origin, hits, tag)

    for r in &records {
        let lvl_str: String = r
            .level_counts
            .iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(",");
        match r.action {
            SilenceAction::ElfPatch => {
                let key = r
                    .attributed_elf
                    .clone()
                    .unwrap_or_else(|| r.exe.trim_start_matches('/').to_string());
                if !key.is_empty() {
                    let ent = blob_map.entry(key.clone()).or_insert_with(|| BlobWorkItem {
                        rel_path: key,
                        in_extract: r.elf_in_extract,
                        log_imports: r.elf_log_imports.clone(),
                        has_is_loggable: r.elf_has_is_loggable,
                        total_hits: 0,
                        tags: Vec::new(),
                    });
                    ent.total_hits += r.total_hits;
                    ent.tags.push((
                        r.tag.clone(),
                        lvl_str,
                        r.total_hits,
                        if r.static_anchor.is_empty() {
                            truncate_str(&r.top_norm_msg, 38).to_string()
                        } else {
                            r.static_anchor.clone()
                        },
                    ));
                }
            }
            SilenceAction::Prop => {
                prop_cands
                    .entry(r.suggestion.clone())
                    .and_modify(|x| x.1 += r.total_hits)
                    .or_insert_with(|| (r.origin.label().to_string(), r.total_hits, r.tag.clone()));
            }
            _ => {}
        }
    }
    let mut blob_list: Vec<BlobWorkItem> = blob_map.into_values().collect();
    blob_list.sort_by(|a, b| b.total_hits.cmp(&a.total_hits));

    if opts.json {
        println!("{{");
        println!("  \"device\": {},", json_escape(&dev.serial));
        println!("  \"scanned_lines\": {parsed_lines},");
        println!("  \"span_seconds\": {:.1},", span_sec);
        println!("  \"records\": [");
        for (i, r) in records.iter().enumerate() {
            let comma = if i + 1 < records.len() { "," } else { "" };
            let lvls: String = r
                .level_counts
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "    {{\"tag\":{},\"pid\":{},\"proc\":{},\"origin\":{},\"hits\":{},\"rate_per_min\":{:.1},\"levels\":{},\"elf\":{},\"match\":{},\"in_extract\":{},\"action\":{},\"reason\":{},\"suggestion\":{},\"anchor\":{},\"sample\":{}}}{comma}",
                json_escape(&r.tag),
                r.pid,
                json_escape(&r.proc_name),
                json_escape(r.origin.label()),
                r.total_hits,
                r.rate_per_min,
                json_escape(&lvls),
                json_escape(r.attributed_elf.as_deref().unwrap_or(&r.exe)),
                json_escape(r.match_confidence),
                r.elf_in_extract,
                json_escape(r.action.label()),
                json_escape(&r.reason),
                json_escape(&r.suggestion),
                json_escape(&r.static_anchor),
                json_escape(&truncate_str(&r.top_raw_msg, 100)),
            );
        }
        println!("  ]");
        println!("}}");
        return 0;
    }

    let lvls_disp: String = opts.levels.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
    println!("========================================================================");
    println!(
        "ktool log-noise: vendor/prebuilt log spam hunter [{}] (levels: {lvls_disp})",
        dev.serial
    );
    println!("========================================================================");
    println!(
        "  scanned  : {parsed_lines} lines over {:.1}s ({:.1} min) | min_hits>={} | resolved {} ELFs",
        span_sec,
        span_min,
        opts.min_hits,
        profiles.len()
    );
    let vol_parts: Vec<String> = vol_by_origin
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    println!("  volume   : {}", vol_parts.join("  "));

    println!(
        "\n[1] {} Noisy Log Sources ({}):",
        records.len(),
        if opts.include_all { "all processes" } else { "vendor/ODM/prebuilt only; pass --all for system/apps" }
    );
    if records.is_empty() {
        println!("  clean: no log tags met threshold (min_hits={}) in scanned window", opts.min_hits);
    } else {
        println!(
            "  {:>5} {:>6} {:<9} {:<9} {:<24} {:<10} {}",
            "HITS", "/MIN", "LEVELS", "ORIGIN", "TAG", "ACTION", "ATTRIBUTED BINARY / REASON"
        );
        for r in records.iter().take(40) {
            let lvls: String = r
                .level_counts
                .iter()
                .map(|(k, v)| format!("{k}{v}"))
                .collect::<Vec<_>>()
                .join("/");
            let target = r
                .attributed_elf
                .as_deref()
                .unwrap_or_else(|| if !r.exe.is_empty() { r.exe.as_str() } else { r.proc_name.as_str() });
            println!(
                "  {:>5} {:>6.1} {:<9} {:<9} {:<24} {:<10} {} [{}] ({})",
                r.total_hits,
                r.rate_per_min,
                truncate_str(&lvls, 9),
                r.origin.label(),
                truncate_str(&r.tag, 24),
                r.action.label(),
                target,
                r.match_confidence,
                r.reason
            );
            println!("        sample: {}", truncate_str(&r.top_norm_msg, 98));
        }
    }

    println!("\n[2] Prebuilt Xiaomi/Vendor ELF Patch Targets ({} binaries):", blob_list.len());
    if blob_list.is_empty() {
        println!("  none in this capture window.");
    } else {
        for b in &blob_list {
            let ext_tag = if b.in_extract { "in extract-files.py" } else { "new to extract-files.py" };
            let imps = if b.log_imports.is_empty() {
                "indirect/wrapper".to_string()
            } else {
                b.log_imports.join(",")
            };
            println!(
                "  * {}  ({} hits | {} | liblog: {} | is_loggable={})",
                b.rel_path,
                b.total_hits,
                ext_tag,
                imps,
                if b.has_is_loggable { "yes" } else { "NO" }
            );
            for (tag, lvls, hits, clue) in &b.tags {
                println!("      - tag={:<26} ({:<10} x{:<4}) clue: \"{}\"", tag, lvls, hits, clue);
            }
        }
    }

    println!("\n[3] Zero-Risk Property Silence Candidates (try in device/xiaomi/onyx/properties/vendor.prop):");
    if prop_cands.is_empty() {
        println!("  none in this capture window.");
    } else {
        let mut pvec: Vec<(String, String, usize)> = prop_cands
            .into_iter()
            .map(|(line, (orig, hits, _))| (line, orig, hits))
            .collect();
        pvec.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        for (line, orig, hits) in pvec.iter().take(25) {
            println!("  {:<46} # {:<8} x{}", line, orig, hits);
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_threadtime_with_bracket_and_space_tags() {
        let l1 = "11-22 11:11:25.378  1656  1656 I [AIDL] TouchFeatureSensor: onEvent: send hand detect result 0";
        let p1 = parse_threadtime_line(l1).unwrap();
        assert_eq!(p1.pid, 1656);
        assert_eq!(p1.level, 'I');
        assert_eq!(p1.tag, "[AIDL] TouchFeatureSensor");
        assert_eq!(p1.msg, "onEvent: send hand detect result 0");

        let l2 = "11-22 11:11:25.900  1656  1701 I [THP0]  : frame 12345 status=0";
        let p2 = parse_threadtime_line(l2).unwrap();
        assert_eq!(p2.tag, "[THP0]");
        assert_eq!(p2.level, 'I');
    }

    #[test]
    fn test_extract_static_anchor() {
        let a = extract_static_anchor("onEvent: send hand detect result 4");
        assert_eq!(a, "onEvent: send hand detect result");
        let b = extract_static_anchor("Frame 98123 failed with status=0xdeadbeef in SnapAlloc");
        assert!(b.contains("failed with status") || b.contains("SnapAlloc"));
    }

    #[test]
    fn test_prop_tag_validation() {
        assert!(is_valid_prop_tag("SnapAlloc"));
        assert!(is_valid_prop_tag("vendor.qti.media.c2-1.0"));
        assert!(!is_valid_prop_tag("[THP0]"));
        assert!(!is_valid_prop_tag("[AIDL] TouchFeatureSensor"));
    }

    #[test]
    fn test_silence_plan_prebuilt_ignores_prop_and_brackets() {
        let mut lvls = BTreeMap::new();
        lvls.insert('I', 65);
        let (act, reason, _) = decide_silence_plan(
            "[THP0]",
            &lvls,
            "touch report frame 123",
            EmitterOrigin::PrebuiltOdm,
            None,
            None,
        );
        assert_eq!(act, SilenceAction::ElfPatch);
        assert!(reason.contains("non-prop-safe"));

        // Even a prop-safe tag that ignores an already-stricter prop must map to ELF-PATCH
        let (act2, reason2, _) = decide_silence_plan(
            "SnapAlloc",
            &lvls,
            "allocate buffer ok",
            EmitterOrigin::PrebuiltVendor,
            Some("W"),
            None,
        );
        assert_eq!(act2, SilenceAction::ElfPatch);
        assert!(reason2.contains("ignores active prop"));

        // Critical warning must be flagged for review instead of blindly silenced
        let mut wlvls = BTreeMap::new();
        wlvls.insert('W', 10);
        let (act3, _, _) = decide_silence_plan(
            "ThermalMon",
            &wlvls,
            "imminent thermal shutdown triggered",
            EmitterOrigin::PrebuiltVendor,
            None,
            None,
        );
        assert_eq!(act3, SilenceAction::ReviewWarn);
    }
}
