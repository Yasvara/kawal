//! All-in-one single-shot ADB live device health & diagnostics suite:
//!   - `ktool health [-s <serial>] [--only <secs>] [--full] [--dump-avc] [--json]`
//!   - Shared helpers also usable by `ktool live-audit [--full] [-s <serial>]`
//!
//! Runs a single structured POSIX `sh` probe over `adb shell` (automatically escalating
//! via `su` only if `uid != 0`), parses all sections in Rust, applies strict PASS/WARN/FAIL
//! gates, categorizes & deduplicates SELinux AVCs and logcat errors, scopes tombstones/ANRs
//! to the current boot, and prints a concise engineering report (or `--json`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::util::*;

#[derive(Clone, Debug, Default)]
pub struct HealthOpts {
    pub serial: Option<String>,
    pub only: Option<BTreeSet<String>>,
    pub full: bool,
    pub dump_avc: bool,
    pub json: bool,
}

impl HealthOpts {
    pub fn wants(&self, sec: &str) -> bool {
        match &self.only {
            None => true,
            Some(set) => set.contains(sec),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateStatus {
    Pass,
    Info,
    Warn,
    Fail,
}

impl GateStatus {
    fn as_str(self) -> &'static str {
        match self {
            GateStatus::Pass => "PASS",
            GateStatus::Info => "INFO",
            GateStatus::Warn => "WARN",
            GateStatus::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Debug)]
struct GateRow {
    name: &'static str,
    status: GateStatus,
    summary: String,
}

// ====================================================== ADB device discovery & transport

#[derive(Clone, Debug)]
pub(crate) struct AdbDevice {
    pub(crate) serial: String,
    pub(crate) state: String,
    pub(crate) meta: String,
}

fn list_adb_devices(ctx: &Ctx) -> Result<Vec<AdbDevice>, String> {
    let (rc, out, err) = run_cmd("adb", &["devices", "-l"], &ctx.ws_root, None);
    if rc != 0 {
        return Err(format!("adb devices failed (rc={rc}): {}", err.trim()));
    }
    let mut devs = Vec::new();
    for ln in out.lines().skip(1) {
        let t = ln.trim();
        if t.is_empty() || t.starts_with('*') {
            continue;
        }
        let mut parts = t.split_whitespace();
        let Some(serial) = parts.next() else { continue };
        let Some(state) = parts.next() else { continue };
        let meta = parts.collect::<Vec<_>>().join(" ");
        devs.push(AdbDevice {
            serial: serial.to_string(),
            state: state.to_string(),
            meta,
        });
    }
    Ok(devs)
}

pub(crate) fn select_adb_device(ctx: &Ctx, requested: Option<&str>) -> Result<AdbDevice, String> {
    let devs = list_adb_devices(ctx)?;
    let online: Vec<AdbDevice> = devs.into_iter().filter(|d| d.state == "device").collect();
    if let Some(req) = requested {
        if let Some(found) = online.into_iter().find(|d| d.serial == req) {
            return Ok(found);
        }
        return Err(format!("requested ADB device `{req}` not found or not online"));
    }
    match online.len() {
        0 => Err("no online ADB device found (check USB/ADB authorization)".to_string()),
        1 => Ok(online.into_iter().next().unwrap()),
        n => {
            let ids = online.iter().map(|d| d.serial.as_str()).collect::<Vec<_>>().join(", ");
            Err(format!("{n} ADB devices connected ({ids}); specify `-s <serial>`"))
        }
    }
}

fn build_probe_script(opts: &HealthOpts) -> String {
    let mut s = String::with_capacity(4096);
    s.push_str("LC_ALL=C\n");
    s.push_str("echo '@@SEC:META@@'\n");
    s.push_str("echo \"uid=$(id -u)\"\n");
    s.push_str("echo \"epoch=$(date +%s)\"\n");
    s.push_str("echo \"uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)\"\n");
    s.push_str("echo \"uptime_str=$(uptime 2>/dev/null)\"\n");
    s.push_str("echo \"selinux=$(getenforce 2>/dev/null)\"\n");
    s.push_str("echo \"uname=$(uname -a 2>/dev/null)\"\n");

    if opts.wants("id") || opts.wants("services") || opts.wants("touch") || opts.wants("sys") {
        s.push_str("echo '@@SEC:PROPS@@'\n");
        s.push_str("getprop 2>/dev/null\n");
    }

    if opts.wants("kernel") || opts.wants("avc") || opts.wants("touch") {
        s.push_str("echo '@@SEC:KERNEL@@'\n");
        s.push_str("echo \"tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)\"\n");
        s.push_str("echo '@@SEC:LSMOD@@'\n");
        s.push_str("lsmod 2>/dev/null\n");
        s.push_str("echo '@@SEC:DMESG@@'\n");
        s.push_str("dmesg 2>/dev/null\n");
        s.push_str("echo '@@SEC:DEFERRED@@'\n");
        s.push_str("cat /sys/kernel/debug/devices_deferred 2>/dev/null || true\n");
    }

    if opts.wants("services") {
        s.push_str("echo '@@SEC:PS@@'\n");
        s.push_str("ps -A -o PID,USER,NAME,ARGS 2>/dev/null\n");
        s.push_str("echo '@@SEC:PENTAS@@'\n");
        s.push_str("dumpsys yasvara_pentas 2>/dev/null | head -n 20 || true\n");
    }

    if opts.wants("crashes") {
        s.push_str("echo '@@SEC:TOMBSTONES_LIST@@'\n");
        s.push_str("for f in /data/tombstones/tombstone_*; do\n");
        s.push_str("  case \"$f\" in *.pb|*'tombstone_*') continue;; esac\n");
        s.push_str("  [ -f \"$f\" ] && stat -c '%Y %s %n' \"$f\" 2>/dev/null\n");
        s.push_str("done | sort -rn | head -n 16\n");

        s.push_str("echo '@@SEC:TOMBSTONES_HEAD@@'\n");
        s.push_str("boot_ep=$(awk -v now=\"$(date +%s)\" '{printf \"%d\", now - $1 - 15}' /proc/uptime 2>/dev/null)\n");
        s.push_str("cnt=0\n");
        s.push_str("for f in $(ls -t /data/tombstones/tombstone_* 2>/dev/null | grep -v '\\.pb$' | head -n 8); do\n");
        s.push_str("  [ -f \"$f\" ] || continue\n");
        s.push_str("  mt=$(stat -c '%Y' \"$f\" 2>/dev/null || echo 0)\n");
        s.push_str("  if [ \"$mt\" -ge \"${boot_ep:-0}\" ] || [ \"$cnt\" -lt 2 ]; then\n");
        s.push_str("    echo \"@@TOMB:$f:$mt@@\"\n");
        s.push_str("    head -n 65 \"$f\" 2>/dev/null\n");
        s.push_str("    cnt=$((cnt+1))\n");
        s.push_str("  fi\n");
        s.push_str("done\n");

        s.push_str("echo '@@SEC:ANR_LIST@@'\n");
        s.push_str("for f in /data/anr/*; do\n");
        s.push_str("  [ -f \"$f\" ] && stat -c '%Y %s %n' \"$f\" 2>/dev/null\n");
        s.push_str("done | sort -rn | head -n 10\n");

        s.push_str("echo '@@SEC:LOGCAT_CRASH@@'\n");
        s.push_str("logcat -d -b crash -t 120 2>/dev/null || true\n");
    }

    if opts.wants("touch") {
        s.push_str("echo '@@SEC:TOUCH@@'\n");
        s.push_str("echo '---mounts---'\n");
        s.push_str("mount 2>/dev/null | grep -iE 'thp|touch' || true\n");
        s.push_str("echo '---thp_ini---'\n");
        s.push_str("grep -Hn -E 'game_long_side_for_horizon|game_short_size_for_horizon|game_new_corner_size' /odm/firmware/o10u_nova_*_thp_config.ini 2>/dev/null || true\n");
        s.push_str("echo '---touch_sysfs---'\n");
        s.push_str("echo \"touch_active=$(cat /sys/class/touch/touch_dev/touch_active_status 2>/dev/null)\"\n");
        s.push_str("echo \"palm_sensor=$(cat /sys/class/touch/touch_dev/palm_sensor 2>/dev/null)\"\n");
        s.push_str("echo '---input_devs---'\n");
        s.push_str("for d in /sys/class/input/event*; do\n");
        s.push_str("  [ -r \"$d/device/name\" ] && echo \"$(basename \"$d\"):$(cat \"$d/device/name\" 2>/dev/null)\"\n");
        s.push_str("done\n");
        s.push_str("echo '---display---'\n");
        s.push_str("dumpsys display 2>/dev/null | grep -E 'DisplayDeviceInfo\\{|mActiveModeId=|mCommittedState=' | head -n 6\n");
    }

    if opts.wants("power") {
        s.push_str("echo '@@SEC:POWER@@'\n");
        s.push_str("for f in status capacity voltage_now current_now temp charge_type quick_charge_type; do\n");
        s.push_str("  [ -r \"/sys/class/power_supply/battery/$f\" ] && echo \"bat.$f=$(cat \"/sys/class/power_supply/battery/$f\" 2>/dev/null)\"\n");
        s.push_str("done\n");
        s.push_str("for f in type online voltage_now current_now real_type; do\n");
        s.push_str("  [ -r \"/sys/class/power_supply/usb/$f\" ] && echo \"usb.$f=$(cat \"/sys/class/power_supply/usb/$f\" 2>/dev/null)\"\n");
        s.push_str("done\n");
        s.push_str("echo '---cpu---'\n");
        s.push_str("for p in /sys/devices/system/cpu/cpufreq/policy*; do\n");
        s.push_str("  [ -d \"$p\" ] || continue\n");
        s.push_str("  echo \"$(basename \"$p\")|$(cat \"$p/related_cpus\" 2>/dev/null)|$(cat \"$p/scaling_governor\" 2>/dev/null)|$(cat \"$p/scaling_cur_freq\" 2>/dev/null)|$(cat \"$p/scaling_max_freq\" 2>/dev/null)\"\n");
        s.push_str("done\n");
        s.push_str("echo '---gpu---'\n");
        s.push_str("for f in gpuclk max_gpuclk gpubusy devfreq/governor temp; do\n");
        s.push_str("  [ -r \"/sys/class/kgsl/kgsl-3d0/$f\" ] && echo \"gpu.$f=$(cat \"/sys/class/kgsl/kgsl-3d0/$f\" 2>/dev/null)\"\n");
        s.push_str("done\n");
        s.push_str("echo '---thermal---'\n");
        s.push_str("for z in /sys/class/thermal/thermal_zone*; do\n");
        s.push_str("  [ -r \"$z/temp\" ] && [ -r \"$z/type\" ] || continue\n");
        s.push_str("  t=$(cat \"$z/temp\" 2>/dev/null)\n");
        s.push_str("  [ -n \"$t\" ] && echo \"$(cat \"$z/type\" 2>/dev/null)|$t\"\n");
        s.push_str("done\n");
    }

    if opts.wants("sys") {
        s.push_str("echo '@@SEC:SYS@@'\n");
        s.push_str("echo '---meminfo---'\n");
        s.push_str("grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null\n");
        s.push_str("echo '---psi---'\n");
        s.push_str("for p in cpu memory io; do\n");
        s.push_str("  [ -r \"/proc/pressure/$p\" ] && sed \"s/^/$p:/\" \"/proc/pressure/$p\" 2>/dev/null\n");
        s.push_str("done\n");
        s.push_str("echo '---df---'\n");
        s.push_str("df -h /data /vendor /odm 2>/dev/null || true\n");
        s.push_str("echo '---net---'\n");
        s.push_str("ip -br addr 2>/dev/null || true\n");
    }

    if opts.wants("logs") {
        s.push_str("echo '@@SEC:LOGCAT_ERR@@'\n");
        s.push_str("logcat -d -b main -b system -t 600 *:E 2>/dev/null || true\n");
        s.push_str("echo '@@SEC:LOGCAT_RECENT@@'\n");
        s.push_str("logcat -d -b main -b system -v threadtime -t 2500 2>/dev/null || true\n");
        if !opts.wants("services") {
            s.push_str("echo '@@SEC:PS@@'\n");
            s.push_str("ps -A -o PID,USER,NAME,ARGS 2>/dev/null\n");
        }
    }

    s.push_str("echo '@@SEC:END@@'\n");
    s
}

pub(crate) fn run_adb_probe(ctx: &Ctx, serial: &str, script: &str) -> Result<String, String> {
    // Wrap so non-root adb shells auto-escalate via `su -c sh` when available, while root shells run `sh` directly.
    let wrapper = "if [ \"$(id -u)\" = 0 ]; then sh; elif command -v su >/dev/null 2>&1 && su -c true 2>/dev/null; then su -c sh; else sh; fi";
    let (rc, out, err) = run_cmd(
        "adb",
        &["-s", serial, "shell", wrapper],
        &ctx.ws_root,
        Some(script.as_bytes()),
    );
    if rc != 0 && !out.contains("@@SEC:META@@") {
        return Err(format!("adb shell probe failed (rc={rc}): {}", err.trim()));
    }
    Ok(out)
}

// ====================================================== Parsers

pub(crate) fn parse_sections(raw: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    let mut cur: Option<String> = None;
    let mut buf = String::new();
    for line in raw.lines() {
        let ln = line.trim_end_matches('\r');
        if let Some(rest) = ln.strip_prefix("@@SEC:") {
            if let Some(name) = rest.strip_suffix("@@") {
                if let Some(prev) = cur.take() {
                    map.insert(prev, std::mem::take(&mut buf));
                }
                if name != "END" {
                    cur = Some(name.to_string());
                }
                continue;
            }
        }
        if cur.is_some() {
            buf.push_str(ln);
            buf.push('\n');
        }
    }
    if let Some(prev) = cur {
        map.insert(prev, buf);
    }
    map
}

pub(crate) fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for ln in text.lines() {
        if let Some((k, v)) = ln.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

pub(crate) fn parse_getprop(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for ln in text.lines() {
        let t = ln.trim();
        if let Some(rest) = t.strip_prefix('[') {
            if let Some((k, v_raw)) = rest.split_once("]: [") {
                if let Some(v) = v_raw.strip_suffix(']') {
                    map.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    map
}

pub fn decode_taint(taint_val: u64) -> (Vec<&'static str>, u64) {
    let mut flags = Vec::new();
    for (bit, name) in [
        (0, "PROPRIETARY"),
        (1, "FORCED_MODULE"),
        (2, "CPU_OUT_OF_SPEC"),
        (3, "FORCED_RMMOD"),
        (4, "MACHINE_CHECK"),
        (5, "BAD_PAGE"),
        (6, "USER"),
        (7, "DIE"),
        (8, "OVERRIDDEN_ACPI"),
        (9, "WARN"),
        (10, "CRAP"),
        (11, "FIRMWARE_WORKAROUND"),
        (12, "OOT"),
        (13, "UNSIGNED"),
        (14, "SOFTLOCKUP"),
        (15, "LIVEPATCH"),
        (16, "AUX"),
        (17, "RANDSTRUCT"),
    ] {
        if (taint_val & (1u64 << bit)) != 0 {
            flags.push(name);
        }
    }
    // Bits 12 (OOT) and 13 (UNSIGNED) are expected for Android vendor_dlkm .ko modules.
    let unexpected = taint_val & !((1u64 << 12) | (1u64 << 13));
    (flags, unexpected)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AvcKey {
    pub(crate) scontext: String,
    pub(crate) tcontext: String,
    pub(crate) tclass: String,
    pub(crate) perms: String,
    pub(crate) target_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AvcBucket {
    SystemHal,
    UntrustedApp,
    SuOrPermissive,
}

#[derive(Clone, Debug)]
pub(crate) struct AvcEntry {
    pub(crate) key: AvcKey,
    pub(crate) bucket: AvcBucket,
    pub(crate) count: usize,
    pub(crate) sample_comm: String,
    pub(crate) sample_app: String,
}

fn extract_context_type(ctx_str: &str) -> String {
    // e.g. u:r:vendor_init:s0 -> vendor_init, u:object_r:sysfs:s0:c512,c768 -> sysfs
    let parts: Vec<&str> = ctx_str.split(':').collect();
    if parts.len() >= 3 {
        parts[2].to_string()
    } else {
        ctx_str.to_string()
    }
}

fn extract_quoted_field(line: &str, key: &str) -> String {
    let needle = format!("{key}=");
    let Some(idx) = line.find(&needle) else { return String::new() };
    let rest = &line[idx + needle.len()..];
    if let Some(after_q) = rest.strip_prefix('"') {
        if let Some(end) = after_q.find('"') {
            return after_q[..end].to_string();
        }
    }
    rest.split_whitespace().next().unwrap_or("").trim_end_matches('\'').to_string()
}

fn parse_avc_line(line: &str) -> Option<(AvcKey, AvcBucket, String, String)> {
    let avc_pos = line.find("avc:  denied")
        .or_else(|| line.find("avc: denied"))?;
    let tail = &line[avc_pos..];
    let lbrace = tail.find('{')?;
    let rbrace = tail[lbrace + 1..].find('}')? + lbrace + 1;
    let perms = tail[lbrace + 1..rbrace].trim().to_string();

    let s_raw = extract_quoted_field(tail, "scontext");
    let t_raw = extract_quoted_field(tail, "tcontext");
    let tclass = extract_quoted_field(tail, "tclass");
    if s_raw.is_empty() || t_raw.is_empty() || tclass.is_empty() {
        return None;
    }
    let scontext = extract_context_type(&s_raw);
    let tcontext = extract_context_type(&t_raw);
    let mut target_name = extract_quoted_field(tail, "name");
    if target_name.is_empty() {
        target_name = extract_quoted_field(tail, "property");
    }
    if target_name.is_empty() {
        target_name = extract_quoted_field(tail, "path");
    }
    let comm = extract_quoted_field(tail, "comm");
    let app = extract_quoted_field(tail, "app");
    let permissive = extract_quoted_field(tail, "permissive") == "1";

    let bucket = if scontext == "su" || scontext == "shell" || permissive {
        AvcBucket::SuOrPermissive
    } else if scontext.starts_with("untrusted_app") || scontext.starts_with("isolated_app") {
        AvcBucket::UntrustedApp
    } else {
        AvcBucket::SystemHal
    };

    Some((
        AvcKey {
            scontext,
            tcontext,
            tclass,
            perms,
            target_name,
        },
        bucket,
        comm,
        app,
    ))
}

pub(crate) fn collect_avcs(dmesg: &str) -> Vec<AvcEntry> {
    let mut grouped: BTreeMap<AvcKey, AvcEntry> = BTreeMap::new();
    for ln in dmesg.lines() {
        if let Some((key, bucket, comm, app)) = parse_avc_line(ln) {
            grouped
                .entry(key.clone())
                .and_modify(|e| {
                    e.count += 1;
                    // Upgrade bucket if any occurrence was enforcing
                    if e.bucket == AvcBucket::SuOrPermissive && bucket != AvcBucket::SuOrPermissive {
                        e.bucket = bucket;
                    }
                })
                .or_insert(AvcEntry {
                    key,
                    bucket,
                    count: 1,
                    sample_comm: comm,
                    sample_app: app,
                });
        }
    }
    let mut out: Vec<AvcEntry> = grouped.into_values().collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

#[derive(Clone, Debug)]
struct TombstoneInfo {
    path: String,
    this_boot: bool,
    executable: String,
    cmdline: String,
    signal: String,
    cause: String,
    uptime: String,
    frames: Vec<String>,
    known_benign: Option<&'static str>,
}

fn parse_tombstone_block(path: &str, mtime: u64, boot_epoch: u64, text: &str) -> TombstoneInfo {
    let mut executable = String::new();
    let mut cmdline = String::new();
    let mut signal = String::new();
    let mut cause = String::new();
    let mut uptime = String::new();
    let mut frames = Vec::new();
    let mut in_bt = false;

    for ln in text.lines() {
        let t = ln.trim();
        if let Some(v) = t.strip_prefix("Executable:") {
            executable = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("Cmdline:") {
            cmdline = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("Process uptime:") {
            uptime = v.trim().to_string();
        } else if t.starts_with("signal ") {
            signal = t.to_string();
        } else if let Some(v) = t.strip_prefix("Cause:") {
            cause = v.trim().to_string();
        } else if t == "backtrace:" {
            in_bt = true;
        } else if in_bt && t.starts_with('#') {
            if frames.len() < 5 {
                frames.push(t.to_string());
            }
        } else if in_bt && !t.is_empty() && !t.starts_with('#') {
            in_bt = false;
        }
    }

    // Known benign one-shot exit destructor race in QCOM /vendor/bin/nv_mac blob
    let all_frames = frames.join(" ");
    let known_benign = if (executable == "/vendor/bin/nv_mac" || cmdline.contains("/vendor/bin/nv_mac"))
        && (all_frames.contains("__cxa_finalize") || all_frames.contains("ThreadPoolManager::~ThreadPoolManager"))
    {
        Some("known benign QCOM nv_mac one-shot exit destructor race")
    } else {
        None
    };

    TombstoneInfo {
        path: path.to_string(),
        this_boot: boot_epoch > 0 && mtime + 15 >= boot_epoch,
        executable,
        cmdline,
        signal,
        cause,
        uptime,
        frames,
        known_benign,
    }
}

fn parse_tombstones(head_sec: &str, boot_epoch: u64) -> Vec<TombstoneInfo> {
    let mut out = Vec::new();
    let mut cur_path = String::new();
    let mut cur_mtime = 0u64;
    let mut buf = String::new();

    for ln in head_sec.lines() {
        if let Some(rest) = ln.strip_prefix("@@TOMB:") {
            if let Some(inner) = rest.strip_suffix("@@") {
                if !cur_path.is_empty() {
                    out.push(parse_tombstone_block(&cur_path, cur_mtime, boot_epoch, &buf));
                    buf.clear();
                }
                if let Some((p, mt)) = inner.rsplit_once(':') {
                    cur_path = p.to_string();
                    cur_mtime = mt.parse().unwrap_or(0);
                }
                continue;
            }
        }
        buf.push_str(ln);
        buf.push('\n');
    }
    if !cur_path.is_empty() {
        out.push(parse_tombstone_block(&cur_path, cur_mtime, boot_epoch, &buf));
    }
    out
}

/// Normalize a `logcat -b main -b system *:E` line into `(tag, normalized_message)` for grouping.
fn normalize_logcat_error(line: &str) -> Option<(String, String)> {
    // Threadtime format: "11-22 11:05:25.436  2214  2214 E TagName : message"
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 6 {
        return None;
    }
    if toks[4] != "E" && toks[4] != "F" {
        return None;
    }
    // Find level token position in original line
    let level_needle = format!(" {} ", toks[4]);
    let idx = line.find(&level_needle)?;
    let after = &line[idx + level_needle.len()..];
    let (tag, msg) = after.split_once(':')?;
    let tag = tag.trim().to_string();
    let mut norm = String::with_capacity(msg.len().min(120));
    let bytes = msg.trim().as_bytes();
    let mut i = 0;
    while i < bytes.len() && norm.len() < 110 {
        if bytes[i] == b'0' && i + 2 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            norm.push_str("0x*");
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
        } else if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i - start >= 3 {
                norm.push('#');
            } else {
                norm.push_str(&msg.trim()[start..i]);
            }
        } else {
            norm.push(bytes[i] as char);
            i += 1;
        }
    }
    Some((tag, norm.trim().to_string()))
}

fn parse_thp_values(thp_text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    // file_basename -> (key -> val)
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for ln in thp_text.lines() {
        // /odm/firmware/o10u_nova_csot_thp_config.ini:320:    game_long_side_for_horizon=20
        let parts: Vec<&str> = ln.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let fname = parts[0].rsplit('/').next().unwrap_or(parts[0]).to_string();
        if let Some((k, v)) = parts[2].trim().split_once('=') {
            out.entry(fname)
                .or_default()
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn split_sub_blocks(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cur = String::from("_root");
    let mut buf = String::new();
    for ln in text.lines() {
        if let Some(rest) = ln.strip_prefix("---") {
            if let Some(name) = rest.strip_suffix("---") {
                if !name.is_empty() && !name.contains(' ') {
                    map.insert(cur, std::mem::take(&mut buf));
                    cur = name.to_string();
                    continue;
                }
            }
        }
        buf.push_str(ln);
        buf.push('\n');
    }
    map.insert(cur, buf);
    map
}

// ====================================================== Main `ktool health`

pub fn cmd_health(ctx: &Ctx, opts: &HealthOpts) -> i32 {
    let dev = match select_adb_device(ctx, opts.serial.as_deref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("!! ktool health: {e}");
            return 1;
        }
    };

    let script = build_probe_script(opts);
    let raw = match run_adb_probe(ctx, &dev.serial, &script) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("!! ktool health: {e}");
            return 1;
        }
    };

    let secs = parse_sections(&raw);
    let meta = parse_kv(secs.get("META").map(|s| s.as_str()).unwrap_or(""));
    let props = parse_getprop(secs.get("PROPS").map(|s| s.as_str()).unwrap_or(""));

    let uid = meta.get("uid").map(|s| s.as_str()).unwrap_or("?");
    let now_epoch: u64 = meta.get("epoch").and_then(|s| s.parse().ok()).unwrap_or(0);
    let uptime_f: f64 = meta.get("uptime_s").and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let boot_epoch = now_epoch.saturating_sub(uptime_f as u64);
    let selinux = meta.get("selinux").map(|s| s.as_str()).unwrap_or("?");
    let uname = meta.get("uname").map(|s| s.as_str()).unwrap_or("");
    let uptime_str = meta.get("uptime_str").map(|s| s.as_str()).unwrap_or("");

    let mut gates: Vec<GateRow> = Vec::new();
    let mut json_details: Vec<(String, String)> = Vec::new();

    if !opts.json {
        println!("========================================================================");
        println!("ktool health: live ADB device audit [{}] ({})", dev.serial, dev.meta);
        println!("========================================================================");
    }

    // ---------------------------------------- [1] IDENTITY & BUILD
    if opts.wants("id") {
        let boot_done = props.get("sys.boot_completed").map(|s| s.as_str()).unwrap_or("?");
        let device = props.get("ro.product.device").map(|s| s.as_str()).unwrap_or("?");
        let model = props.get("ro.product.model").map(|s| s.as_str()).unwrap_or("?");
        let rel = props.get("ro.build.version.release").map(|s| s.as_str()).unwrap_or("?");
        let btype = props.get("ro.build.type").map(|s| s.as_str()).unwrap_or("?");
        let bdate = props.get("ro.build.date").map(|s| s.as_str()).unwrap_or("?");
        let disp = props.get("ro.build.display.id").map(|s| s.as_str()).unwrap_or("?");
        let fp = props.get("ro.build.fingerprint").map(|s| s.as_str()).unwrap_or("?");
        let patch = props.get("ro.build.version.security_patch").map(|s| s.as_str()).unwrap_or("?");
        let slot = props.get("ro.boot.slot_suffix").map(|s| s.as_str()).unwrap_or("none");
        let lineage_ver = props.get("ro.lineage.version").cloned().unwrap_or_default();

        if !opts.json {
            println!("\n[1] Identity & Build:");
            println!("  device   : {device} ({model}) | Android {rel} ({btype}) | slot {slot} | root={}", if uid == "0" { "yes" } else { "no" });
            println!("  build    : {disp} | date: {bdate} | patch: {patch}");
            println!("  fp       : {fp}");
            println!("  boot     : completed={boot_done} | SELinux={selinux} | {uptime_str}");
            if !lineage_ver.is_empty() {
                println!("  note     : ro.lineage.version={lineage_ver}");
            }
        }
        let st = if boot_done != "1" {
            GateStatus::Fail
        } else if selinux != "Enforcing" {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "identity",
            status: st,
            summary: format!("{device} A{rel} slot={slot} boot={boot_done} SELinux={selinux}"),
        });
        json_details.push((
            "identity".into(),
            format!(
                "{{\"serial\":{},\"device\":{},\"android\":{},\"slot\":{},\"boot_completed\":{},\"selinux\":{},\"build_date\":{},\"display_id\":{},\"security_patch\":{},\"root\":{}}}",
                json_escape(&dev.serial),
                json_escape(device),
                json_escape(rel),
                json_escape(slot),
                json_escape(boot_done),
                json_escape(selinux),
                json_escape(bdate),
                json_escape(disp),
                json_escape(patch),
                if uid == "0" { "true" } else { "false" }
            ),
        ));
    }

    // ---------------------------------------- [2] KERNEL & DMESG
    let dmesg = secs.get("DMESG").map(|s| s.as_str()).unwrap_or("");
    if opts.wants("kernel") {
        let kmeta = parse_kv(secs.get("KERNEL").map(|s| s.as_str()).unwrap_or(""));
        let taint_val: u64 = kmeta.get("tainted").and_then(|s| s.parse().ok()).unwrap_or(0);
        let (taint_flags, unexpected_taint) = decode_taint(taint_val);

        let lsmod = secs.get("LSMOD").map(|s| s.as_str()).unwrap_or("");
        let mod_cnt = lsmod.lines().count().saturating_sub(1);

        let head_short = git(ctx, &["rev-parse", "--short=12", "HEAD"]).trim().to_string();
        let mk_ver = crate::boot::read_makefile_version(&ctx.repo).unwrap_or_default();
        let uname_ok = (mk_ver.is_empty() || uname.contains(&mk_ver))
            && (head_short.is_empty() || uname.contains(&head_short[..7.min(head_short.len())]));

        // Check critical SM8735 module groups loaded
        let mut missing_mods = Vec::new();
        if mod_cnt > 0 {
            for (grp, pats) in [
                ("display", &["msm_drm", "mi_disp"][..]),
                ("GPU", &["msm_kgsl"][..]),
                ("WLAN", &["qca_cld3", "icnss2", "cnss2"][..]),
                ("touch", &["xiaomi_touch", "nt36532", "goodix"][..]),
                ("charging", &["mca_", "pmic_glink"][..]),
            ] {
                if !pats.iter().any(|p| lsmod.contains(p)) {
                    missing_mods.push(grp);
                }
            }
        }

        let mut critical = Vec::new();
        let mut probe_fails = Vec::new();
        let mut subsys_errs = Vec::new();
        for ln in dmesg.lines() {
            let low = ln.to_ascii_lowercase();
            if ln.contains("BUG:")
                || ln.contains("Kernel panic")
                || ln.contains("Unable to handle kernel")
                || ln.contains("Internal error:")
                || ln.contains("Call Trace:")
                || ln.contains("KASAN:")
                || ln.contains("UBSAN:")
                || ln.contains("WARNING: CPU:")
                || ln.contains("vma_pad_pages")
                || ln.contains("invalid pad vma")
            {
                critical.push(truncate_str(ln.trim(), 120).to_string());
            } else if low.contains("probe with driver") && low.contains("failed with error") {
                probe_fails.push(truncate_str(ln.trim(), 120).to_string());
            } else if (low.contains("tsens")
                || low.contains("ufshcd")
                || low.contains("glink")
                || low.contains("qrtr")
                || low.contains("kgsl")
                || low.contains("mi_disp")
                || low.contains("icnss")
                || low.contains("mca_")
                || low.contains("xiaomi_touch")
                || low.contains("nt36xxx"))
                && (low.contains("error") || low.contains("failed") || low.contains("timeout"))
            {
                subsys_errs.push(truncate_str(ln.trim(), 120).to_string());
            }
        }
        let deferred: Vec<&str> = secs
            .get("DEFERRED")
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();

        if !opts.json {
            println!("\n[2] Kernel & Modules:");
            println!("  uname    : {uname}");
            if !uname_ok {
                println!("  !! WARN  : running kernel does not match local HEAD ({mk_ver} / {head_short})");
            }
            println!(
                "  tainted  : {taint_val} ({}) | lsmod: {mod_cnt} modules | dmesg: {} lines",
                if taint_flags.is_empty() { "clean".into() } else { taint_flags.join("+") },
                dmesg.lines().count()
            );
            if !missing_mods.is_empty() {
                println!("  !! MISSING CRITICAL MODULE GROUPS: {}", missing_mods.join(", "));
            }
            if critical.is_empty() {
                println!("  splats   : 0 panics / BUG / WARNING / KASAN / vma_pad_pages");
            } else {
                println!("  !! CRITICAL SPLATS ({}):", critical.len());
                for c in critical.iter().take(if opts.full { 30 } else { 10 }) {
                    println!("     {c}");
                }
            }
            if !probe_fails.is_empty() {
                println!("  WARN probe failures ({}):", probe_fails.len());
                for p in probe_fails.iter().take(10) {
                    println!("     {p}");
                }
            }
            if !deferred.is_empty() {
                println!("  deferred : {} probe(s) ({})", deferred.len(), deferred.iter().take(4).copied().collect::<Vec<_>>().join(", "));
            }
            if opts.full && !subsys_errs.is_empty() {
                println!("  INFO subsystem error/timeout lines ({}):", subsys_errs.len());
                for e in subsys_errs.iter().take(15) {
                    println!("     {e}");
                }
            } else if !subsys_errs.is_empty() {
                println!("  subsys   : {} INFO error/timeout lines (use --full to expand)", subsys_errs.len());
            }
        }

        let st = if !critical.is_empty() || unexpected_taint != 0 || !missing_mods.is_empty() {
            GateStatus::Fail
        } else if !uname_ok || !probe_fails.is_empty() {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "kernel",
            status: st,
            summary: format!(
                "{mod_cnt} mods, taint={taint_val}, {} splats, {} probe-fails, {} deferred",
                critical.len(),
                probe_fails.len(),
                deferred.len()
            ),
        });
        json_details.push((
            "kernel".into(),
            format!(
                "{{\"uname\":{},\"matches_head\":{},\"tainted\":{},\"unexpected_taint\":{},\"lsmod\":{},\"critical_splats\":{},\"probe_fails\":{},\"subsys_info\":{},\"deferred\":{}}}",
                json_escape(uname),
                uname_ok,
                taint_val,
                unexpected_taint,
                mod_cnt,
                critical.len(),
                probe_fails.len(),
                subsys_errs.len(),
                deferred.len()
            ),
        ));
    }

    // ---------------------------------------- [3] CORE SERVICES & HALS
    if opts.wants("services") {
        let mut restarting = Vec::new();
        for (k, v) in &props {
            if let Some(svc) = k.strip_prefix("init.svc.") {
                if v == "restarting" {
                    restarting.push(svc.to_string());
                }
            }
        }

        // Essential service checks: (label, required, candidate init.svc.* names)
        let checks: &[(&str, bool, &[&str])] = &[
            ("surfaceflinger", true, &["surfaceflinger"]),
            ("zygote", true, &["zygote"]),
            ("netd", true, &["netd"]),
            ("audioserver", true, &["audioserver"]),
            ("cameraserver", true, &["cameraserver"]),
            ("display-composer", true, &["vendor.qti.hardware.display.composer"]),
            ("display-feature", false, &["vendor.displayfeatureaidl-hal", "displayfeature"]),
            ("audio-hal", true, &["vendor.audio-hal-aidl", "vendor.audio-hal"]),
            ("camera-hal", true, &["vendor.camera-provider"]),
            ("bluetooth-hal", false, &["vendor.bluetooth-aidl-qti", "vendor.bluetooth-1-1"]),
            ("wifi-hal", false, &["vendor.wifi_hal_legacy", "vendor.wifi_hal"]),
            ("ril", false, &["vendor.qcrild"]),
            ("sensors-hal", true, &["vendor.sensors-hal-multihal", "vendor.sensors"]),
            ("thermal-hal", true, &["vendor.thermal-hal"]),
            ("mi_thermal", false, &["mi_thermal_engine"]),
            ("touchfeature", true, &["touchfeature-service"]),
            ("yasvara_sessiond", false, &["yasvara_sessiond"]),
        ];

        let mut running_ok = 0usize;
        let mut down_req = Vec::new();
        let mut down_opt = Vec::new();
        for &(label, req, names) in checks {
            let is_up = names
                .iter()
                .any(|n| props.get(&format!("init.svc.{n}")).is_some_and(|v| v == "running"));
            if is_up {
                running_ok += 1;
            } else if req {
                down_req.push(label);
            } else {
                down_opt.push(label);
            }
        }

        let ps_text = secs.get("PS").map(|s| s.as_str()).unwrap_or("");
        let pentas_running = ps_text.contains("org.yasvara.pentas");
        let pentas_dump = secs.get("PENTAS").map(|s| s.as_str()).unwrap_or("").trim();
        let pentas_top = pentas_dump
            .lines()
            .find(|l| l.trim().starts_with("top:"))
            .map(|l| l.trim())
            .unwrap_or("");
        let pentas_modes = pentas_dump
            .lines()
            .find(|l| l.trim().starts_with("cached modes:"))
            .map(|l| l.trim())
            .unwrap_or("");

        if !opts.json {
            println!("\n[3] Services & HALs:");
            println!("  core+HAL : {running_ok}/{} running | restart-loops: {}", checks.len(), restarting.len());
            if !restarting.is_empty() {
                println!("  !! RESTART-LOOPING SERVICES: {}", restarting.join(", "));
            }
            if !down_req.is_empty() {
                println!("  !! REQUIRED SERVICES NOT RUNNING: {}", down_req.join(", "));
            }
            if !down_opt.is_empty() {
                println!("  INFO optional stopped: {}", down_opt.join(", "));
            }
            println!(
                "  yasvara  : pentas_proc={} | {}",
                if pentas_running { "running" } else { "not-started" },
                if !pentas_top.is_empty() {
                    format!("{pentas_top}, {pentas_modes}")
                } else {
                    "dumpsys unavailable".into()
                }
            );
        }

        let st = if !restarting.is_empty() || !down_req.is_empty() {
            GateStatus::Fail
        } else if !down_opt.is_empty() {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "services",
            status: st,
            summary: format!("{running_ok}/{} up, {} restart-loops, {} req-down", checks.len(), restarting.len(), down_req.len()),
        });
        json_details.push((
            "services".into(),
            format!(
                "{{\"running\":{},\"total\":{},\"restart_loops\":{},\"required_down\":{},\"optional_down\":{},\"pentas_running\":{}}}",
                running_ok,
                checks.len(),
                restarting.len(),
                down_req.len(),
                down_opt.len(),
                pentas_running
            ),
        ));
    }

    // ---------------------------------------- [4] CRASHES, TOMBSTONES & ANRS
    if opts.wants("crashes") {
        let tomb_list = secs.get("TOMBSTONES_LIST").map(|s| s.as_str()).unwrap_or("");
        let total_tombs = tomb_list.lines().filter(|l| !l.trim().is_empty()).count();
        let anr_list = secs.get("ANR_LIST").map(|s| s.as_str()).unwrap_or("");
        let mut anr_this_boot = Vec::new();
        for ln in anr_list.lines() {
            let p: Vec<&str> = ln.splitn(3, ' ').collect();
            if p.len() == 3 {
                let mt: u64 = p[0].parse().unwrap_or(0);
                if boot_epoch > 0 && mt + 15 >= boot_epoch {
                    anr_this_boot.push(p[2].to_string());
                }
            }
        }

        let tombs = parse_tombstones(
            secs.get("TOMBSTONES_HEAD").map(|s| s.as_str()).unwrap_or(""),
            boot_epoch,
        );
        let this_boot_tombs: Vec<&TombstoneInfo> = tombs.iter().filter(|t| t.this_boot).collect();
        let real_tombs: Vec<&TombstoneInfo> = this_boot_tombs
            .iter()
            .copied()
            .filter(|t| t.known_benign.is_none())
            .collect();
        let benign_tombs: Vec<&TombstoneInfo> = this_boot_tombs
            .iter()
            .copied()
            .filter(|t| t.known_benign.is_some())
            .collect();

        let crash_log = secs.get("LOGCAT_CRASH").map(|s| s.as_str()).unwrap_or("");
        let java_fatals: Vec<&str> = crash_log
            .lines()
            .filter(|l| l.contains("FATAL EXCEPTION") || l.contains("Process: "))
            .collect();

        if !opts.json {
            println!("\n[4] Crashes, Tombstones & ANRs (boot-scoped):");
            println!(
                "  summary  : {} real / {} known-benign tombstones THIS BOOT ({} older stored) | {} ANRs THIS BOOT | {} Java fatal lines",
                real_tombs.len(),
                benign_tombs.len(),
                total_tombs.saturating_sub(this_boot_tombs.len()),
                anr_this_boot.len(),
                java_fatals.len()
            );
            for t in &real_tombs {
                println!(
                    "  !! CRASH : {} | exe={} (uptime {}) | {}",
                    t.path.rsplit('/').next().unwrap_or(&t.path),
                    if t.executable.is_empty() { &t.cmdline } else { &t.executable },
                    t.uptime,
                    t.signal
                );
                if !t.cause.is_empty() {
                    println!("     cause : {}", t.cause);
                }
                for f in t.frames.iter().take(3) {
                    println!("     bt    : {}", truncate_str(f, 110));
                }
            }
            for t in &benign_tombs {
                println!(
                    "  INFO     : {} | {} ({})",
                    t.path.rsplit('/').next().unwrap_or(&t.path),
                    t.executable,
                    t.known_benign.unwrap_or("known")
                );
            }
            for a in &anr_this_boot {
                println!("  !! ANR   : {a}");
            }
            for jf in java_fatals.iter().take(6) {
                println!("  !! JAVA  : {}", truncate_str(jf.trim(), 115));
            }
        }

        let st = if !real_tombs.is_empty() || !anr_this_boot.is_empty() || !java_fatals.is_empty() {
            GateStatus::Fail
        } else if !benign_tombs.is_empty() {
            GateStatus::Pass
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "crashes",
            status: st,
            summary: format!(
                "{} real crashes ({} known-benign), {} ANRs, {} Java fatals this boot",
                real_tombs.len(),
                benign_tombs.len(),
                anr_this_boot.len(),
                java_fatals.len()
            ),
        });
        json_details.push((
            "crashes".into(),
            format!(
                "{{\"real_tombstones\":{},\"benign_tombstones\":{},\"anrs_this_boot\":{},\"java_fatals\":{}}}",
                real_tombs.len(),
                benign_tombs.len(),
                anr_this_boot.len(),
                java_fatals.len()
            ),
        ));
    }

    // ---------------------------------------- [5] SELINUX AVC DENIALS
    if opts.wants("avc") {
        let avcs = collect_avcs(dmesg);
        let sys_avcs: Vec<&AvcEntry> = avcs.iter().filter(|a| a.bucket == AvcBucket::SystemHal).collect();
        let app_avcs: Vec<&AvcEntry> = avcs.iter().filter(|a| a.bucket == AvcBucket::UntrustedApp).collect();
        let su_avcs: Vec<&AvcEntry> = avcs.iter().filter(|a| a.bucket == AvcBucket::SuOrPermissive).collect();

        let sys_hits: usize = sys_avcs.iter().map(|a| a.count).sum();
        let app_hits: usize = app_avcs.iter().map(|a| a.count).sum();
        let su_hits: usize = su_avcs.iter().map(|a| a.count).sum();

        if !opts.json {
            println!("\n[5] SELinux AVC Denials (deduplicated):");
            println!(
                "  totals   : SYSTEM/HAL={} unique ({} hits) | untrusted_app={} unique ({} hits, blocked as expected) | su/early-perm={} unique ({} hits)",
                sys_avcs.len(), sys_hits, app_avcs.len(), app_hits, su_avcs.len(), su_hits
            );
            for a in sys_avcs.iter().take(if opts.full || opts.dump_avc { 50 } else { 10 }) {
                let extra = if !a.key.target_name.is_empty() {
                    format!(" name={}", a.key.target_name)
                } else {
                    String::new()
                };
                println!(
                    "  [x{:<3}] {} -> {}:{} {{ {} }}{} (comm={})",
                    a.count, a.key.scontext, a.key.tcontext, a.key.tclass, a.key.perms, extra, a.sample_comm
                );
            }
            if opts.dump_avc && !sys_avcs.is_empty() {
                println!("  --- suggested allow rules (review before applying) ---");
                let mut rules: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
                for a in &sys_avcs {
                    let entry = rules
                        .entry((a.key.scontext.clone(), a.key.tcontext.clone(), a.key.tclass.clone()))
                        .or_default();
                    for p in a.key.perms.split_whitespace() {
                        entry.insert(p.to_string());
                    }
                }
                for ((sc, tc, cl), perms) in rules {
                    let plist: Vec<String> = perms.into_iter().collect();
                    let pstr = if plist.len() == 1 {
                        plist[0].clone()
                    } else {
                        format!("{{ {} }}", plist.join(" "))
                    };
                    println!("  allow {sc} {tc}:{cl} {pstr};");
                }
            }
            if (opts.full || opts.dump_avc) && !app_avcs.is_empty() {
                println!("  --- untrusted_app (expected Enforcing blocks) ---");
                for a in app_avcs.iter().take(10) {
                    println!(
                        "  [x{:<3}] {} ({}) -> {}:{} {{ {} }} name={}",
                        a.count, a.key.scontext, a.sample_app, a.key.tcontext, a.key.tclass, a.key.perms, a.key.target_name
                    );
                }
            }
        }

        let st = if !sys_avcs.is_empty() {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "selinux",
            status: st,
            summary: format!("{} actionable SYSTEM/HAL denials ({} hits); {} app blocks", sys_avcs.len(), sys_hits, app_hits),
        });
        json_details.push((
            "selinux".into(),
            format!(
                "{{\"system_hal_unique\":{},\"system_hal_hits\":{},\"untrusted_app_unique\":{},\"untrusted_app_hits\":{},\"su_perm_unique\":{}}}",
                sys_avcs.len(),
                sys_hits,
                app_avcs.len(),
                app_hits,
                su_avcs.len()
            ),
        ));
    }

    // ---------------------------------------- [6] TOUCH, THP & DISPLAY
    if opts.wants("touch") {
        let tb = split_sub_blocks(secs.get("TOUCH").map(|s| s.as_str()).unwrap_or(""));
        let thp_mounts: Vec<&str> = tb
            .get("mounts")
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let thp_map = parse_thp_values(tb.get("thp_ini").map(|s| s.as_str()).unwrap_or(""));
        let tsys = parse_kv(tb.get("touch_sysfs").map(|s| s.as_str()).unwrap_or(""));
        let input_devs = tb.get("input_devs").map(|s| s.as_str()).unwrap_or("");
        let has_nvt = input_devs.contains("NVTCapacitiveTouchScreen");
        let has_uinput_mi = input_devs.contains("uinput-xiaomi");

        let waterproof = props
            .get("persist.vendor.hostprocess.waterproof")
            .map(|s| s.as_str())
            .unwrap_or("unset");
        let gtt_ver = props
            .get("persist.vendor.touchfeature.gameturbotool.version")
            .map(|s| s.as_str())
            .unwrap_or("unset");

        let disp_raw = tb.get("display").map(|s| s.as_str()).unwrap_or("");
        let disp_state = disp_raw
            .lines()
            .find_map(|l| l.trim().strip_prefix("mCommittedState="))
            .unwrap_or("?");
        let disp_fps = disp_raw
            .lines()
            .find_map(|l| {
                let idx = l.find("renderFrameRate ")?;
                let rest = &l[idx + "renderFrameRate ".len()..];
                let num = rest.split(',').next()?.trim();
                num.parse::<f64>().ok().map(|f| format!("{f:.0}Hz"))
            })
            .unwrap_or_else(|| "?".into());

        if !opts.json {
            println!("\n[6] Touch, THP & Display:");
            println!(
                "  input    : NVTCapacitiveTouchScreen={} | uinput-xiaomi={} | touch_active={}",
                if has_nvt { "OK" } else { "MISSING" },
                if has_uinput_mi { "OK" } else { "MISSING" },
                tsys.get("touch_active").filter(|s| !s.is_empty()).map(|s| s.as_str()).unwrap_or("n/a")
            );
            println!(
                "  THP      : bind-mounts={} | waterproof={waterproof} | gameturbo={gtt_ver}",
                if thp_mounts.is_empty() { "0 (native odm)".into() } else { format!("{} ACTIVE!", thp_mounts.len()) }
            );
            for (fname, kv) in &thp_map {
                let l = kv.get("game_long_side_for_horizon").map(|s| s.as_str()).unwrap_or("?");
                let sh = kv.get("game_short_size_for_horizon").map(|s| s.as_str()).unwrap_or("?");
                let c = kv.get("game_new_corner_size").map(|s| s.as_str()).unwrap_or("?");
                println!("  cfg      : {fname} -> long={l} short={sh} corner={c} px");
            }
            println!("  display  : state={disp_state} | renderFrameRate={disp_fps}");
        }

        let st = if !has_nvt {
            GateStatus::Fail
        } else if !thp_mounts.is_empty() || waterproof == "true" {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "touch+disp",
            status: st,
            summary: format!(
                "NVT={} uinput={} bind-mounts={} waterproof={waterproof} disp={disp_state}@{disp_fps}",
                if has_nvt { "ok" } else { "MISS" },
                if has_uinput_mi { "ok" } else { "MISS" },
                thp_mounts.len()
            ),
        });
        json_details.push((
            "touch".into(),
            format!(
                "{{\"nvt_touch\":{},\"uinput_xiaomi\":{},\"thp_bind_mounts\":{},\"waterproof\":{},\"display_state\":{},\"display_fps\":{}}}",
                has_nvt,
                has_uinput_mi,
                thp_mounts.len(),
                json_escape(waterproof),
                json_escape(disp_state),
                json_escape(&disp_fps)
            ),
        ));
    }

    // ---------------------------------------- [7] POWER, CPU, GPU & THERMALS
    if opts.wants("power") {
        let pb = split_sub_blocks(secs.get("POWER").map(|s| s.as_str()).unwrap_or(""));
        let pkv = parse_kv(pb.get("_root").map(|s| s.as_str()).unwrap_or(""));
        let bat_status = pkv.get("bat.status").map(|s| s.as_str()).unwrap_or("?");
        let bat_cap = pkv.get("bat.capacity").map(|s| s.as_str()).unwrap_or("?");
        let bat_uv: f64 = pkv.get("bat.voltage_now").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let bat_ua: f64 = pkv.get("bat.current_now").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let bat_temp_c: f64 = pkv.get("bat.temp").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0) / 10.0;
        let bat_ctype = pkv.get("bat.charge_type").map(|s| s.as_str()).unwrap_or("?");
        let bat_w = (bat_uv / 1_000_000.0) * (bat_ua.abs() / 1_000_000.0);

        let usb_online = pkv.get("usb.online").map(|s| s.as_str()).unwrap_or("0") == "1";
        let usb_type = pkv.get("usb.type").map(|s| s.as_str()).unwrap_or("none");
        let usb_v: f64 = pkv.get("usb.voltage_now").and_then(|s| s.parse().ok()).unwrap_or(0.0) / 1_000_000.0;
        let usb_a: f64 = pkv.get("usb.current_now").and_then(|s| s.parse().ok()).unwrap_or(0.0) / 1_000_000.0;

        let gkv = parse_kv(pb.get("gpu").map(|s| s.as_str()).unwrap_or(""));
        let gpu_mhz = gkv.get("gpu.gpuclk").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) / 1_000_000;
        let gpu_max = gkv.get("gpu.max_gpuclk").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) / 1_000_000;
        let gpu_gov = gkv.get("gpu.devfreq/governor").map(|s| s.as_str()).unwrap_or("?");
        let gpu_temp = gkv.get("gpu.temp").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0) / 1000.0;
        let gpu_busy_pct = gkv
            .get("gpu.gpubusy")
            .and_then(|s| {
                let mut it = s.split_whitespace();
                let busy: f64 = it.next()?.parse().ok()?;
                let total: f64 = it.next()?.parse().ok()?;
                if total > 0.0 { Some((busy / total) * 100.0) } else { Some(0.0) }
            })
            .unwrap_or(0.0);

        let mut zones: Vec<(String, f64)> = Vec::new();
        for ln in pb.get("thermal").map(|s| s.as_str()).unwrap_or("").lines() {
            if let Some((name, raw_t)) = ln.split_once('|') {
                if let Ok(v) = raw_t.trim().parse::<i64>() {
                    // Normalize mC vs C
                    let c = if v.abs() > 1000 { v as f64 / 1000.0 } else { v as f64 };
                    if c > 0.0 && c < 150.0 {
                        zones.push((name.trim().to_string(), c));
                    }
                }
            }
        }
        zones.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let max_soc_c = zones.first().map(|z| z.1).unwrap_or(0.0);

        let mut cpu_summary = Vec::new();
        for ln in pb.get("cpu").map(|s| s.as_str()).unwrap_or("").lines() {
            let p: Vec<&str> = ln.split('|').collect();
            if p.len() == 5 {
                let cur_m = p[3].trim().parse::<u64>().unwrap_or(0) / 1000;
                let max_m = p[4].trim().parse::<u64>().unwrap_or(0) / 1000;
                cpu_summary.push(format!("{}(c{}):{}/{}MHz[{}]", p[0], p[1].trim().replace(' ', ","), cur_m, max_m, p[2].trim()));
            }
        }

        if !opts.json {
            println!("\n[7] Power, CPU/GPU & Thermals:");
            println!(
                "  battery  : {bat_status} {bat_cap}% ({bat_ctype}) | {:.3}V {:+.0}mA ({:.1}W) | {:.1}°C",
                bat_uv / 1_000_000.0,
                bat_ua / 1000.0,
                bat_w,
                bat_temp_c
            );
            if usb_online {
                println!("  usb      : {usb_type} online | {:.2}V {:.2}A ({:.1}W)", usb_v, usb_a, usb_v * usb_a);
            }
            if !cpu_summary.is_empty() {
                println!("  cpu      : {}", cpu_summary.join("  "));
            }
            println!(
                "  gpu      : {gpu_mhz}/{gpu_max} MHz ({gpu_busy_pct:.1}% busy) [{gpu_gov}] | {:.1}°C",
                gpu_temp
            );
            if !zones.is_empty() {
                let top_z: Vec<String> = zones
                    .iter()
                    .take(6)
                    .map(|(n, c)| format!("{n}={c:.1}°C"))
                    .collect();
                println!("  thermals : hottest: {}", top_z.join(", "));
            }
        }

        let st = if bat_temp_c >= 45.0 || max_soc_c >= 75.0 {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "power+thm",
            status: st,
            summary: format!("bat={bat_cap}%({bat_status}) {bat_temp_c:.1}°C | SoC peak {max_soc_c:.1}°C | GPU {gpu_mhz}MHz({gpu_busy_pct:.0}%)"),
        });
        json_details.push((
            "power".into(),
            format!(
                "{{\"bat_status\":{},\"bat_pct\":{},\"bat_temp_c\":{:.1},\"soc_peak_c\":{:.1},\"gpu_mhz\":{},\"gpu_busy_pct\":{:.1}}}",
                json_escape(bat_status),
                bat_cap.parse::<i64>().unwrap_or(-1),
                bat_temp_c,
                max_soc_c,
                gpu_mhz,
                gpu_busy_pct
            ),
        ));
    }

    // ---------------------------------------- [8] MEMORY, PSI, STORAGE & NETWORK
    if opts.wants("sys") {
        let sb = split_sub_blocks(secs.get("SYS").map(|s| s.as_str()).unwrap_or(""));
        let mut mem_kb: HashMap<String, u64> = HashMap::new();
        for ln in sb.get("meminfo").map(|s| s.as_str()).unwrap_or("").lines() {
            if let Some((k, rest)) = ln.split_once(':') {
                if let Some(val) = rest.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()) {
                    mem_kb.insert(k.trim().to_string(), val);
                }
            }
        }
        let mem_tot = *mem_kb.get("MemTotal").unwrap_or(&0);
        let mem_avail = *mem_kb.get("MemAvailable").unwrap_or(&0);
        let mem_pct = if mem_tot > 0 { (mem_avail as f64 / mem_tot as f64) * 100.0 } else { 0.0 };
        let swap_tot = *mem_kb.get("SwapTotal").unwrap_or(&0);
        let swap_free = *mem_kb.get("SwapFree").unwrap_or(&0);

        let mut psi_lines = Vec::new();
        let mut mem_full_avg60 = 0.0f64;
        for ln in sb.get("psi").map(|s| s.as_str()).unwrap_or("").lines() {
            if let Some((kind, rest)) = ln.split_once(':') {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 3 {
                    let level = parts[0];
                    let a10 = parts[1].strip_prefix("avg10=").unwrap_or("0");
                    let a60 = parts[2].strip_prefix("avg60=").unwrap_or("0");
                    if kind == "memory" && level == "full" {
                        mem_full_avg60 = a60.parse().unwrap_or(0.0);
                    }
                    if level == "some" || (kind == "memory" && level == "full") {
                        psi_lines.push(format!("{kind}.{level}={a10}/{a60}"));
                    }
                }
            }
        }

        let mut data_use_pct = 0u64;
        let mut data_df_line = String::new();
        for ln in sb.get("df").map(|s| s.as_str()).unwrap_or("").lines().skip(1) {
            if ln.contains("/data") || ln.contains("/emulated") {
                let p: Vec<&str> = ln.split_whitespace().collect();
                if p.len() >= 5 {
                    data_use_pct = p[4].trim_end_matches('%').parse().unwrap_or(0);
                    data_df_line = format!("used {} / {} ({} free, {}%)", p[2], p[1], p[3], data_use_pct);
                }
            }
        }

        let mut active_ifaces = Vec::new();
        for ln in sb.get("net").map(|s| s.as_str()).unwrap_or("").lines() {
            let p: Vec<&str> = ln.split_whitespace().collect();
            if p.len() >= 3 {
                let name = p[0];
                let state = p[1];
                if state != "DOWN"
                    && !name.starts_with("lo")
                    && !name.starts_with("dummy")
                    && !name.starts_with("r_rmnet")
                    && !name.starts_with("rmnet_ipa")
                {
                    let ip = p[2..].iter().find(|x| !x.starts_with("fe80::")).copied().unwrap_or(p[2]);
                    active_ifaces.push(format!("{name}={ip}"));
                }
            }
        }

        let sim = props.get("gsm.sim.state").map(|s| s.as_str()).unwrap_or("");
        let op = props.get("gsm.operator.alpha").map(|s| s.as_str()).unwrap_or("");
        let rat = props.get("gsm.network.type").map(|s| s.as_str()).unwrap_or("");

        if !opts.json {
            println!("\n[8] Memory, Storage, PSI & Network:");
            println!(
                "  memory   : avail {:.2} / {:.2} GiB ({:.0}% free) | swap used {:.2} / {:.2} GiB",
                mem_avail as f64 / 1048576.0,
                mem_tot as f64 / 1048576.0,
                mem_pct,
                swap_tot.saturating_sub(swap_free) as f64 / 1048576.0,
                swap_tot as f64 / 1048576.0
            );
            if !psi_lines.is_empty() {
                println!("  psi      : {}", psi_lines.join("  "));
            }
            if !data_df_line.is_empty() {
                println!("  storage  : /data {data_df_line}");
            }
            println!(
                "  network  : {} | SIM=[{sim}] op=[{op}] rat=[{rat}]",
                if active_ifaces.is_empty() { "none".into() } else { active_ifaces.join(", ") }
            );
        }

        let st = if (mem_tot > 0 && mem_pct < 12.0) || data_use_pct >= 90 || mem_full_avg60 > 5.0 {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "mem+net",
            status: st,
            summary: format!(
                "RAM {:.1}/{:.1}GiB ({:.0}%) | /data {}% | {} active net",
                mem_avail as f64 / 1048576.0,
                mem_tot as f64 / 1048576.0,
                mem_pct,
                data_use_pct,
                active_ifaces.len()
            ),
        });
        json_details.push((
            "sys".into(),
            format!(
                "{{\"mem_avail_gib\":{:.2},\"mem_total_gib\":{:.2},\"data_use_pct\":{},\"active_ifaces\":{},\"operator\":{},\"rat\":{}}}",
                mem_avail as f64 / 1048576.0,
                mem_tot as f64 / 1048576.0,
                data_use_pct,
                active_ifaces.len(),
                json_escape(op),
                json_escape(rat)
            ),
        ));
    }

    // ---------------------------------------- [9] LOGCAT ERROR DIGEST
    if opts.wants("logs") {
        let lraw = secs.get("LOGCAT_ERR").map(|s| s.as_str()).unwrap_or("");
        let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut total_errs = 0usize;
        for ln in lraw.lines() {
            if let Some(key) = normalize_logcat_error(ln) {
                *counts.entry(key).or_insert(0) += 1;
                total_errs += 1;
            }
        }
        let mut ranked: Vec<((String, String), usize)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top_cnt = ranked.first().map(|x| x.1).unwrap_or(0);

        let recent_raw = secs.get("LOGCAT_RECENT").map(|s| s.as_str()).unwrap_or("");
        let ps_raw = secs.get("PS").map(|s| s.as_str()).unwrap_or("");
        let vendor_noise = crate::lognoise::summarize_vendor_noise_inline(
            recent_raw,
            ps_raw,
            if opts.full { 12 } else { 6 },
        );

        if !opts.json {
            println!("\n[9] Logcat Error Digest (last 600 *:E lines -> {} unique signatures):", ranked.len());
            for ((tag, msg), cnt) in ranked.iter().take(if opts.full { 20 } else { 8 }) {
                println!("  [x{:<3}] {:<24} {}", cnt, truncate_str(tag, 24), truncate_str(msg, 85));
            }
            if !vendor_noise.is_empty() {
                println!("  --- top vendor/prebuilt V/D/I/W log noise (last 2500 lines; run `ktool log-noise` for ELF plan) ---");
                for (cnt, lvl, tag, proc_n, msg) in &vendor_noise {
                    println!(
                        "  [x{:<3} {lvl}] {:<24} ({:<22}) {}",
                        cnt,
                        truncate_str(tag, 24),
                        truncate_str(proc_n, 22),
                        truncate_str(msg, 52)
                    );
                }
            }
        }

        let st = if top_cnt >= 150 {
            GateStatus::Warn
        } else {
            GateStatus::Info
        };
        gates.push(GateRow {
            name: "logcat",
            status: st,
            summary: format!("{total_errs} E/F lines -> {} unique (max repeat x{top_cnt})", ranked.len()),
        });
        json_details.push((
            "logcat".into(),
            format!(
                "{{\"total_errors\":{},\"unique_signatures\":{},\"max_repeat\":{}}}",
                total_errs,
                ranked.len(),
                top_cnt
            ),
        ));
    }

    // ---------------------------------------- VERDICT
    let has_fail = gates.iter().any(|g| g.status == GateStatus::Fail);
    let has_warn = gates.iter().any(|g| g.status == GateStatus::Warn);
    let verdict = if has_fail {
        "UNHEALTHY (FAIL)"
    } else if has_warn {
        "HEALTHY WITH WARNINGS (WARN)"
    } else {
        "HEALTHY (PASS)"
    };

    if opts.json {
        println!("{{");
        println!("  \"verdict\": {},", json_escape(verdict));
        println!("  \"gates\": [");
        for (i, g) in gates.iter().enumerate() {
            let comma = if i + 1 < gates.len() { "," } else { "" };
            println!(
                "    {{\"gate\": {}, \"status\": {}, \"summary\": {}}}{comma}",
                json_escape(g.name),
                json_escape(g.status.as_str()),
                json_escape(&g.summary)
            );
        }
        println!("  ],");
        println!("  \"sections\": {{");
        for (i, (k, v)) in json_details.iter().enumerate() {
            let comma = if i + 1 < json_details.len() { "," } else { "" };
            println!("    {}: {v}{comma}", json_escape(k));
        }
        println!("  }}");
        println!("}}");
    } else {
        println!("\n========================================================================");
        println!("HEALTH VERDICT: {verdict}");
        println!("========================================================================");
        for g in &gates {
            println!("  [{:<4}] {:<11} {}", g.status.as_str(), g.name, g.summary);
        }
    }

    if has_fail { 1 } else { 0 }
}

// ====================================================== Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sections_roundtrip() {
        let raw = "@@SEC:META@@\nuid=0\nselinux=Enforcing\n@@SEC:KERNEL@@\ntainted=12288\n@@SEC:END@@\n";
        let m = parse_sections(raw);
        assert_eq!(m.get("META").unwrap().trim(), "uid=0\nselinux=Enforcing");
        assert_eq!(m.get("KERNEL").unwrap().trim(), "tainted=12288");
        assert!(!m.contains_key("END"));
    }

    #[test]
    fn test_decode_taint_oot_unsigned_clean() {
        let (flags, unexpected) = decode_taint(12288);
        assert_eq!(flags, vec!["OOT", "UNSIGNED"]);
        assert_eq!(unexpected, 0);
        let (flags2, unexp2) = decode_taint(12288 | (1 << 9));
        assert!(flags2.contains(&"WARN"));
        assert_ne!(unexp2, 0);
    }

    #[test]
    fn test_avc_categorization_and_dedup() {
        let sample = "\
[  173.42] type=1400 audit(1:62): avc:  denied  { read } for  comm=\"sps-core\" name=\"serial_number\" scontext=u:r:untrusted_app_34:s0:c184 tcontext=u:object_r:vendor_sysfs_soc_sensitive:s0 tclass=file permissive=0 app=com.shopee.id
[  173.43] type=1400 audit(1:63): avc:  denied  { read } for  comm=\"sps-core\" name=\"serial_number\" scontext=u:r:untrusted_app_34:s0:c184 tcontext=u:object_r:vendor_sysfs_soc_sensitive:s0 tclass=file permissive=0 app=com.shopee.id
[  229.12] type=1400 audit(1:113): avc:  denied  { read } for  comm=\"DefaultDispatch\" name=\"ddr_device_type\" scontext=u:r:system_app:s0 tcontext=u:object_r:vendor_sysfs_ddr:s0 tclass=file permissive=0
[  287.33] type=1400 audit(1:114): avc:  denied  { getattr } for  comm=\"mount\" name=\"/\" scontext=u:r:su:s0 tcontext=u:object_r:firmware_file:s0 tclass=filesystem permissive=1
";
        let avcs = collect_avcs(sample);
        assert_eq!(avcs.len(), 3);
        let shopee = avcs.iter().find(|a| a.key.scontext == "untrusted_app_34").unwrap();
        assert_eq!(shopee.count, 2);
        assert_eq!(shopee.bucket, AvcBucket::UntrustedApp);
        let sys = avcs.iter().find(|a| a.key.scontext == "system_app").unwrap();
        assert_eq!(sys.bucket, AvcBucket::SystemHal);
        let su = avcs.iter().find(|a| a.key.scontext == "su").unwrap();
        assert_eq!(su.bucket, AvcBucket::SuOrPermissive);
    }

    #[test]
    fn test_tombstone_benign_nv_mac() {
        let block = "\
Executable: /vendor/bin/nv_mac
Cmdline: /vendor/bin/nv_mac
Process uptime: 3s
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1b0
Cause: null pointer dereference
backtrace:
      #00 pc 0000d410 /vendor/lib64/libqcrilNrQtiMutex.so
      #03 pc 00030a10 /vendor/lib64/libqcrilNrFramework.so (ThreadPoolManager::~ThreadPoolManager()+36)
      #04 pc 0008cb4c /apex/com.android.runtime/lib64/bionic/libc.so (__cxa_finalize+652)
";
        let info = parse_tombstone_block("/data/tombstones/tombstone_31", 1000, 990, block);
        assert!(info.this_boot);
        assert!(info.known_benign.is_some());
        assert_eq!(info.executable, "/vendor/bin/nv_mac");
        assert_eq!(info.frames.len(), 3);
    }

    #[test]
    fn test_normalize_logcat_error() {
        let a = "11-22 11:05:25.436  2214  2214 E CamX    : [ERROR] frame 12345 failed at 0x7f881a00";
        let b = "11-22 11:05:26.100  2214  2214 E CamX    : [ERROR] frame 99999 failed at 0x7f992b10";
        assert_eq!(normalize_logcat_error(a), normalize_logcat_error(b));
    }

    #[test]
    fn test_parse_thp_values() {
        let sample = "\
/odm/firmware/o10u_nova_csot_thp_config.ini:320:    game_long_side_for_horizon=20
/odm/firmware/o10u_nova_csot_thp_config.ini:321:    game_short_size_for_horizon=20
/odm/firmware/o10u_nova_csot_thp_config.ini:323:    game_new_corner_size=40
";
        let m = parse_thp_values(sample);
        let csot = m.get("o10u_nova_csot_thp_config.ini").unwrap();
        assert_eq!(csot.get("game_long_side_for_horizon").unwrap(), "20");
        assert_eq!(csot.get("game_new_corner_size").unwrap(), "40");
    }
}
