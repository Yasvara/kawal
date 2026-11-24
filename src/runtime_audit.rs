//! Deep live power, memory, FD/DMA-BUF leak, IRQ, wakelock & vendor-daemon forensic audit:
//!   - `ktool runtime-audit [-s <serial>] [--window N] [--only <secs>] [--top N] [--full]`
//!     `                    [--save <file>] [--diff <file>] [--json]`
//!
//! Runs a TWO-PHASE single-shot POSIX `sh` probe over `adb shell`:
//!   - Phase A (zero observer pollution): captures fast single-pass `awk` `/proc/[0-9]*/{status,stat}`
//!     and `/proc/interrupts` snapshots separated by `--window N` quiet seconds BEFORE running any
//!     heavy `dumpsys` or `dmabuf_dump` calls.
//!   - Phase B (deep inspection): captures `/proc/<pid>/{exe,fd}`, FD target breakdowns for top FD
//!     holders, `dmabuf_dump`, `dumpsys meminfo`, `/proc/slabinfo`, ZRAM `mm_stat`, `/sys/class/wakeup`,
//!     `suspend_stats`, CPU0 cpuidle, `dumpsys power`/`deviceidle`, `dumpsys alarm`/`jobscheduler`,
//!     Power HAL ADPF status, active `dmesg` AVCs, and `/sys/kernel/irq/*` + I2C bus topology.
//!
//! Cross-references GICv3 `hwirq - 32` against local `sm8735-devicetrees` to label exact I2C/SPI
//! controllers & attached chips, applies PASS/INFO/WARN/FAIL gates, and supports `--save` / `--diff`
//! snapshots for automated Before-vs-After ROM/kernel verification.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::device::{
    AvcBucket, collect_avcs, json_escape, parse_kv, parse_sections, run_adb_probe,
    select_adb_device, split_sub_blocks,
};
use crate::util::*;

#[derive(Clone, Debug)]
pub struct RuntimeAuditOpts {
    pub serial: Option<String>,
    pub window_s: u64,
    pub only: Option<BTreeSet<String>>,
    pub top: usize,
    pub full: bool,
    pub save: Option<PathBuf>,
    pub diff: Option<PathBuf>,
    pub json: bool,
}

impl Default for RuntimeAuditOpts {
    fn default() -> Self {
        Self {
            serial: None,
            window_s: 5,
            only: None,
            top: 12,
            full: false,
            save: None,
            diff: None,
            json: false,
        }
    }
}

impl RuntimeAuditOpts {
    fn wants(&self, sec: &str) -> bool {
        match &self.only {
            None => true,
            Some(set) => set.contains(sec),
        }
    }

    fn effective_top(&self) -> usize {
        if self.full { self.top.max(25) } else { self.top }
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

// ====================================================== Probe script builder

const AWK_PROC_STATUS: &str = r#"awk '
FNR==1 { if (pid!="") print pid "|" name "|" uid "|" thr "|" rss "|" swp "|" vc "|" nvc; pid=""; name=""; uid=0; thr=0; rss=0; swp=0; vc=0; nvc=0 }
/^Name:/ { name=$2 }
/^Pid:/ { pid=$2 }
/^Uid:/ { uid=$2 }
/^Threads:/ { thr=$2 }
/^VmRSS:/ { rss=$2 }
/^VmSwap:/ { swp=$2 }
/^voluntary_ctxt_switches:/ { vc=$2 }
/^nonvoluntary_ctxt_switches:/ { nvc=$2 }
END { if (pid!="") print pid "|" name "|" uid "|" thr "|" rss "|" swp "|" vc "|" nvc }
' /proc/[0-9]*/status 2>/dev/null"#;

const AWK_PROC_STAT: &str = r#"awk '{ n=split($0, a, ")"); rest=a[n]; split(rest, f, " "); print $1 "|" f[12] "|" f[13] }' /proc/[0-9]*/stat 2>/dev/null"#;

fn build_probe_script(opts: &RuntimeAuditOpts) -> String {
    let need_delta = opts.window_s > 0 && (opts.wants("cpu") || opts.wants("irq") || opts.wants("daemons") || opts.wants("power"));
    let need_proc = opts.wants("cpu") || opts.wants("mem") || opts.wants("fd") || opts.wants("dmabuf") || opts.wants("daemons");
    let mut s = String::with_capacity(8192);
    s.push_str("LC_ALL=C\n");

    // ---------- PHASE A: Zero-observer-pollution idle delta window ----------
    s.push_str("echo '@@SEC:T0_META@@'\n");
    s.push_str("echo \"probe_pid=$$\"\n");
    s.push_str("echo \"uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)\"\n");
    s.push_str("echo \"bat_uA=$(cat /sys/class/power_supply/battery/current_now 2>/dev/null)\"\n");
    s.push_str("echo \"bat_uV=$(cat /sys/class/power_supply/battery/voltage_now 2>/dev/null)\"\n");
    s.push_str("echo \"bat_status=$(cat /sys/class/power_supply/battery/status 2>/dev/null)\"\n");
    s.push_str("echo \"bat_cap=$(cat /sys/class/power_supply/battery/capacity 2>/dev/null)\"\n");
    s.push_str("echo \"bat_temp=$(cat /sys/class/power_supply/battery/temp 2>/dev/null)\"\n");
    s.push_str("echo \"usb_online=$(cat /sys/class/power_supply/usb/online 2>/dev/null)\"\n");

    if need_proc {
        s.push_str("echo '@@SEC:T0_STATUS@@'\n");
        s.push_str(AWK_PROC_STATUS);
        s.push('\n');
        s.push_str("echo '@@SEC:T0_STAT@@'\n");
        s.push_str(AWK_PROC_STAT);
        s.push('\n');
    }
    if opts.wants("irq") {
        s.push_str("echo '@@SEC:T0_IRQS@@'\n");
        s.push_str("cat /proc/interrupts 2>/dev/null\n");
    }

    if need_delta {
        s.push_str(&format!("sleep {}\n", opts.window_s));
        s.push_str("echo '@@SEC:T1_META@@'\n");
        s.push_str("echo \"uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)\"\n");
        s.push_str("echo \"bat_uA=$(cat /sys/class/power_supply/battery/current_now 2>/dev/null)\"\n");
        s.push_str("echo \"bat_uV=$(cat /sys/class/power_supply/battery/voltage_now 2>/dev/null)\"\n");
        s.push_str("echo \"bat_status=$(cat /sys/class/power_supply/battery/status 2>/dev/null)\"\n");
        if need_proc {
            s.push_str("echo '@@SEC:T1_STATUS@@'\n");
            s.push_str(AWK_PROC_STATUS);
            s.push('\n');
            s.push_str("echo '@@SEC:T1_STAT@@'\n");
            s.push_str(AWK_PROC_STAT);
            s.push('\n');
        }
        if opts.wants("irq") {
            s.push_str("echo '@@SEC:T1_IRQS@@'\n");
            s.push_str("cat /proc/interrupts 2>/dev/null\n");
        }
    }

    // ---------- PHASE B: Deep forensic inspection (after idle window!) ----------
    s.push_str("echo '@@SEC:META@@'\n");
    s.push_str("echo \"uid=$(id -u)\"\n");
    s.push_str("echo \"epoch=$(date +%s)\"\n");
    s.push_str("echo \"uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)\"\n");
    s.push_str("echo \"device=$(getprop ro.product.device 2>/dev/null)\"\n");
    s.push_str("echo \"model=$(getprop ro.product.model 2>/dev/null)\"\n");
    s.push_str("echo \"build_id=$(getprop ro.build.display.id 2>/dev/null)\"\n");
    s.push_str("echo \"uname=$(uname -r 2>/dev/null)\"\n");
    s.push_str("echo \"selinux=$(getenforce 2>/dev/null)\"\n");
    s.push_str("echo \"clk_tck=$(getconf CLK_TCK 2>/dev/null || echo 100)\"\n");

    if need_proc {
        s.push_str("echo '@@SEC:PS@@'\n");
        s.push_str("ps -A -o PID,PPID,UID,USER,NAME,ARGS 2>/dev/null\n");
        s.push_str("echo '@@SEC:PROC_EXE@@'\n");
        s.push_str("ls -l /proc/[0-9]*/exe 2>/dev/null || true\n");
        s.push_str("echo '@@SEC:PROC_FD_CNT@@'\n");
        s.push_str(
            "ls -1 /proc/[0-9]*/fd 2>/dev/null | awk '\n\
             /^\\/proc\\/[0-9]+\\/fd:$/ { if (p!=\"\") print p \"|\" c; sub(/^\\/proc\\//, \"\"); sub(/\\/fd:$/, \"\"); p=$0; c=0; next }\n\
             /^[0-9]+$/ { c++ }\n\
             END { if (p!=\"\") print p \"|\" c }\n\
             '\n",
        );
    }

    if opts.wants("fd") {
        s.push_str("echo '@@SEC:FD_DETAIL@@'\n");
        s.push_str(
            "top_pids=$(ls -1 /proc/[0-9]*/fd 2>/dev/null | awk '\n\
             /^\\/proc\\/[0-9]+\\/fd:$/ { if (p!=\"\" && c>=100) print c \" \" p; sub(/^\\/proc\\//, \"\"); sub(/\\/fd:$/, \"\"); p=$0; c=0; next }\n\
             /^[0-9]+$/ { c++ }\n\
             END { if (p!=\"\" && c>=100) print c \" \" p }\n\
             ' | sort -rn | head -n 10 | awk '{print $2}')\n\
             for p in $top_pids; do\n\
               [ -d \"/proc/$p/fd\" ] || continue\n\
               echo \"@@FD:$p@@\"\n\
               ls -l \"/proc/$p/fd\" 2>/dev/null | awk '{print $NF}' | sed -E 's/:[0-9]+$/:.../; s/\\/sys\\/devices\\/virtual\\/wakeup\\/wakeup[0-9]+\\/.*/\\/sys\\/wakeup\\/*/g; s/ashmem[0-9a-f-]+/ashmem/g' | sort | uniq -c | sort -rn | head -n 12\n\
             done\n",
        );
    }

    if opts.wants("dmabuf") || opts.wants("fd") {
        s.push_str("echo '@@SEC:DMABUF@@'\n");
        s.push_str("dmabuf_dump 2>/dev/null || true\n");
        s.push_str("echo ''\n");
    }

    if opts.wants("mem") || opts.wants("daemons") {
        s.push_str("echo '@@SEC:MEMINFO@@'\n");
        s.push_str("echo '---proc_meminfo---'\n");
        s.push_str("cat /proc/meminfo 2>/dev/null\n");
        s.push_str("echo '---zram---'\n");
        s.push_str("cat /sys/block/zram0/mm_stat 2>/dev/null || true\n");
        s.push_str("echo '---slab---'\n");
        s.push_str("awk 'NR>2 { b=$3*$4; if (b>=2097152) printf \"%d|%s|%d|%d\\n\", b, $1, $3, $4 }' /proc/slabinfo 2>/dev/null | sort -rn | head -n 18\n");
        s.push_str("echo '---deferred_probes---'\n");
        s.push_str("cat /sys/kernel/debug/devices_deferred 2>/dev/null | sed '/^$/d' | wc -l\n");
        s.push_str("echo '---kmsg_splats---'\n");
        s.push_str("dmesg 2>/dev/null | grep -cE 'BUG:|Kernel panic|WARNING: CPU:|KASAN:|UBSAN:|CFI failure|Synchronous External Abort|RCU stall|page allocation failure|Out of memory:' || true\n");
        s.push_str("echo '---dumpsys_meminfo---'\n");
        s.push_str("dumpsys meminfo 2>/dev/null || true\n");
    }

    if opts.wants("power") {
        s.push_str("echo '@@SEC:WAKEUPS@@'\n");
        s.push_str("echo '---suspend_stats---'\n");
        s.push_str("for f in /sys/power/suspend_stats/*; do [ -r \"$f\" ] && echo \"$(basename \"$f\")=$(cat \"$f\" 2>/dev/null)\"; done\n");
        s.push_str("echo '---mem_sleep---'\n");
        s.push_str("cat /sys/power/mem_sleep 2>/dev/null || true\n");
        s.push_str("echo '---cpuidle---'\n");
        s.push_str("for st in /sys/devices/system/cpu/cpu0/cpuidle/state*; do [ -d \"$st\" ] && echo \"$(basename \"$st\")|$(cat \"$st/name\" 2>/dev/null)|$(cat \"$st/usage\" 2>/dev/null)|$(cat \"$st/time\" 2>/dev/null)\"; done\n");
        s.push_str("echo '---deviceidle---'\n");
        s.push_str("dumpsys deviceidle 2>/dev/null | grep -E 'mState=|mLightState=|mScreenOn=|mCharging=|mDeepEnabled=|mLightEnabled=|mMotionActive=' | head -n 10 || true\n");
        s.push_str("echo '---power_wakelocks---'\n");
        s.push_str("dumpsys power 2>/dev/null | awk '/Wake Locks: size=/{f=1} f{print} f && /^$/{exit}' | head -n 45 || true\n");
        s.push_str("echo '---sysfs_wakeup---'\n");
        s.push_str(
            "for w in /sys/class/wakeup/wakeup*; do\n\
               [ -r \"$w/name\" ] || continue\n\
               read nm < \"$w/name\" 2>/dev/null\n\
               read ac < \"$w/active_count\" 2>/dev/null\n\
               read ev < \"$w/event_count\" 2>/dev/null\n\
               read wc < \"$w/wakeup_count\" 2>/dev/null\n\
               read am < \"$w/active_time_ms\" 2>/dev/null\n\
               read tm < \"$w/total_time_ms\" 2>/dev/null\n\
               read pm < \"$w/prevent_suspend_time_ms\" 2>/dev/null\n\
               read mm < \"$w/max_time_ms\" 2>/dev/null\n\
               if [ \"${ev:-0}\" != 0 ] || [ \"${tm:-0}\" != 0 ] || [ \"${ac:-0}\" != 0 ]; then\n\
                 echo \"$nm|$ac|$ev|$wc|$am|$tm|$pm|$mm\"\n\
               fi\n\
             done\n",
        );
    }

    if opts.wants("irq") {
        s.push_str("echo '@@SEC:IRQ_META@@'\n");
        s.push_str("echo '---irq_hw---'\n");
        s.push_str(
            "for d in /sys/kernel/irq/*; do\n\
               [ -r \"$d/actions\" ] || continue\n\
               read act < \"$d/actions\" 2>/dev/null\n\
               [ -n \"$act\" ] || continue\n\
               read chip < \"$d/chip_name\" 2>/dev/null\n\
               read hw < \"$d/hwirq\" 2>/dev/null\n\
               echo \"${d##*/}|$chip|$hw|$act\"\n\
             done\n",
        );
        s.push_str("echo '---i2c_bus---'\n");
        s.push_str(
            "for bus in /sys/bus/i2c/devices/i2c-*; do\n\
               [ -d \"$bus\" ] || continue\n\
               real=$(readlink -f \"$bus\" 2>/dev/null)\n\
               devs=\"\"\n\
               for sub in \"$bus\"/[0-9]*-[0-9a-f]*; do\n\
                 [ -r \"$sub/name\" ] || continue\n\
                 read dn < \"$sub/name\" 2>/dev/null\n\
                 [ -n \"$devs\" ] && devs=\"$devs,\"\n\
                 devs=\"$devs${sub##*/}($dn)\"\n\
               done\n\
               echo \"${bus##*/}|$real|$devs\"\n\
             done\n",
        );
    }

    if opts.wants("alarms") {
        s.push_str("echo '@@SEC:ALARMS_JOBS@@'\n");
        s.push_str("echo '---alarms---'\n");
        s.push_str("dumpsys alarm 2>/dev/null | awk '/^  Alarm Stats:/{f=1; next} f && /^  [A-Z]/{exit} f{print}' | head -n 260 || true\n");
        s.push_str("echo '---jobs---'\n");
        s.push_str("dumpsys jobscheduler 2>/dev/null | awk '/Running jobs:/{f=1} f{print} f && /^$/{exit}' | head -n 60 || true\n");
    }

    if opts.wants("mem") || opts.wants("daemons") || opts.wants("power") {
        s.push_str("echo '@@SEC:POWER_THERM@@'\n");
        s.push_str("echo '---power_hal---'\n");
        s.push_str("dumpsys android.hardware.power.IPower/default 2>/dev/null | grep -E 'IsAdpfSupported|ADPF Tag Profile|PowerSessionManager ADPF|ID\\.Min\\.Act|SustainedPerformanceMode' | head -n 40 || true\n");
        if opts.full {
            s.push_str("echo '---hot_wchan---'\n");
            s.push_str(
                "for pat in citsensorservice diag-router tftp_server rmt_storage mi_thermal_engine padatd pantaud; do\n\
                   pid=$(pgrep -f \"$pat\" 2>/dev/null | head -n 1)\n\
                   [ -n \"$pid\" ] || continue\n\
                   echo \"@@WC:$pat:$pid@@\"\n\
                   for t in /proc/$pid/task/*; do\n\
                     read tc < \"$t/comm\" 2>/dev/null; read tw < \"$t/wchan\" 2>/dev/null\n\
                     echo \"$tc:$tw\"\n\
                   done | sort | uniq -c | sort -rn | head -n 8\n\
                 done\n",
            );
        }
    }

    if opts.wants("avc") {
        s.push_str("echo '@@SEC:DMESG_AVC@@'\n");
        s.push_str("dmesg 2>/dev/null | grep 'avc:' || true\n");
    }

    s.push_str("echo '@@SEC:END@@'\n");
    s
}

// ====================================================== Data models & parsers

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct ProcSnap {
    pid: u32,
    name: String,
    uid: u32,
    threads: u32,
    rss_kb: u64,
    swap_kb: u64,
    vctx: u64,
    nvctx: u64,
    utime: u64,
    stime: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct PsMeta {
    pid: u32,
    ppid: u32,
    uid: u32,
    user: String,
    name: String,
    args: String,
    exe: String,
    fd_count: usize,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct ProcDelta {
    pid: u32,
    name: String,
    display: String,
    exe: String,
    is_kthread: bool,
    dvctx: u64,
    dnvctx: u64,
    dticks: u64,
    vctx_per_s: f64,
    cpu_pct: f64,
    rss_kb: u64,
    swap_kb: u64,
    threads: u32,
}

#[derive(Clone, Debug)]
struct IrqRow {
    irq_id: String,
    desc: String,
    delta: u64,
    rate_s: f64,
    total: u64,
    cum_rate_s: f64,
    attr: String,
}

#[derive(Clone, Debug)]
struct DmaBufProc {
    pid: u32,
    name: String,
    total_rss_kb: u64,
    total_pss_kb: u64,
    buf_count: usize,
    max_buf_kb: u64,
}

#[derive(Clone, Debug, Default)]
struct MemSummary {
    mem_total_kb: u64,
    mem_avail_kb: u64,
    slab_recl_kb: u64,
    slab_unrecl_kb: u64,
    vmalloc_used_kb: u64,
    page_tables_kb: u64,
    kernel_stack_kb: u64,
    percpu_kb: u64,
    deferred_probes: usize,
    kmsg_splats: usize,
    zram_orig_kb: u64,
    zram_compr_kb: u64,
    zram_mem_used_kb: u64,
    ds_total_ram_kb: u64,
    ds_free_ram_kb: u64,
    ds_used_ram_kb: u64,
    ds_lost_ram_kb: u64,
    ds_zram_phys_kb: u64,
    ds_zram_swap_kb: u64,
    oom_totals_kb: BTreeMap<String, u64>,
    persistent_procs: Vec<(String, u32, u64)>,
    top_slabs: Vec<(String, u64, u64)>, // name, bytes, num_objs
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct WakeupSource {
    name: String,
    active: u64,
    events: u64,
    wakeups: u64,
    active_ms: u64,
    total_ms: u64,
    prevent_ms: u64,
    max_ms: u64,
}

#[derive(Clone, Debug)]
struct AlarmPkgStat {
    uid_pkg: String,
    running_ms: u64,
    wakeups: u64,
    top_tag: String,
    top_tag_wakes: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct VendorDaemon {
    pid: u32,
    name: String,
    exe: String,
    category: &'static str,
    rss_kb: u64,
    swap_kb: u64,
    threads: u32,
    fds: usize,
    cum_ticks: u64,
    vctx_per_s: f64,
}

#[derive(Clone, Debug, Default)]
struct Snapshot {
    timestamp: String,
    device: String,
    build_id: String,
    uname: String,
    uptime_s: f64,
    window_s: f64,
    adpf_supported: Option<bool>,
    used_ram_kb: u64,
    mem_avail_kb: u64,
    slab_recl_kb: u64,
    slab_unrecl_kb: u64,
    vmalloc_used_kb: u64,
    page_tables_kb: u64,
    kernel_stack_kb: u64,
    percpu_kb: u64,
    deferred_probes: usize,
    kmsg_splats: usize,
    native_pss_kb: u64,
    persistent_pss_kb: u64,
    persistent_count: usize,
    custom_pers_count: usize,
    lineage_proc_count: usize,
    zram_phys_kb: u64,
    zram_swap_kb: u64,
    vendor_daemon_count: usize,
    vendor_daemon_rss_swap_kb: u64,
    idle_user_vctx_s: f64,
    kthread_vctx_s: f64,
    idle_irq_s: f64,
    mi_thermal_fds: usize,
    mi_thermal_rss_kb: u64,
    mi_thermal_vctx_s: f64,
    padatd_rss_kb: u64,
    pantaud_rss_kb: u64,
    ir_yasvara_rss_kb: u64,
    launcher3_fds: usize,
    launcher3_dmabuf_cnt: usize,
    launcher3_dmabuf_kb: u64,
    total_dmabuf_kb: u64,
    active_wakelocks: usize,
    sys_avc_unique: usize,
    sys_avc_total: usize,
}

fn parse_proc_status(text: &str) -> HashMap<u32, ProcSnap> {
    let mut out = HashMap::new();
    for ln in text.lines() {
        let parts: Vec<&str> = ln.split('|').collect();
        if parts.len() < 8 {
            continue;
        }
        let Ok(pid) = parts[0].trim().parse::<u32>() else { continue };
        out.insert(
            pid,
            ProcSnap {
                pid,
                name: parts[1].trim().to_string(),
                uid: parts[2].trim().parse().unwrap_or(0),
                threads: parts[3].trim().parse().unwrap_or(0),
                rss_kb: parts[4].trim().parse().unwrap_or(0),
                swap_kb: parts[5].trim().parse().unwrap_or(0),
                vctx: parts[6].trim().parse().unwrap_or(0),
                nvctx: parts[7].trim().parse().unwrap_or(0),
                utime: 0,
                stime: 0,
            },
        );
    }
    out
}

fn merge_proc_stat(snaps: &mut HashMap<u32, ProcSnap>, text: &str) {
    for ln in text.lines() {
        let parts: Vec<&str> = ln.split('|').collect();
        if parts.len() < 3 {
            continue;
        }
        let Ok(pid) = parts[0].trim().parse::<u32>() else { continue };
        if let Some(s) = snaps.get_mut(&pid) {
            s.utime = parts[1].trim().parse().unwrap_or(0);
            s.stime = parts[2].trim().parse().unwrap_or(0);
        }
    }
}

fn parse_ps_meta(ps_text: &str, exe_text: &str, fd_text: &str) -> HashMap<u32, PsMeta> {
    let mut map: HashMap<u32, PsMeta> = HashMap::new();
    for ln in ps_text.lines().skip(1) {
        let cols: Vec<&str> = ln.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let Ok(pid) = cols[0].parse::<u32>() else { continue };
        let ppid = cols[1].parse::<u32>().unwrap_or(0);
        let uid = cols[2].parse::<u32>().unwrap_or(0);
        let user = cols[3].to_string();
        let name = cols[4].to_string();
        let args = if cols.len() > 5 { cols[5..].join(" ") } else { name.clone() };
        map.insert(
            pid,
            PsMeta {
                pid,
                ppid,
                uid,
                user,
                name,
                args,
                exe: String::new(),
                fd_count: 0,
            },
        );
    }
    // Parse `ls -l /proc/[0-9]*/exe`: "... /proc/1234/exe -> /vendor/bin/foo"
    for ln in exe_text.lines() {
        let Some((left, right)) = ln.split_once(" -> ") else { continue };
        let Some(p_idx) = left.rfind("/proc/") else { continue };
        let after = &left[p_idx + 6..];
        let Some(pid_str) = after.split('/').next() else { continue };
        let Ok(pid) = pid_str.parse::<u32>() else { continue };
        let exe = right.trim().trim_end_matches(" (deleted)").to_string();
        map.entry(pid)
            .and_modify(|m| m.exe = exe.clone())
            .or_insert_with(|| PsMeta {
                pid,
                exe,
                ..Default::default()
            });
    }
    for ln in fd_text.lines() {
        let Some((p_s, c_s)) = ln.split_once('|') else { continue };
        let Ok(pid) = p_s.trim().parse::<u32>() else { continue };
        let cnt = c_s.trim().parse::<usize>().unwrap_or(0);
        if let Some(m) = map.get_mut(&pid) {
            m.fd_count = cnt;
        }
    }
    map
}

fn parse_interrupts(text: &str) -> HashMap<String, (u64, String)> {
    let mut map = HashMap::new();
    let mut n_cpus = 0usize;
    for (idx, ln) in text.lines().enumerate() {
        let t = ln.trim();
        if t.is_empty() {
            continue;
        }
        if idx == 0 && t.starts_with("CPU0") {
            n_cpus = t.split_whitespace().count();
            continue;
        }
        let Some((id_raw, rest)) = t.split_once(':') else { continue };
        let id = id_raw.trim().to_string();
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let cpu_cols = if n_cpus > 0 { n_cpus.min(toks.len()) } else { 0 };
        let mut sum = 0u64;
        let mut consumed = 0usize;
        for tok in &toks {
            if cpu_cols > 0 && consumed >= cpu_cols {
                break;
            }
            if let Ok(v) = tok.parse::<u64>() {
                sum = sum.saturating_add(v);
                consumed += 1;
            } else {
                break;
            }
        }
        let desc = if consumed < toks.len() {
            toks[consumed..].join(" ")
        } else {
            String::new()
        };
        map.insert(id, (sum, desc));
    }
    map
}

/// Scans `sm8735-devicetrees` (`*qupv3*.dtsi` / `*.dtsi`) to map `GIC_SPI <num>` -> controller node
/// (e.g. `585 -> ("88c000", "qupv3_se11_i2c")`) so `i2c_geni` / `spi_geni` IRQs resolve to exact chips.
fn load_dt_irq_map(dt_root: &Path) -> HashMap<u32, (String, String)> {
    let mut map: HashMap<u32, (String, String)> = HashMap::new();
    let qcom_dir = dt_root.join("qcom");
    let Ok(rd) = fs::read_dir(&qcom_dir) else { return map };
    let mut files: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.contains("qupv3") && n.ends_with(".dtsi"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    for path in files {
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let mut cur_label = String::new();
        let mut cur_addr = String::new();
        for raw in text.lines() {
            let ln = raw.trim();
            if ln.contains('@') && ln.ends_with('{') && (ln.contains("i2c@") || ln.contains("spi@") || ln.contains("uart@")) {
                let before_brace = ln.trim_end_matches('{').trim();
                let (lbl, node) = match before_brace.split_once(':') {
                    Some((l, r)) => (l.trim(), r.trim()),
                    None => ("", before_brace),
                };
                if let Some((_, addr)) = node.split_once('@') {
                    cur_label = if !lbl.is_empty() { lbl.to_string() } else { node.to_string() };
                    cur_addr = addr.trim().to_ascii_lowercase();
                }
            } else if ln == "};" {
                cur_label.clear();
                cur_addr.clear();
            } else if !cur_addr.is_empty() && ln.contains("GIC_SPI") {
                if let Some(pos) = ln.find("GIC_SPI") {
                    let rest = ln[pos + 7..].trim_start();
                    let num_s: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(spi) = num_s.parse::<u32>() {
                        // Prefer `i2c` entries over shared `spi`/`uart` overlays on the same SE
                        let is_i2c = cur_label.contains("i2c");
                        match map.get(&spi) {
                            Some((_, prev_lbl)) if prev_lbl.contains("i2c") && !is_i2c => {}
                            _ => {
                                map.insert(spi, (cur_addr.clone(), cur_label.clone()));
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

fn parse_i2c_buses(text: &str) -> Vec<(String, String, String)> {
    // (bus_name, addr_hex_lower, devs_csv)
    let mut out = Vec::new();
    for ln in text.lines() {
        let parts: Vec<&str> = ln.splitn(3, '|').collect();
        if parts.len() < 3 {
            continue;
        }
        let bus = parts[0].trim().to_string();
        let real = parts[1].trim();
        let devs = parts[2].trim().to_string();
        // Extract hex address from ".../88c000.i2c/i2c-11"
        let mut addr = String::new();
        for seg in real.split('/') {
            if let Some(hex) = seg.strip_suffix(".i2c") {
                addr = hex.to_ascii_lowercase();
                break;
            }
        }
        out.push((bus, addr, devs));
    }
    out
}

fn parse_irq_hw(text: &str) -> HashMap<String, (String, u32, String)> {
    // irq_num_str -> (chip, hwirq, actions)
    let mut map = HashMap::new();
    for ln in text.lines() {
        let parts: Vec<&str> = ln.splitn(4, '|').collect();
        if parts.len() < 4 {
            continue;
        }
        let irq = parts[0].trim().to_string();
        let chip = parts[1].trim().to_string();
        let hwirq = parts[2].trim().parse::<u32>().unwrap_or(0);
        let act = parts[3].trim().to_string();
        map.insert(irq, (chip, hwirq, act));
    }
    map
}

fn resolve_irq_attr(
    irq_id: &str,
    irq_hw: &HashMap<String, (String, u32, String)>,
    dt_map: &HashMap<u32, (String, String)>,
    i2c_buses: &[(String, String, String)],
) -> String {
    let Some((chip, hwirq, act)) = irq_hw.get(irq_id) else {
        return String::new();
    };
    if chip.contains("GIC") && *hwirq >= 32 {
        let spi = hwirq - 32;
        if let Some((addr, lbl)) = dt_map.get(&spi) {
            if let Some((bus, _, devs)) = i2c_buses.iter().find(|(_, a, _)| a == addr) {
                if !devs.is_empty() {
                    return format!("{bus}: {devs}");
                }
                return format!("{bus} ({lbl})");
            }
            return format!("{lbl}@{addr} (SPI {spi})");
        }
        if act.contains("geni") {
            return format!("GIC_SPI {spi}");
        }
    }
    String::new()
}

fn parse_fd_detail(text: &str) -> HashMap<u32, Vec<(usize, String)>> {
    let mut out: HashMap<u32, Vec<(usize, String)>> = HashMap::new();
    let mut cur_pid: Option<u32> = None;
    for ln in text.lines() {
        let t = ln.trim();
        if let Some(rest) = t.strip_prefix("@@FD:") {
            if let Some(p_s) = rest.strip_suffix("@@") {
                cur_pid = p_s.parse::<u32>().ok();
                continue;
            }
        }
        if let Some(pid) = cur_pid {
            let mut it = t.splitn(2, char::is_whitespace);
            if let (Some(c_s), Some(target)) = (it.next(), it.next()) {
                if let Ok(cnt) = c_s.trim().parse::<usize>() {
                    out.entry(pid).or_default().push((cnt, target.trim().to_string()));
                }
            }
        }
    }
    out
}

fn parse_dmabuf_dump(text: &str) -> (Vec<DmaBufProc>, u64) {
    let mut procs = Vec::new();
    let mut cur_name = String::new();
    let mut cur_pid = 0u32;
    let mut buf_count = 0usize;
    let mut max_buf_kb = 0u64;
    let mut in_proc = false;

    for raw in text.lines() {
        let ln = raw.trim();
        if ln.is_empty() || ln.starts_with("Unable to read") || ln.starts_with("Warning:") || ln.starts_with("dmabuf total:") {
            continue;
        }
        if ln.starts_with("---") {
            in_proc = false;
            continue;
        }
        if ln.starts_with("Name") && ln.contains("Exporter") {
            continue;
        }
        if ln.starts_with("PROCESS TOTAL") {
            let toks: Vec<&str> = ln.split_whitespace().collect();
            // "PROCESS TOTAL 43484 kB 43484 kB"
            let rss_kb = toks.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let pss_kb = toks.get(4).and_then(|s| s.parse::<u64>().ok()).unwrap_or(rss_kb);
            if cur_pid > 0 {
                procs.push(DmaBufProc {
                    pid: cur_pid,
                    name: cur_name.clone(),
                    total_rss_kb: rss_kb,
                    total_pss_kb: pss_kb,
                    buf_count,
                    max_buf_kb,
                });
            }
            in_proc = false;
            continue;
        }
        if !in_proc {
            // Header line: "droid.launcher3:3815" or "vendor.xiaomi.s:2247"
            if let Some((nm, p_s)) = ln.rsplit_once(':') {
                if let Ok(pid) = p_s.trim().parse::<u32>() {
                    cur_name = nm.trim().to_string();
                    cur_pid = pid;
                    buf_count = 0;
                    max_buf_kb = 0;
                    in_proc = true;
                }
            }
            continue;
        }
        // Buffer row: "qcom,system  10396 kB  10396 kB  1  218  qcom,system"
        let toks: Vec<&str> = ln.split_whitespace().collect();
        if toks.len() >= 6 && toks[2] == "kB" {
            if let Ok(sz) = toks[1].parse::<u64>() {
                buf_count += 1;
                if sz > max_buf_kb {
                    max_buf_kb = sz;
                }
            }
        }
    }

    procs.sort_by(|a, b| b.total_pss_kb.cmp(&a.total_pss_kb).then_with(|| b.buf_count.cmp(&a.buf_count)));
    let total_pss_kb: u64 = procs.iter().map(|p| p.total_pss_kb).sum();
    (procs, total_pss_kb)
}

fn parse_kb_comma(s: &str) -> u64 {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    cleaned.parse::<u64>().unwrap_or(0)
}

fn parse_meminfo(sec_text: &str) -> MemSummary {
    let mut m = MemSummary::default();
    let sub = split_sub_blocks(sec_text);

    if let Some(pm) = sub.get("proc_meminfo") {
        for ln in pm.lines() {
            let mut it = ln.split_whitespace();
            let Some(k) = it.next() else { continue };
            let val = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            match k {
                "MemTotal:" => m.mem_total_kb = val,
                "MemAvailable:" => m.mem_avail_kb = val,
                "SReclaimable:" => m.slab_recl_kb = val,
                "SUnreclaim:" => m.slab_unrecl_kb = val,
                "VmallocUsed:" => m.vmalloc_used_kb = val,
                "PageTables:" => m.page_tables_kb = val,
                "KernelStack:" => m.kernel_stack_kb = val,
                "Percpu:" => m.percpu_kb = val,
                _ => {}
            }
        }
    }

    if let Some(dp) = sub.get("deferred_probes") {
        m.deferred_probes = dp.trim().parse::<usize>().unwrap_or(0);
    }
    if let Some(ks) = sub.get("kmsg_splats") {
        m.kmsg_splats = ks.trim().parse::<usize>().unwrap_or(0);
    }

    if let Some(zr) = sub.get("zram") {
        let toks: Vec<u64> = zr.split_whitespace().filter_map(|s| s.parse::<u64>().ok()).collect();
        if toks.len() >= 3 {
            m.zram_orig_kb = toks[0] / 1024;
            m.zram_compr_kb = toks[1] / 1024;
            m.zram_mem_used_kb = toks[2] / 1024;
        }
    }

    if let Some(sl) = sub.get("slab") {
        for ln in sl.lines() {
            let parts: Vec<&str> = ln.split('|').collect();
            if parts.len() >= 4 {
                let bytes = parts[0].trim().parse::<u64>().unwrap_or(0);
                let name = parts[1].trim().to_string();
                let objs = parts[2].trim().parse::<u64>().unwrap_or(0);
                m.top_slabs.push((name, bytes, objs));
            }
        }
    }

    if let Some(ds) = sub.get("dumpsys_meminfo") {
        let mut in_oom = false;
        let mut cur_oom = String::new();
        for raw in ds.lines() {
            let t = raw.trim();
            if t.starts_with("Total PSS by OOM adjustment:") {
                in_oom = true;
                continue;
            }
            if t.starts_with("Total PSS by category:") {
                in_oom = false;
                continue;
            }
            if in_oom {
                // Group header: "    734,353K: Persistent" (4 leading spaces)
                // Process entry: "        245,112K: system (pid 1479)" (8+ leading spaces)
                let indent = raw.len() - raw.trim_start().len();
                if let Some((kb_part, rest)) = t.split_once("K:") {
                    let kb = parse_kb_comma(kb_part);
                    let label = rest.trim();
                    if indent <= 5 {
                        cur_oom = label.to_string();
                        m.oom_totals_kb.insert(cur_oom.clone(), kb);
                    } else if cur_oom == "Persistent" || cur_oom == "Persistent Service" {
                        let (pname, pid) = if let Some((l, r)) = label.split_once(" (pid ") {
                            let pid_s = r.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
                            (l.trim().to_string(), pid_s.parse::<u32>().unwrap_or(0))
                        } else {
                            (label.to_string(), 0)
                        };
                        m.persistent_procs.push((pname, pid, kb));
                    }
                }
            } else if let Some(rest) = t.strip_prefix("Total RAM:") {
                if let Some((kb_s, _)) = rest.split_once('K') {
                    m.ds_total_ram_kb = parse_kb_comma(kb_s);
                }
            } else if let Some(rest) = t.strip_prefix("Free RAM:") {
                if let Some((kb_s, _)) = rest.split_once('K') {
                    m.ds_free_ram_kb = parse_kb_comma(kb_s);
                }
            } else if let Some(rest) = t.strip_prefix("Used RAM:") {
                if let Some((kb_s, _)) = rest.split_once('K') {
                    m.ds_used_ram_kb = parse_kb_comma(kb_s);
                }
            } else if let Some(rest) = t.strip_prefix("Lost RAM:") {
                if let Some((kb_s, _)) = rest.split_once('K') {
                    m.ds_lost_ram_kb = parse_kb_comma(kb_s);
                }
            } else if let Some(rest) = t.strip_prefix("ZRAM:") {
                // "ZRAM: 569,796K physical used for 1,662,108K in swap (8,388,604K total swap)"
                if let Some((phys_s, after)) = rest.split_once("K physical used for") {
                    m.ds_zram_phys_kb = parse_kb_comma(phys_s);
                    if let Some((swap_s, _)) = after.split_once("K in swap") {
                        m.ds_zram_swap_kb = parse_kb_comma(swap_s);
                    }
                }
            }
        }
    }

    m
}

fn parse_wakeup_sources(text: &str) -> Vec<WakeupSource> {
    let mut out = Vec::new();
    for ln in text.lines() {
        let parts: Vec<&str> = ln.split('|').collect();
        if parts.len() < 8 {
            continue;
        }
        out.push(WakeupSource {
            name: parts[0].trim().to_string(),
            active: parts[1].trim().parse().unwrap_or(0),
            events: parts[2].trim().parse().unwrap_or(0),
            wakeups: parts[3].trim().parse().unwrap_or(0),
            active_ms: parts[4].trim().parse().unwrap_or(0),
            total_ms: parts[5].trim().parse().unwrap_or(0),
            prevent_ms: parts[6].trim().parse().unwrap_or(0),
            max_ms: parts[7].trim().parse().unwrap_or(0),
        });
    }
    out.sort_by(|a, b| {
        b.prevent_ms
            .cmp(&a.prevent_ms)
            .then_with(|| b.total_ms.cmp(&a.total_ms))
            .then_with(|| b.events.cmp(&a.events))
    });
    out
}

fn parse_duration_ms(s: &str) -> u64 {
    // Handles "+1m23s456ms", "+621ms", "+2s10ms", "+1h2m3s4ms"
    let t = s.trim().trim_start_matches('+');
    let mut total = 0u64;
    let mut num = 0u64;
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            num = num * 10 + (bytes[i] - b'0') as u64;
            i += 1;
        } else if i + 1 < bytes.len() && &t[i..i + 2] == "ms" {
            total += num;
            num = 0;
            i += 2;
        } else {
            match bytes[i] {
                b'd' => total += num * 86_400_000,
                b'h' => total += num * 3_600_000,
                b'm' => total += num * 60_000,
                b's' => total += num * 1_000,
                _ => {}
            }
            num = 0;
            i += 1;
        }
    }
    total
}

fn parse_alarm_stats(text: &str) -> Vec<AlarmPkgStat> {
    let mut out: Vec<AlarmPkgStat> = Vec::new();
    let mut cur: Option<AlarmPkgStat> = None;
    let mut pending_wakes = 0u64;
    for raw in text.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if indent <= 2 && t.contains(" running, ") && t.contains(" wakeups:") {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            // "u0a164:com.google.android.gms +246ms running, 24 wakeups:"
            let toks: Vec<&str> = t.split_whitespace().collect();
            let uid_pkg = toks.first().copied().unwrap_or("").to_string();
            let running_ms = toks.get(1).map(|s| parse_duration_ms(s)).unwrap_or(0);
            let wakeups = toks.get(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            cur = Some(AlarmPkgStat {
                uid_pkg,
                running_ms,
                wakeups,
                top_tag: String::new(),
                top_tag_wakes: 0,
            });
            pending_wakes = 0;
        } else if indent == 4 && t.contains(" wakes ") {
            // "+134ms 20 wakes 20 alarms, last -1m59s669ms:"
            let toks: Vec<&str> = t.split_whitespace().collect();
            pending_wakes = toks.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        } else if indent >= 6 {
            if let Some(c) = cur.as_mut() {
                if pending_wakes > c.top_tag_wakes || c.top_tag.is_empty() {
                    c.top_tag_wakes = pending_wakes;
                    c.top_tag = t.to_string();
                }
            }
        }
    }
    if let Some(prev) = cur {
        out.push(prev);
    }
    out.sort_by(|a, b| b.wakeups.cmp(&a.wakeups).then_with(|| b.running_ms.cmp(&a.running_ms)));
    out
}

fn categorize_vendor_daemon(exe: &str, name: &str) -> &'static str {
    let low = format!("{} {}", exe, name).to_ascii_lowercase();
    if low.contains("camera") {
        "Camera"
    } else if low.contains("citsensor") {
        "Display/ALS-CWB"
    } else if low.contains("display") || low.contains("composer") || low.contains("allocator") || low.contains("surface") {
        "Display"
    } else if low.contains("audio") || low.contains("dolby") || low.contains("soundtrigger") || low.contains("dax") {
        "Audio"
    } else if low.contains("sensor") || low.contains("touch") || low.contains("vibrator") || low.contains("haptic") {
        "Sensors/Input"
    } else if low.contains("thermal") || low.contains("power") || low.contains("micharge") || low.contains("health") || low.contains("qspm") {
        "Power/Thermal"
    } else if low.contains("diag") || low.contains("qcc") || low.contains("qwes") || low.contains("xtra") || low.contains("tlpd") || low.contains("hypsys") || low.contains("snapdragon_services") || low.contains("qsap_dcfd") {
        "Diag/Telemetry"
    } else if low.contains("wfd") || low.contains("wifidisplay") || low.contains("vpp") {
        "WFD/VPP"
    } else if low.contains("qcril") || low.contains("tftp") || low.contains("rmt_storage") || low.contains("ims") || low.contains("qms") || low.contains("nicmd") || low.contains("dpmd") || low.contains("cnd") || low.contains("ipacm") || low.contains("netmgr") || low.contains("qrtr") || low.contains("modem") || low.contains("gnss") {
        "Modem/Net/GNSS"
    } else if low.contains("qsee") || low.contains("soter") || low.contains("trustedui") || low.contains("gatekeeper") || low.contains("keymint") || low.contains("drm") || low.contains("biometrics") || low.contains("fingerprint") || low.contains("ssgtz") || low.contains("feature_enabler") {
        "TEE/DRM/Bio"
    } else if low.contains("media") || low.contains("codec") || low.contains("c2") {
        "Media/Codec"
    } else {
        "Vendor/Other"
    }
}

fn is_core_aosp_persistent(proc_name: &str) -> bool {
    matches!(
        proc_name,
        "system"
            | "com.android.systemui"
            | "com.android.phone"
            | "com.android.networkstack.process"
            | "com.android.se"
            | "com.android.nfc"
            | "com.android.bluetooth"
            | "com.android.uwb"
            | "com.android.wifi"
            | "com.android.shell"
            | "com.qualcomm.qti.telephonyservice"
            | "com.qualcomm.location"
            | "org.codeaurora.ims"
            | "com.qti.phone"
            | "com.xiaomi.joyose"
    ) || proc_name.starts_with("com.android.networkstack")
        || proc_name.starts_with("com.android.server.")
        || proc_name.starts_with("com.google.android.networkstack")
}

fn is_retired_or_lineage(name: &str, args: &str) -> bool {
    let s = format!("{name} {args}");
    s.contains("org.lineageos.")
        || s.contains("lineage-sdk")
        || s.contains("android.hardware.ir-service.lineage")
        || s.contains("vendor.lineage.health-service")
        || s.contains("com.xiaomi.settings")
        || s.contains("SimpleDeviceConfig")
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn fmt_mb(kb: u64) -> String {
    format!("{:.1}M", kb as f64 / 1024.0)
}

// ====================================================== Snapshot JSON save / load / diff

impl Snapshot {
    fn to_json(&self) -> String {
        let adpf_s = match self.adpf_supported {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        };
        format!(
            "{{\n\
             \x20 \"timestamp\": {},\n\
             \x20 \"device\": {},\n\
             \x20 \"build_id\": {},\n\
             \x20 \"uname\": {},\n\
             \x20 \"uptime_s\": {:.2},\n\
             \x20 \"window_s\": {:.2},\n\
             \x20 \"adpf_supported\": {},\n\
             \x20 \"used_ram_kb\": {},\n\
             \x20 \"mem_avail_kb\": {},\n\
             \x20 \"slab_recl_kb\": {},\n\
             \x20 \"slab_unrecl_kb\": {},\n\
             \x20 \"vmalloc_used_kb\": {},\n\
             \x20 \"page_tables_kb\": {},\n\
             \x20 \"kernel_stack_kb\": {},\n\
             \x20 \"percpu_kb\": {},\n\
             \x20 \"deferred_probes\": {},\n\
             \x20 \"kmsg_splats\": {},\n\
             \x20 \"native_pss_kb\": {},\n\
             \x20 \"persistent_pss_kb\": {},\n\
             \x20 \"persistent_count\": {},\n\
             \x20 \"custom_pers_count\": {},\n\
             \x20 \"lineage_proc_count\": {},\n\
             \x20 \"zram_phys_kb\": {},\n\
             \x20 \"zram_swap_kb\": {},\n\
             \x20 \"vendor_daemon_count\": {},\n\
             \x20 \"vendor_daemon_rss_swap_kb\": {},\n\
             \x20 \"idle_user_vctx_s\": {:.2},\n\
             \x20 \"kthread_vctx_s\": {:.2},\n\
             \x20 \"idle_irq_s\": {:.2},\n\
             \x20 \"mi_thermal_fds\": {},\n\
             \x20 \"mi_thermal_rss_kb\": {},\n\
             \x20 \"mi_thermal_vctx_s\": {:.2},\n\
             \x20 \"padatd_rss_kb\": {},\n\
             \x20 \"pantaud_rss_kb\": {},\n\
             \x20 \"ir_yasvara_rss_kb\": {},\n\
             \x20 \"launcher3_fds\": {},\n\
             \x20 \"launcher3_dmabuf_cnt\": {},\n\
             \x20 \"launcher3_dmabuf_kb\": {},\n\
             \x20 \"total_dmabuf_kb\": {},\n\
             \x20 \"active_wakelocks\": {},\n\
             \x20 \"sys_avc_unique\": {},\n\
             \x20 \"sys_avc_total\": {}\n\
             }}\n",
            json_escape(&self.timestamp),
            json_escape(&self.device),
            json_escape(&self.build_id),
            json_escape(&self.uname),
            self.uptime_s,
            self.window_s,
            adpf_s,
            self.used_ram_kb,
            self.mem_avail_kb,
            self.slab_recl_kb,
            self.slab_unrecl_kb,
            self.vmalloc_used_kb,
            self.page_tables_kb,
            self.kernel_stack_kb,
            self.percpu_kb,
            self.deferred_probes,
            self.kmsg_splats,
            self.native_pss_kb,
            self.persistent_pss_kb,
            self.persistent_count,
            self.custom_pers_count,
            self.lineage_proc_count,
            self.zram_phys_kb,
            self.zram_swap_kb,
            self.vendor_daemon_count,
            self.vendor_daemon_rss_swap_kb,
            self.idle_user_vctx_s,
            self.kthread_vctx_s,
            self.idle_irq_s,
            self.mi_thermal_fds,
            self.mi_thermal_rss_kb,
            self.mi_thermal_vctx_s,
            self.padatd_rss_kb,
            self.pantaud_rss_kb,
            self.ir_yasvara_rss_kb,
            self.launcher3_fds,
            self.launcher3_dmabuf_cnt,
            self.launcher3_dmabuf_kb,
            self.total_dmabuf_kb,
            self.active_wakelocks,
            self.sys_avc_unique,
            self.sys_avc_total,
        )
    }

    fn from_json(text: &str) -> Result<Self, String> {
        let mut s = Snapshot::default();
        let mut found_any = false;
        for raw in text.lines() {
            let ln = raw.trim().trim_end_matches(',');
            let Some((k_raw, v_raw)) = ln.split_once(':') else { continue };
            let k = k_raw.trim().trim_matches('"');
            let v = v_raw.trim();
            let v_str = v.trim_matches('"').to_string();
            found_any = true;
            match k {
                "timestamp" => s.timestamp = v_str,
                "device" => s.device = v_str,
                "build_id" => s.build_id = v_str,
                "uname" => s.uname = v_str,
                "uptime_s" => s.uptime_s = v.parse().unwrap_or(0.0),
                "window_s" => s.window_s = v.parse().unwrap_or(0.0),
                "adpf_supported" => {
                    s.adpf_supported = match v {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    }
                }
                "used_ram_kb" => s.used_ram_kb = v.parse().unwrap_or(0),
                "mem_avail_kb" => s.mem_avail_kb = v.parse().unwrap_or(0),
                "slab_recl_kb" => s.slab_recl_kb = v.parse().unwrap_or(0),
                "slab_unrecl_kb" => s.slab_unrecl_kb = v.parse().unwrap_or(0),
                "vmalloc_used_kb" => s.vmalloc_used_kb = v.parse().unwrap_or(0),
                "page_tables_kb" => s.page_tables_kb = v.parse().unwrap_or(0),
                "kernel_stack_kb" => s.kernel_stack_kb = v.parse().unwrap_or(0),
                "percpu_kb" => s.percpu_kb = v.parse().unwrap_or(0),
                "deferred_probes" => s.deferred_probes = v.parse().unwrap_or(0),
                "kmsg_splats" => s.kmsg_splats = v.parse().unwrap_or(0),
                "native_pss_kb" => s.native_pss_kb = v.parse().unwrap_or(0),
                "persistent_pss_kb" => s.persistent_pss_kb = v.parse().unwrap_or(0),
                "persistent_count" => s.persistent_count = v.parse().unwrap_or(0),
                "custom_pers_count" => s.custom_pers_count = v.parse().unwrap_or(0),
                "lineage_proc_count" => s.lineage_proc_count = v.parse().unwrap_or(0),
                "zram_phys_kb" => s.zram_phys_kb = v.parse().unwrap_or(0),
                "zram_swap_kb" => s.zram_swap_kb = v.parse().unwrap_or(0),
                "vendor_daemon_count" => s.vendor_daemon_count = v.parse().unwrap_or(0),
                "vendor_daemon_rss_swap_kb" => s.vendor_daemon_rss_swap_kb = v.parse().unwrap_or(0),
                "idle_user_vctx_s" => s.idle_user_vctx_s = v.parse().unwrap_or(0.0),
                "kthread_vctx_s" => s.kthread_vctx_s = v.parse().unwrap_or(0.0),
                "idle_irq_s" => s.idle_irq_s = v.parse().unwrap_or(0.0),
                "mi_thermal_fds" => s.mi_thermal_fds = v.parse().unwrap_or(0),
                "mi_thermal_rss_kb" => s.mi_thermal_rss_kb = v.parse().unwrap_or(0),
                "mi_thermal_vctx_s" => s.mi_thermal_vctx_s = v.parse().unwrap_or(0.0),
                "padatd_rss_kb" => s.padatd_rss_kb = v.parse().unwrap_or(0),
                "pantaud_rss_kb" => s.pantaud_rss_kb = v.parse().unwrap_or(0),
                "ir_yasvara_rss_kb" => s.ir_yasvara_rss_kb = v.parse().unwrap_or(0),
                "launcher3_fds" => s.launcher3_fds = v.parse().unwrap_or(0),
                "launcher3_dmabuf_cnt" => s.launcher3_dmabuf_cnt = v.parse().unwrap_or(0),
                "launcher3_dmabuf_kb" => s.launcher3_dmabuf_kb = v.parse().unwrap_or(0),
                "total_dmabuf_kb" => s.total_dmabuf_kb = v.parse().unwrap_or(0),
                "active_wakelocks" => s.active_wakelocks = v.parse().unwrap_or(0),
                "sys_avc_unique" => s.sys_avc_unique = v.parse().unwrap_or(0),
                "sys_avc_total" => s.sys_avc_total = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        if !found_any {
            return Err("snapshot JSON contained no recognizable fields".into());
        }
        Ok(s)
    }
}

fn print_diff_row_f64(label: &str, before: f64, after: f64, unit: &str, lower_is_better: bool) {
    let delta = after - before;
    let tag = if delta.abs() < 0.05 {
        "SAME"
    } else if (delta < 0.0) == lower_is_better {
        "BETTER"
    } else {
        "REGRESS"
    };
    let sign = if delta >= 0.0 { "+" } else { "" };
    println!(
        "  {:<28} {:>10.1}{:<4} -> {:>10.1}{:<4} ({}{:.1}{})  [{}]",
        label, before, unit, after, unit, sign, delta, unit, tag
    );
}

fn print_diff_row_u64(label: &str, before: u64, after: u64, unit: &str, lower_is_better: bool) {
    let delta = after as i64 - before as i64;
    let tag = if delta == 0 {
        "SAME"
    } else if (delta < 0) == lower_is_better {
        "BETTER"
    } else {
        "REGRESS"
    };
    let sign = if delta > 0 { "+" } else { "" };
    println!(
        "  {:<28} {:>10}{:<4} -> {:>10}{:<4} ({}{}{})  [{}]",
        label, before, unit, after, unit, sign, delta, unit, tag
    );
}

fn print_snapshot_diff(before: &Snapshot, after: &Snapshot) {
    println!("\n========================================================================");
    println!("BEFORE vs AFTER DELTA ({} -> {})", before.timestamp, after.timestamp);
    if !before.uname.is_empty() || !after.uname.is_empty() {
        println!("  kernel: {} -> {}", before.uname, after.uname);
    }
    println!("========================================================================");
    let adpf_b = before.adpf_supported.map(|b| if b { "Yes" } else { "No" }).unwrap_or("?");
    let adpf_a = after.adpf_supported.map(|b| if b { "Yes" } else { "No" }).unwrap_or("?");
    let adpf_tag = if adpf_b == adpf_a {
        "SAME"
    } else if adpf_a == "Yes" {
        "BETTER"
    } else {
        "REGRESS"
    };
    println!("  {:<28} {:>14} -> {:>14}  [{}]", "Power HAL ADPF", adpf_b, adpf_a, adpf_tag);
    print_diff_row_f64("Used RAM", before.used_ram_kb as f64 / 1024.0, after.used_ram_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("MemAvailable", before.mem_avail_kb as f64 / 1024.0, after.mem_avail_kb as f64 / 1024.0, "M", false);
    if before.slab_unrecl_kb > 0 || after.slab_unrecl_kb > 0 {
        print_diff_row_f64("Kernel Slab Unreclaimable", before.slab_unrecl_kb as f64 / 1024.0, after.slab_unrecl_kb as f64 / 1024.0, "M", true);
        print_diff_row_f64("Kernel Slab Reclaimable", before.slab_recl_kb as f64 / 1024.0, after.slab_recl_kb as f64 / 1024.0, "M", true);
        print_diff_row_f64("Kernel VmallocUsed", before.vmalloc_used_kb as f64 / 1024.0, after.vmalloc_used_kb as f64 / 1024.0, "M", true);
        print_diff_row_f64("Kernel PageTables", before.page_tables_kb as f64 / 1024.0, after.page_tables_kb as f64 / 1024.0, "M", true);
        print_diff_row_f64("KernelStack + Percpu", (before.kernel_stack_kb + before.percpu_kb) as f64 / 1024.0, (after.kernel_stack_kb + after.percpu_kb) as f64 / 1024.0, "M", true);
        print_diff_row_u64("Deferred probes", before.deferred_probes as u64, after.deferred_probes as u64, "", true);
        print_diff_row_u64("Kernel dmesg splats", before.kmsg_splats as u64, after.kmsg_splats as u64, "", true);
    }
    print_diff_row_f64("Native PSS", before.native_pss_kb as f64 / 1024.0, after.native_pss_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("Persistent PSS", before.persistent_pss_kb as f64 / 1024.0, after.persistent_pss_kb as f64 / 1024.0, "M", true);
    print_diff_row_u64("Custom *PERS* apps", before.custom_pers_count as u64, after.custom_pers_count as u64, "", true);
    print_diff_row_u64("Retired Lineage/Xiaomi procs", before.lineage_proc_count as u64, after.lineage_proc_count as u64, "", true);
    print_diff_row_f64("ZRAM phys used", before.zram_phys_kb as f64 / 1024.0, after.zram_phys_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("Vendor daemons R+S", before.vendor_daemon_rss_swap_kb as f64 / 1024.0, after.vendor_daemon_rss_swap_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("Idle userspace vctx/s", before.idle_user_vctx_s, after.idle_user_vctx_s, "/s", true);
    if before.kthread_vctx_s > 0.0 || after.kthread_vctx_s > 0.0 {
        print_diff_row_f64("Idle kthread vctx/s", before.kthread_vctx_s, after.kthread_vctx_s, "/s", true);
    }
    print_diff_row_f64("Idle non-timer IRQs/s", before.idle_irq_s, after.idle_irq_s, "/s", true);
    print_diff_row_u64("mi_thermal_engine FDs", before.mi_thermal_fds as u64, after.mi_thermal_fds as u64, "", true);
    print_diff_row_f64("mi_thermal_engine vctx/s", before.mi_thermal_vctx_s, after.mi_thermal_vctx_s, "/s", true);
    print_diff_row_f64("padatd RSS (0=lazy idle)", before.padatd_rss_kb as f64 / 1024.0, after.padatd_rss_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("pantaud RSS (0=lazy idle)", before.pantaud_rss_kb as f64 / 1024.0, after.pantaud_rss_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("ir-yasvara RSS (0=lazy)", before.ir_yasvara_rss_kb as f64 / 1024.0, after.ir_yasvara_rss_kb as f64 / 1024.0, "M", true);
    print_diff_row_u64("Launcher3 open FDs", before.launcher3_fds as u64, after.launcher3_fds as u64, "", true);
    print_diff_row_u64("Launcher3 DMA-BUF count", before.launcher3_dmabuf_cnt as u64, after.launcher3_dmabuf_cnt as u64, "", true);
    print_diff_row_f64("Launcher3 DMA-BUF PSS", before.launcher3_dmabuf_kb as f64 / 1024.0, after.launcher3_dmabuf_kb as f64 / 1024.0, "M", true);
    print_diff_row_f64("Total DMA-BUF PSS", before.total_dmabuf_kb as f64 / 1024.0, after.total_dmabuf_kb as f64 / 1024.0, "M", true);
    print_diff_row_u64("System/HAL AVCs (unique)", before.sys_avc_unique as u64, after.sys_avc_unique as u64, "", true);
}

// ====================================================== Main command

pub fn cmd_runtime_audit(ctx: &Ctx, opts: &RuntimeAuditOpts) -> i32 {
    let dev = match select_adb_device(ctx, opts.serial.as_deref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let script = build_probe_script(opts);
    let raw = match run_adb_probe(ctx, &dev.serial, &script) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let secs = parse_sections(&raw);
    let meta = parse_kv(secs.get("META").map(|s| s.as_str()).unwrap_or(""));
    let t0_meta = parse_kv(secs.get("T0_META").map(|s| s.as_str()).unwrap_or(""));
    let t1_meta = parse_kv(secs.get("T1_META").map(|s| s.as_str()).unwrap_or(""));

    let probe_pid: u32 = t0_meta.get("probe_pid").and_then(|s| s.parse().ok()).unwrap_or(0);
    let t0_up: f64 = t0_meta.get("uptime_s").and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let t1_up: f64 = t1_meta.get("uptime_s").and_then(|s| s.parse().ok()).unwrap_or(t0_up);
    let dt = (t1_up - t0_up).max(0.0);
    let uptime_s: f64 = meta.get("uptime_s").and_then(|s| s.parse().ok()).unwrap_or(t1_up.max(1.0));
    let clk_tck: f64 = meta.get("clk_tck").and_then(|s| s.parse().ok()).unwrap_or(100.0);

    let device = meta.get("device").cloned().unwrap_or_else(|| "unknown".into());
    let model = meta.get("model").cloned().unwrap_or_default();
    let build_id = meta.get("build_id").cloned().unwrap_or_default();
    let uname = meta.get("uname").cloned().unwrap_or_default();
    let epoch = meta.get("epoch").cloned().unwrap_or_else(|| "0".into());

    let mut snap0 = parse_proc_status(secs.get("T0_STATUS").map(|s| s.as_str()).unwrap_or(""));
    merge_proc_stat(&mut snap0, secs.get("T0_STAT").map(|s| s.as_str()).unwrap_or(""));

    let snap1 = if secs.contains_key("T1_STATUS") {
        let mut m = parse_proc_status(secs.get("T1_STATUS").map(|s| s.as_str()).unwrap_or(""));
        merge_proc_stat(&mut m, secs.get("T1_STAT").map(|s| s.as_str()).unwrap_or(""));
        m
    } else {
        snap0.clone()
    };

    let ps_meta = parse_ps_meta(
        secs.get("PS").map(|s| s.as_str()).unwrap_or(""),
        secs.get("PROC_EXE").map(|s| s.as_str()).unwrap_or(""),
        secs.get("PROC_FD_CNT").map(|s| s.as_str()).unwrap_or(""),
    );

    // Exclude probe shell & its direct children from idle noise
    let is_probe_proc = |pid: u32, name: &str| -> bool {
        if pid == probe_pid {
            return true;
        }
        if let Some(m) = ps_meta.get(&pid) {
            if m.ppid == probe_pid {
                return true;
            }
            if name == "adbd" && m.args.contains("adbd") {
                return false;
            }
        }
        matches!(name, "sh" | "awk" | "sleep") && ps_meta.get(&pid).map(|m| m.ppid == probe_pid).unwrap_or(false)
    };

    // Compute per-process idle deltas
    let mut proc_deltas: Vec<ProcDelta> = Vec::new();
    let mut vctx_rate_by_pid: HashMap<u32, f64> = HashMap::new();
    if dt > 0.1 {
        for (pid, p1) in &snap1 {
            if is_probe_proc(*pid, &p1.name) {
                continue;
            }
            let Some(p0) = snap0.get(pid) else { continue };
            let dvctx = p1.vctx.saturating_sub(p0.vctx);
            let dnvctx = p1.nvctx.saturating_sub(p0.nvctx);
            let dticks = (p1.utime + p1.stime).saturating_sub(p0.utime + p0.stime);
            let vctx_per_s = dvctx as f64 / dt;
            let cpu_pct = (dticks as f64 / clk_tck) / dt * 100.0;
            vctx_rate_by_pid.insert(*pid, vctx_per_s);

            let pm = ps_meta.get(pid);
            let exe = pm.map(|m| m.exe.clone()).unwrap_or_default();
            let is_kthread = exe.is_empty() && p1.rss_kb == 0;
            let display = pm
                .map(|m| {
                    if !m.args.is_empty() && !m.args.starts_with('[') {
                        m.args.split_whitespace().next().unwrap_or(&m.name).to_string()
                    } else {
                        p1.name.clone()
                    }
                })
                .unwrap_or_else(|| p1.name.clone());

            if dvctx > 0 || dticks > 0 {
                proc_deltas.push(ProcDelta {
                    pid: *pid,
                    name: p1.name.clone(),
                    display,
                    exe,
                    is_kthread,
                    dvctx,
                    dnvctx,
                    dticks,
                    vctx_per_s,
                    cpu_pct,
                    rss_kb: p1.rss_kb,
                    swap_kb: p1.swap_kb,
                    threads: p1.threads,
                });
            }
        }
        proc_deltas.sort_by(|a, b| b.dvctx.cmp(&a.dvctx).then_with(|| b.dticks.cmp(&a.dticks)));
    }

    let mut snap = Snapshot {
        timestamp: epoch.clone(),
        device: device.clone(),
        build_id: build_id.clone(),
        uname: uname.clone(),
        uptime_s,
        window_s: dt,
        ..Default::default()
    };

    let mut gates: Vec<GateRow> = Vec::new();
    let top_n = opts.effective_top();

    if !opts.json {
        println!("========================================================================");
        println!(
            "YASVARA RUNTIME FORENSIC AUDIT  [{} | {} ({}) | up {:.0}m | win {:.1}s]",
            dev.serial,
            device,
            model,
            uptime_s / 60.0,
            dt
        );
        println!("  kernel: {} | build: {}", uname, trunc(&build_id, 55));
        println!("========================================================================");
    }

    // ---------------------------------------- [1] IDLE CPU & CTX-SWITCHES
    if opts.wants("cpu") {
        let user_deltas: Vec<&ProcDelta> = proc_deltas
            .iter()
            .filter(|d| !d.is_kthread && d.name != "adbd")
            .collect();
        let kern_deltas: Vec<&ProcDelta> = proc_deltas.iter().filter(|d| d.is_kthread).collect();
        let total_user_vctx_s: f64 = user_deltas.iter().map(|d| d.vctx_per_s).sum();
        let total_kern_vctx_s: f64 = kern_deltas.iter().map(|d| d.vctx_per_s).sum();
        let total_user_cpu: f64 = user_deltas.iter().map(|d| d.cpu_pct).sum();
        snap.idle_user_vctx_s = total_user_vctx_s;
        snap.kthread_vctx_s = total_kern_vctx_s;

        let hot_daemons: Vec<&&ProcDelta> = user_deltas
            .iter()
            .filter(|d| d.vctx_per_s >= 15.0 || d.cpu_pct >= 3.0)
            .collect();

        if !opts.json {
            println!("\n[1] Clean Idle CPU & Context Switches (window={:.2}s, zero dumpsys noise):", dt);
            if dt <= 0.1 {
                println!("  (skipped: --window 0)");
            } else {
                println!(
                    "  Userspace total (excl. adbd/probe): {:.1} vctx/s | {:.2}% CPU | {} hot (>=15 vctx/s)",
                    total_user_vctx_s,
                    total_user_cpu,
                    hot_daemons.len()
                );
                println!("  --- Top Userspace Idle Chatter ---");
                for d in user_deltas.iter().take(top_n) {
                    let flag = if d.vctx_per_s >= 15.0 || d.cpu_pct >= 3.0 { " [!]" } else { "" };
                    println!(
                        "    {:>6.1}/s vctx  {:>5.2}% cpu  pid={:<6} {:<34} R+S={:<7} thr={:<3}{}",
                        d.vctx_per_s,
                        d.cpu_pct,
                        d.pid,
                        trunc(&d.display, 34),
                        fmt_mb(d.rss_kb + d.swap_kb),
                        d.threads,
                        flag
                    );
                }
                println!("  --- Top Kernel Threads ---");
                for d in kern_deltas.iter().take(top_n.min(8)) {
                    println!(
                        "    {:>6.1}/s vctx  {:>5.2}% cpu  pid={:<6} {}",
                        d.vctx_per_s,
                        d.cpu_pct,
                        d.pid,
                        trunc(&d.name, 42)
                    );
                }
            }
        }

        let st = if dt <= 0.1 {
            GateStatus::Info
        } else if !hot_daemons.is_empty() {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        let hot_list = hot_daemons
            .iter()
            .take(4)
            .map(|d| format!("{}({:.0}/s)", d.name, d.vctx_per_s))
            .collect::<Vec<_>>()
            .join(", ");
        gates.push(GateRow {
            name: "idle_cpu",
            status: st,
            summary: if dt <= 0.1 {
                "window=0 (skipped)".into()
            } else if hot_daemons.is_empty() {
                format!("{:.1} user vctx/s, {:.2}% CPU (quiet)", total_user_vctx_s, total_user_cpu)
            } else {
                format!("{:.1} user vctx/s | hot: {}", total_user_vctx_s, hot_list)
            },
        });
    }

    // ---------------------------------------- [2] IRQ ACTIVITY & DT I2C ATTRIBUTION
    if opts.wants("irq") {
        let irqs0 = parse_interrupts(secs.get("T0_IRQS").map(|s| s.as_str()).unwrap_or(""));
        let irqs1 = if secs.contains_key("T1_IRQS") {
            parse_interrupts(secs.get("T1_IRQS").map(|s| s.as_str()).unwrap_or(""))
        } else {
            irqs0.clone()
        };
        let irq_sub = split_sub_blocks(secs.get("IRQ_META").map(|s| s.as_str()).unwrap_or(""));
        let irq_hw = parse_irq_hw(irq_sub.get("irq_hw").map(|s| s.as_str()).unwrap_or(""));
        let i2c_buses = parse_i2c_buses(irq_sub.get("i2c_bus").map(|s| s.as_str()).unwrap_or(""));
        let dt_map = load_dt_irq_map(&ctx.devicetrees);

        let mut rows: Vec<IrqRow> = Vec::new();
        for (id, (tot1, desc)) in &irqs1 {
            if matches!(id.as_str(), "IPI0" | "IPI1" | "IPI2" | "IPI3" | "IPI4" | "IPI5" | "IPI6" | "Err") {
                continue;
            }
            if desc.contains("arch_timer") {
                continue;
            }
            let tot0 = irqs0.get(id).map(|x| x.0).unwrap_or(*tot1);
            let delta = tot1.saturating_sub(tot0);
            let rate_s = if dt > 0.1 { delta as f64 / dt } else { 0.0 };
            let cum_rate_s = *tot1 as f64 / uptime_s.max(1.0);
            if delta == 0 && *tot1 < 1000 {
                continue;
            }
            let attr = resolve_irq_attr(id, &irq_hw, &dt_map, &i2c_buses);
            rows.push(IrqRow {
                irq_id: id.clone(),
                desc: desc.clone(),
                delta,
                rate_s,
                total: *tot1,
                cum_rate_s,
                attr,
            });
        }
        rows.sort_by(|a, b| {
            b.delta
                .cmp(&a.delta)
                .then_with(|| b.total.cmp(&a.total))
        });

        let total_irq_s: f64 = rows.iter().map(|r| r.rate_s).sum();
        snap.idle_irq_s = total_irq_s;
        let hot_irqs: Vec<&IrqRow> = rows
            .iter()
            .filter(|r| {
                r.rate_s >= 12.0
                    && !r.desc.contains("dwc3")
                    && !r.desc.contains("ipa")
                    && !r.desc.contains("gsi")
                    && !r.desc.contains("bwmon")
                    && !r.desc.contains("apps_rsc-drv")
                    && !r.desc.contains("ipcc_")
                    && !r.desc.contains("glink-native")
                    && !r.desc.contains("msm_drm")
                    && !r.desc.contains("hfi")
            })
            .collect();

        if !opts.json {
            println!("\n[2] Hardware IRQs (excl. arch_timer & IPIs; idle total={:.1}/s):", total_irq_s);
            for r in rows.iter().take(top_n) {
                let chip_info = if r.attr.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", r.attr)
                };
                println!(
                    "    IRQ {:<4} {:>6.1}/s (Δ{:<5})  cum={:<8} ({:>5.1}/s)  {}{}",
                    r.irq_id,
                    r.rate_s,
                    r.delta,
                    r.total,
                    r.cum_rate_s,
                    trunc(&r.desc, 34),
                    chip_info
                );
            }
            // Always show top cumulative i2c_geni IRQs if not in idle top
            let mut i2c_rows: Vec<&IrqRow> = rows.iter().filter(|r| r.desc.contains("i2c_geni")).collect();
            i2c_rows.sort_by(|a, b| b.total.cmp(&a.total));
            if !i2c_rows.is_empty() {
                println!("  --- I2C Bus Cumulative Breakdown ---");
                for r in i2c_rows.iter().take(6) {
                    println!(
                        "    IRQ {:<4} cum={:<8} ({:>5.1}/s) idle={:>4.1}/s  {}",
                        r.irq_id,
                        r.total,
                        r.cum_rate_s,
                        r.rate_s,
                        if r.attr.is_empty() { &r.desc } else { &r.attr }
                    );
                }
            }
        }

        let st = if !hot_irqs.is_empty() { GateStatus::Warn } else { GateStatus::Pass };
        gates.push(GateRow {
            name: "irqs",
            status: st,
            summary: if hot_irqs.is_empty() {
                format!("{:.1} non-timer IRQs/s idle (no unexpected IRQ storm)", total_irq_s)
            } else {
                let s = hot_irqs
                    .iter()
                    .take(3)
                    .map(|r| format!("IRQ{}({:.0}/s {})", r.irq_id, r.rate_s, if r.attr.is_empty() { &r.desc } else { &r.attr }))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{:.1} IRQs/s | hot: {s}", total_irq_s)
            },
        });
    }

    // ---------------------------------------- [3] POWER, SLEEP, WAKELOCKS & DOZE
    if opts.wants("power") {
        let w_sub = split_sub_blocks(secs.get("WAKEUPS").map(|s| s.as_str()).unwrap_or(""));
        let susp_kv = parse_kv(w_sub.get("suspend_stats").map(|s| s.as_str()).unwrap_or(""));
        let mem_sleep = w_sub.get("mem_sleep").map(|s| s.trim()).unwrap_or("?");
        let devidle = w_sub.get("deviceidle").map(|s| s.trim()).unwrap_or("");
        let power_wl_raw = w_sub.get("power_wakelocks").map(|s| s.as_str()).unwrap_or("");
        let sysfs_wakes = parse_wakeup_sources(w_sub.get("sysfs_wakeup").map(|s| s.as_str()).unwrap_or(""));

        let bat_ua: i64 = t1_meta
            .get("bat_uA")
            .or_else(|| t0_meta.get("bat_uA"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let bat_uv: i64 = t1_meta
            .get("bat_uV")
            .or_else(|| t0_meta.get("bat_uV"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let bat_status = t1_meta
            .get("bat_status")
            .or_else(|| t0_meta.get("bat_status"))
            .map(|s| s.as_str())
            .unwrap_or("?");
        let bat_cap = t0_meta.get("bat_cap").map(|s| s.as_str()).unwrap_or("?");
        let bat_temp_c = t0_meta.get("bat_temp").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0) / 10.0;
        let usb_online = t0_meta.get("usb_online").map(|s| s.as_str()).unwrap_or("0");
        let power_mw = (bat_ua.abs() as f64 / 1000.0) * (bat_uv as f64 / 1_000_000.0);

        // Parse CPU0 cpuidle residency
        let mut idle_states: Vec<(String, u64, u64)> = Vec::new();
        let mut total_idle_us = 0u64;
        for ln in w_sub.get("cpuidle").map(|s| s.as_str()).unwrap_or("").lines() {
            let p: Vec<&str> = ln.split('|').collect();
            if p.len() >= 4 {
                let nm = p[1].trim().to_string();
                let usg = p[2].trim().parse::<u64>().unwrap_or(0);
                let tm = p[3].trim().parse::<u64>().unwrap_or(0);
                total_idle_us += tm;
                idle_states.push((nm, usg, tm));
            }
        }
        let deep_c_pct = if total_idle_us > 0 {
            let deep_us: u64 = idle_states.iter().skip(1).map(|x| x.2).sum();
            deep_us as f64 / total_idle_us as f64 * 100.0
        } else {
            0.0
        };

        let active_wls: Vec<&str> = power_wl_raw
            .lines()
            .skip(1)
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();
        snap.active_wakelocks = active_wls.len();

        let susp_ok: u64 = susp_kv.get("success").and_then(|s| s.parse().ok()).unwrap_or(0);
        let susp_fail: u64 = susp_kv.get("fail").and_then(|s| s.parse().ok()).unwrap_or(0);

        if !opts.json {
            println!("\n[3] Power, Sleep, CPUIdle & Wakelocks:");
            println!(
                "  Battery: {}% ({}) | {:.1} mA @ {:.3}V ({:.0} mW) | {:.1}°C | usb_online={}",
                bat_cap,
                bat_status,
                bat_ua as f64 / 1000.0,
                bat_uv as f64 / 1_000_000.0,
                power_mw,
                bat_temp_c,
                usb_online
            );
            println!(
                "  Suspend: mode=[{}] ok={} fail={} | CPU0 deep-C={:.1}% ({})",
                mem_sleep,
                susp_ok,
                susp_fail,
                deep_c_pct,
                idle_states
                    .iter()
                    .map(|(n, u, t)| format!("{n}:{}({:.0}s)", u, *t as f64 / 1e6))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            if !devidle.is_empty() {
                let compact = devidle.lines().map(|l| l.trim()).collect::<Vec<_>>().join(" | ");
                println!("  Doze:    {}", trunc(&compact, 100));
            }
            println!("  Active Android WakeLocks ({}):", active_wls.len());
            for wl in active_wls.iter().take(if opts.full { 15 } else { 6 }) {
                println!("    {}", trunc(wl, 96));
            }
            println!("  --- Top Kernel Wakeup Sources (/sys/class/wakeup) ---");
            for ws in sysfs_wakes.iter().take(top_n.min(10)) {
                println!(
                    "    {:<44} total={:>7.1}s  prevent={:>6.1}s  ev={:<7} max={:>6}ms",
                    trunc(&ws.name, 44),
                    ws.total_ms as f64 / 1000.0,
                    ws.prevent_ms as f64 / 1000.0,
                    ws.events,
                    ws.max_ms
                );
            }
        }

        let st = if susp_fail > 0 {
            GateStatus::Warn
        } else {
            GateStatus::Info
        };
        gates.push(GateRow {
            name: "power",
            status: st,
            summary: format!(
                "{}% {} {:.0}mW | suspend ok={} fail={} | deep-C={:.0}% | {} active WLs",
                bat_cap, bat_status, power_mw, susp_ok, susp_fail, deep_c_pct, active_wls.len()
            ),
        });
    }

    // ---------------------------------------- [4] MEMORY, PERSISTENT, ADPF & KEY SERVICES
    let mem = if opts.wants("mem") || opts.wants("daemons") {
        parse_meminfo(secs.get("MEMINFO").map(|s| s.as_str()).unwrap_or(""))
    } else {
        MemSummary::default()
    };

    let pt_sub = split_sub_blocks(secs.get("POWER_THERM").map(|s| s.as_str()).unwrap_or(""));
    let mut adpf_sessions = 0usize;
    if let Some(phal) = pt_sub.get("power_hal") {
        adpf_sessions = phal.lines().filter(|l| l.contains("ID.Min.Act(")).count();
        if phal.contains("IsAdpfSupported: No") {
            snap.adpf_supported = Some(false);
        } else if phal.contains("IsAdpfSupported: Yes")
            || phal.contains("ADPF Tag Profile")
            || adpf_sessions > 0
        {
            snap.adpf_supported = Some(true);
        }
    }

    // Key Yasvara / thermal / retired services
    let find_service_stats = |pat: &str| -> Option<(u32, u64, u64, usize, f64)> {
        for (pid, m) in &ps_meta {
            if m.name.contains(pat) || m.exe.contains(pat) || m.args.contains(pat) {
                let s1 = snap1.get(pid);
                let rss = s1.map(|x| x.rss_kb).unwrap_or(0);
                let swp = s1.map(|x| x.swap_kb).unwrap_or(0);
                let vc = vctx_rate_by_pid.get(pid).copied().unwrap_or(0.0);
                return Some((*pid, rss, swp, m.fd_count, vc));
            }
        }
        None
    };

    let therm_st = find_service_stats("mi_thermal_engine");
    if let Some((_, rss, _, fds, vc)) = therm_st {
        snap.mi_thermal_fds = fds;
        snap.mi_thermal_rss_kb = rss;
        snap.mi_thermal_vctx_s = vc;
    }
    let padat_st = find_service_stats("padatd");
    if let Some((_, rss, _, _, _)) = padat_st {
        snap.padatd_rss_kb = rss;
    }
    let pantau_st = find_service_stats("pantaud");
    if let Some((_, rss, _, _, _)) = pantau_st {
        snap.pantaud_rss_kb = rss;
    }
    let ir_yas_st = find_service_stats("android.hardware.ir-service.yasvara");
    if let Some((_, rss, _, _, _)) = ir_yas_st {
        snap.ir_yasvara_rss_kb = rss;
    }

    let mut retired_procs: Vec<(u32, String, u64)> = Vec::new();
    for (pid, m) in &ps_meta {
        if is_retired_or_lineage(&m.name, &m.args) {
            let rs = snap1.get(pid).map(|x| x.rss_kb + x.swap_kb).unwrap_or(0);
            retired_procs.push((*pid, m.args.clone(), rs));
        }
    }
    retired_procs.sort_by(|a, b| b.2.cmp(&a.2));
    snap.lineage_proc_count = retired_procs.len();

    if opts.wants("mem") {
        let native_pss = mem.oom_totals_kb.get("Native").copied().unwrap_or(0);
        let pers_pss = mem.oom_totals_kb.get("Persistent").copied().unwrap_or(0)
            + mem.oom_totals_kb.get("Persistent Service").copied().unwrap_or(0);
        snap.used_ram_kb = mem.ds_used_ram_kb;
        snap.mem_avail_kb = mem.mem_avail_kb;
        snap.slab_recl_kb = mem.slab_recl_kb;
        snap.slab_unrecl_kb = mem.slab_unrecl_kb;
        snap.vmalloc_used_kb = mem.vmalloc_used_kb;
        snap.page_tables_kb = mem.page_tables_kb;
        snap.kernel_stack_kb = mem.kernel_stack_kb;
        snap.percpu_kb = mem.percpu_kb;
        snap.deferred_probes = mem.deferred_probes;
        snap.kmsg_splats = mem.kmsg_splats;
        snap.native_pss_kb = native_pss;
        snap.persistent_pss_kb = pers_pss;
        snap.persistent_count = mem.persistent_procs.len();
        let custom_pers: Vec<&(String, u32, u64)> = mem
            .persistent_procs
            .iter()
            .filter(|(n, _, _)| !is_core_aosp_persistent(n))
            .collect();
        snap.custom_pers_count = custom_pers.len();
        snap.zram_phys_kb = if mem.ds_zram_phys_kb > 0 { mem.ds_zram_phys_kb } else { mem.zram_mem_used_kb };
        snap.zram_swap_kb = if mem.ds_zram_swap_kb > 0 { mem.ds_zram_swap_kb } else { mem.zram_orig_kb };

        let zram_ratio = if snap.zram_phys_kb > 0 {
            snap.zram_swap_kb as f64 / snap.zram_phys_kb as f64
        } else {
            0.0
        };

        if !opts.json {
            println!("\n[4] Memory, Persistent Apps, ADPF & Yasvara Service Hygiene:");
            println!(
                "  RAM:  Total={} | Avail={} | Used={} | Lost={} | Slab={:.0}M recl / {:.0}M unrecl",
                fmt_mb(mem.mem_total_kb),
                fmt_mb(mem.mem_avail_kb),
                fmt_mb(mem.ds_used_ram_kb),
                fmt_mb(mem.ds_lost_ram_kb),
                mem.slab_recl_kb as f64 / 1024.0,
                mem.slab_unrecl_kb as f64 / 1024.0,
            );
            println!(
                "  KMEM: Vmalloc={:.0}M | PageTables={:.0}M | KStack={:.0}M | Percpu={:.0}M | deferred={} | splats={}",
                mem.vmalloc_used_kb as f64 / 1024.0,
                mem.page_tables_kb as f64 / 1024.0,
                mem.kernel_stack_kb as f64 / 1024.0,
                mem.percpu_kb as f64 / 1024.0,
                mem.deferred_probes,
                mem.kmsg_splats,
            );
            println!(
                "  ZRAM: {} phys -> {} swap ({:.2}x) | Native PSS={} | Persistent PSS={} ({} procs)",
                fmt_mb(snap.zram_phys_kb),
                fmt_mb(snap.zram_swap_kb),
                zram_ratio,
                fmt_mb(native_pss),
                fmt_mb(pers_pss),
                mem.persistent_procs.len(),
            );
            let adpf_lbl = match snap.adpf_supported {
                Some(true) if adpf_sessions > 0 => format!("Yes ({adpf_sessions} active sessions) [OK]"),
                Some(true) => "Yes [OK]".into(),
                Some(false) => "No [WARN]".into(),
                None => "unknown".into(),
            };
            println!(
                "  ADPF: {} | mi_thermal_engine: {} | padatd: {} | pantaud: {} | ir-yasvara: {}",
                adpf_lbl,
                therm_st
                    .map(|(_, r, _, f, v)| format!("RSS={} FDs={} {:.1}vctx/s", fmt_mb(r), f, v))
                    .unwrap_or_else(|| "NOT RUNNING".into()),
                padat_st.map(|(_, r, s, _, _)| format!("RUNNING({})", fmt_mb(r + s))).unwrap_or_else(|| "0K(lazy)".into()),
                pantau_st.map(|(_, r, s, _, _)| format!("RUNNING({})", fmt_mb(r + s))).unwrap_or_else(|| "0K(lazy)".into()),
                ir_yas_st.map(|(_, r, s, _, _)| format!("RUNNING({})", fmt_mb(r + s))).unwrap_or_else(|| "0K(lazy)".into()),
            );
            if !custom_pers.is_empty() {
                println!("  --- Non-Core *PERS* Apps ({}) ---", custom_pers.len());
                for (n, pid, kb) in &custom_pers {
                    println!("    {:<42} pid={:<6} PSS={}", trunc(n, 42), pid, fmt_mb(*kb));
                }
            }
            if !retired_procs.is_empty() {
                println!("  --- Retired Lineage / XiaomiParts Procs Still Running ({}) ---", retired_procs.len());
                for (pid, args, rs) in &retired_procs {
                    println!("    pid={:<6} R+S={:<7} {}", pid, fmt_mb(*rs), trunc(args, 68));
                }
            }
            if opts.full && !mem.top_slabs.is_empty() {
                println!("  --- Top Kernel Slabs ---");
                for (nm, bytes, objs) in mem.top_slabs.iter().take(8) {
                    println!("    {:<28} {:>7.1}M  ({} objs)", nm, *bytes as f64 / 1_048_576.0, objs);
                }
            }
        }

        let mut issues = Vec::new();
        if !retired_procs.is_empty() {
            issues.push(format!("{} retired Lineage/XiaomiParts procs", retired_procs.len()));
        }
        if snap.adpf_supported == Some(false) {
            issues.push("ADPF=No".into());
        }
        if snap.mi_thermal_fds > 60 {
            issues.push(format!("mi_thermal FDs={}", snap.mi_thermal_fds));
        }
        if !custom_pers.is_empty() {
            issues.push(format!("{} custom *PERS*", custom_pers.len()));
        }
        if mem.slab_unrecl_kb > 614_400 {
            issues.push(format!("SUnreclaim={:.0}M (>600M)", mem.slab_unrecl_kb as f64 / 1024.0));
        }
        if mem.vmalloc_used_kb > 524_288 {
            issues.push(format!("Vmalloc={:.0}M (>512M)", mem.vmalloc_used_kb as f64 / 1024.0));
        }
        if mem.deferred_probes > 0 {
            issues.push(format!("{} deferred probes", mem.deferred_probes));
        }
        if mem.kmsg_splats > 0 {
            issues.push(format!("{} kernel dmesg splats", mem.kmsg_splats));
        }
        let st = if !issues.is_empty() { GateStatus::Warn } else { GateStatus::Pass };
        gates.push(GateRow {
            name: "memory",
            status: st,
            summary: if issues.is_empty() {
                format!(
                    "Used={} Avail={} Pers={} ADPF=Yes",
                    fmt_mb(mem.ds_used_ram_kb),
                    fmt_mb(mem.mem_avail_kb),
                    fmt_mb(pers_pss)
                )
            } else {
                format!("Used={} | {}", fmt_mb(mem.ds_used_ram_kb), issues.join(", "))
            },
        });
    }

    // ---------------------------------------- [5] OPEN FDS & DMA-BUF LEAK HUNTER
    let (dmabufs, total_dmabuf_kb) = if opts.wants("dmabuf") || opts.wants("fd") {
        parse_dmabuf_dump(secs.get("DMABUF").map(|s| s.as_str()).unwrap_or(""))
    } else {
        (Vec::new(), 0)
    };
    snap.total_dmabuf_kb = total_dmabuf_kb;

    if opts.wants("fd") || opts.wants("dmabuf") {
        let fd_detail = parse_fd_detail(secs.get("FD_DETAIL").map(|s| s.as_str()).unwrap_or(""));
        let mut fd_ranked: Vec<(&u32, &PsMeta)> = ps_meta.iter().filter(|(_, m)| m.fd_count > 0).collect();
        fd_ranked.sort_by(|a, b| b.1.fd_count.cmp(&a.1.fd_count));

        // Capture Launcher3 specific metrics for baseline diffing
        for (pid, m) in &ps_meta {
            if m.args.contains("com.android.launcher3") && !m.args.contains(':') {
                snap.launcher3_fds = m.fd_count;
                if let Some(d) = dmabufs.iter().find(|x| x.pid == *pid) {
                    snap.launcher3_dmabuf_cnt = d.buf_count;
                    snap.launcher3_dmabuf_kb = d.total_pss_kb;
                }
            }
        }

        let mut leak_suspects: Vec<String> = Vec::new();
        for (pid, m) in fd_ranked.iter().take(12) {
            let lbl = m.args.split_whitespace().next().unwrap_or(&m.name);
            if lbl.contains("suspend-service") || m.name.contains("suspend") {
                continue;
            }
            let dmabuf_fds = fd_detail
                .get(pid)
                .map(|v| v.iter().filter(|(_, t)| t.contains("dmabuf")).map(|(c, _)| *c).sum::<usize>())
                .unwrap_or(0);
            let sync_fds = fd_detail
                .get(pid)
                .map(|v| v.iter().filter(|(_, t)| t.contains("sync_file")).map(|(c, _)| *c).sum::<usize>())
                .unwrap_or(0);
            let suspect = if lbl == "system_server" {
                m.fd_count >= 2500 || dmabuf_fds >= 250
            } else if lbl == "com.android.launcher3" {
                // Hardware-bitmap icons (2 dmabufs/icon) + high-end-gfx Recents cache normally hold ~350-450 dmabufs
                m.fd_count >= 950 || dmabuf_fds >= 550 || sync_fds >= 120
            } else {
                m.fd_count >= 800 || dmabuf_fds >= 250 || sync_fds >= 80
            };
            if suspect {
                leak_suspects.push(format!("{lbl}(fds={},dmabuf={},sync={})", m.fd_count, dmabuf_fds, sync_fds));
            }
        }

        if !opts.json {
            println!("\n[5] Open FDs & DMA-BUF Leak Hunter (total DMA-BUF PSS={}):", fmt_mb(total_dmabuf_kb));
            println!("  --- Top Open FD Holders ---");
            for (pid, m) in fd_ranked.iter().take(top_n.min(10)) {
                let lbl = m.args.split_whitespace().next().unwrap_or(&m.name);
                let benign = if lbl.contains("suspend-service") {
                    " [BENIGN: wakeup sysfs cache]"
                } else {
                    ""
                };
                let breakdown = fd_detail
                    .get(pid)
                    .map(|v| {
                        v.iter()
                            .take(4)
                            .map(|(c, t)| format!("{}x{}", c, trunc(t, 22)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                println!(
                    "    {:>4} FDs  pid={:<6} {:<32}{}  {}",
                    m.fd_count,
                    pid,
                    trunc(lbl, 32),
                    benign,
                    if benign.is_empty() && !breakdown.is_empty() {
                        format!("({breakdown})")
                    } else {
                        String::new()
                    }
                );
            }
            println!("  --- Top DMA-BUF Memory Holders (dmabuf_dump) ---");
            for d in dmabufs.iter().take(top_n.min(10)) {
                let full_name = ps_meta
                    .get(&d.pid)
                    .map(|m| m.args.split_whitespace().next().unwrap_or(&m.name).to_string())
                    .unwrap_or_else(|| d.name.clone());
                println!(
                    "    PSS={:<7} RSS={:<7} bufs={:<4} max_buf={:<7} pid={:<6} {}",
                    fmt_mb(d.total_pss_kb),
                    fmt_mb(d.total_rss_kb),
                    d.buf_count,
                    fmt_mb(d.max_buf_kb),
                    d.pid,
                    trunc(&full_name, 38)
                );
            }
        }

        let st = if !leak_suspects.is_empty() {
            GateStatus::Warn
        } else {
            GateStatus::Pass
        };
        gates.push(GateRow {
            name: "fd_dmabuf",
            status: st,
            summary: if leak_suspects.is_empty() {
                format!("total DMA-BUF={} (no FD/dmabuf leak anomalies)", fmt_mb(total_dmabuf_kb))
            } else {
                format!("suspects: {}", leak_suspects.join(", "))
            },
        });
    }

    // ---------------------------------------- [6] ALWAYS-ON VENDOR & ODM DAEMONS
    if opts.wants("daemons") {
        let mut daemons: Vec<VendorDaemon> = Vec::new();
        for (pid, m) in &ps_meta {
            let is_vendor_odm = m.exe.starts_with("/vendor/") || m.exe.starts_with("/odm/");
            if !is_vendor_odm {
                continue;
            }
            let Some(s1) = snap1.get(pid) else { continue };
            let cat = categorize_vendor_daemon(&m.exe, &m.name);
            daemons.push(VendorDaemon {
                pid: *pid,
                name: m.exe.rsplit('/').next().unwrap_or(&m.name).to_string(),
                exe: m.exe.clone(),
                category: cat,
                rss_kb: s1.rss_kb,
                swap_kb: s1.swap_kb,
                threads: s1.threads,
                fds: m.fd_count,
                cum_ticks: s1.utime + s1.stime,
                vctx_per_s: vctx_rate_by_pid.get(pid).copied().unwrap_or(0.0),
            });
        }
        daemons.sort_by(|a, b| (b.rss_kb + b.swap_kb).cmp(&(a.rss_kb + a.swap_kb)));
        let total_vnd_kb: u64 = daemons.iter().map(|d| d.rss_kb + d.swap_kb).sum();
        let total_vnd_thr: u32 = daemons.iter().map(|d| d.threads).sum();
        snap.vendor_daemon_count = daemons.len();
        snap.vendor_daemon_rss_swap_kb = total_vnd_kb;

        // Category rollup
        let mut cat_sum: BTreeMap<&'static str, (usize, u64, u32)> = BTreeMap::new();
        for d in &daemons {
            let e = cat_sum.entry(d.category).or_insert((0, 0, 0));
            e.0 += 1;
            e.1 += d.rss_kb + d.swap_kb;
            e.2 += d.threads;
        }
        let mut cat_ranked: Vec<(&'static str, usize, u64, u32)> = cat_sum
            .into_iter()
            .map(|(k, (c, kb, t))| (k, c, kb, t))
            .collect();
        cat_ranked.sort_by(|a, b| b.2.cmp(&a.2));

        if !opts.json {
            println!(
                "\n[6] Always-On Vendor/ODM Daemons ({} procs, total R+S={}, {} threads):",
                daemons.len(),
                fmt_mb(total_vnd_kb),
                total_vnd_thr
            );
            println!("  --- By Category ---");
            for (cat, cnt, kb, thr) in &cat_ranked {
                println!("    {:<18} {:>2} procs  R+S={:<7}  thr={}", cat, cnt, fmt_mb(*kb), thr);
            }
            println!("  --- Heaviest Vendor/ODM Daemons ---");
            for d in daemons.iter().take(top_n) {
                println!(
                    "    R+S={:<7} (RSS={:<6} Swp={:<6}) thr={:<3} fd={:<3} vctx={:>5.1}/s  ticks={:<5} {:<15} {}",
                    fmt_mb(d.rss_kb + d.swap_kb),
                    fmt_mb(d.rss_kb),
                    fmt_mb(d.swap_kb),
                    d.threads,
                    d.fds,
                    d.vctx_per_s,
                    d.cum_ticks,
                    d.category,
                    trunc(&d.name, 36)
                );
            }
            if opts.full {
                if let Some(wc) = pt_sub.get("hot_wchan") {
                    if !wc.trim().is_empty() {
                        println!("  --- Hot Daemon Thread Wchans ---");
                        for ln in wc.lines() {
                            println!("    {ln}");
                        }
                    }
                }
            }
        }

        gates.push(GateRow {
            name: "daemons",
            status: GateStatus::Info,
            summary: format!("{} vendor/odm procs, {} R+S, {} threads", daemons.len(), fmt_mb(total_vnd_kb), total_vnd_thr),
        });
    }

    // ---------------------------------------- [7] ALARMS & RUNNING JOBS
    if opts.wants("alarms") {
        let aj_sub = split_sub_blocks(secs.get("ALARMS_JOBS").map(|s| s.as_str()).unwrap_or(""));
        let alarms = parse_alarm_stats(aj_sub.get("alarms").map(|s| s.as_str()).unwrap_or(""));
        let jobs_raw = aj_sub.get("jobs").map(|s| s.trim()).unwrap_or("");
        let up_hr = (uptime_s / 3600.0).max(0.05);

        let noisy_alarms: Vec<&AlarmPkgStat> = alarms
            .iter()
            .filter(|a| !a.uid_pkg.starts_with("1000:") && (a.wakeups as f64 / up_hr) >= 15.0)
            .collect();

        if !opts.json {
            println!("\n[7] Alarm Wakeups & Running Jobs (uptime={:.2}h):", up_hr);
            for a in alarms.iter().take(top_n.min(10)) {
                println!(
                    "    {:>4} wakes ({:>5.1}/hr)  run={:>5}ms  {:<36} top={}",
                    a.wakeups,
                    a.wakeups as f64 / up_hr,
                    a.running_ms,
                    trunc(&a.uid_pkg, 36),
                    trunc(&a.top_tag, 42)
                );
            }
            let job_lines: Vec<&str> = jobs_raw.lines().filter(|l| l.contains("JOB #") || l.contains("Slot #")).collect();
            if !job_lines.is_empty() {
                println!("  --- Running Jobs ({}) ---", job_lines.len());
                for jl in job_lines.iter().take(6) {
                    println!("    {}", trunc(jl.trim(), 96));
                }
            }
        }

        let st = if !noisy_alarms.is_empty() { GateStatus::Warn } else { GateStatus::Pass };
        gates.push(GateRow {
            name: "alarms",
            status: st,
            summary: if noisy_alarms.is_empty() {
                format!("{} waking pkgs (no runaway app alarms)", alarms.len())
            } else {
                let s = noisy_alarms
                    .iter()
                    .take(3)
                    .map(|a| format!("{}({:.0}/hr)", a.uid_pkg, a.wakeups as f64 / up_hr))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("frequent app wakes: {s}")
            },
        });
    }

    // ---------------------------------------- [8] RUNTIME SELINUX AVCS
    if opts.wants("avc") {
        let avc_raw = secs.get("DMESG_AVC").map(|s| s.as_str()).unwrap_or("");
        let avcs = collect_avcs(avc_raw);
        let sys_avcs: Vec<_> = avcs.iter().filter(|a| a.bucket == AvcBucket::SystemHal).collect();
        let app_avcs: Vec<_> = avcs.iter().filter(|a| a.bucket == AvcBucket::UntrustedApp).collect();
        let sys_total: usize = sys_avcs.iter().map(|a| a.count).sum();
        snap.sys_avc_unique = sys_avcs.len();
        snap.sys_avc_total = sys_total;

        if !opts.json {
            println!(
                "\n[8] Runtime SELinux AVCs ({} System/HAL unique [{} hits], {} UntrustedApp unique):",
                sys_avcs.len(),
                sys_total,
                app_avcs.len()
            );
            for a in sys_avcs.iter().take(top_n) {
                println!(
                    "    [x{:<3}] {} -> {} ({}) {{ {} }} name={:?} comm={}",
                    a.count,
                    a.key.scontext,
                    a.key.tcontext,
                    a.key.tclass,
                    a.key.perms,
                    a.key.target_name,
                    a.sample_comm
                );
            }
        }

        let st = if !sys_avcs.is_empty() { GateStatus::Warn } else { GateStatus::Pass };
        gates.push(GateRow {
            name: "avc",
            status: st,
            summary: format!("{} System/HAL unique ({} hits), {} app", sys_avcs.len(), sys_total, app_avcs.len()),
        });
    }

    // ---------------------------------------- SAVE / DIFF / VERDICT
    if let Some(save_path) = &opts.save {
        if let Err(e) = fs::write(save_path, snap.to_json()) {
            eprintln!("warning: failed to write snapshot {}: {e}", save_path.display());
        } else if !opts.json {
            println!("\n[saved baseline snapshot -> {}]", save_path.display());
        }
    }

    if let Some(diff_path) = &opts.diff {
        match fs::read_to_string(diff_path).and_then(|t| {
            Snapshot::from_json(&t).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }) {
            Ok(before) => {
                if !opts.json {
                    print_snapshot_diff(&before, &snap);
                }
            }
            Err(e) => eprintln!("warning: failed to load diff baseline {}: {e}", diff_path.display()),
        }
    }

    let has_fail = gates.iter().any(|g| g.status == GateStatus::Fail);
    let has_warn = gates.iter().any(|g| g.status == GateStatus::Warn);
    let verdict = if has_fail {
        "FAIL"
    } else if has_warn {
        "WARN"
    } else {
        "PASS"
    };

    if opts.json {
        print!("{}", snap.to_json());
    } else {
        println!("\n========================================================================");
        println!("RUNTIME AUDIT VERDICT: {verdict}");
        println!("========================================================================");
        for g in &gates {
            println!("  [{:<4}] {:<10} {}", g.status.as_str(), g.name, g.summary);
        }
    }

    if has_fail { 1 } else { 0 }
}

// ====================================================== Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_status_and_stat() {
        let st = "1523|diag-router|1000|4|3900|4544|20316|2280\n1727|tftp_server|1000|1|3060|1636|19270|783\n";
        let mut m = parse_proc_status(st);
        merge_proc_stat(&mut m, "1523|120|317\n1727|40|108\n");
        let d = m.get(&1523).unwrap();
        assert_eq!(d.name, "diag-router");
        assert_eq!(d.rss_kb, 3900);
        assert_eq!(d.swap_kb, 4544);
        assert_eq!(d.vctx, 20316);
        assert_eq!(d.utime + d.stime, 437);
    }

    #[test]
    fn test_parse_interrupts_and_i2c_resolution() {
        let txt = "\
           CPU0       CPU1       CPU2       CPU3
328:      10000      12000       5000       6542     GICv3 617 Level     i2c_geni
";
        let irqs = parse_interrupts(txt);
        assert_eq!(irqs.get("328").unwrap().0, 33542);
        assert!(irqs.get("328").unwrap().1.contains("i2c_geni"));

        let hw = parse_irq_hw("328|GICv3|617|i2c_geni\n");
        let mut dt_map = HashMap::new();
        dt_map.insert(585u32, ("88c000".into(), "qupv3_se11_i2c".into()));
        let buses = parse_i2c_buses(
            "i2c-11|/sys/devices/platform/soc/8c0000.qcom,qupv3_2_geni_se/88c000.i2c/i2c-11|11-0055(bq27z561_master),11-006f(sc8581)\n",
        );
        let attr = resolve_irq_attr("328", &hw, &dt_map, &buses);
        assert_eq!(attr, "i2c-11: 11-0055(bq27z561_master),11-006f(sc8581)");
    }

    #[test]
    fn test_parse_dmabuf_dump() {
        let sample = "\
 vendor.xiaomi.s:2247
                  Name              Rss              Pss         nr_procs            Inode               Exporter
           qcom,system         10396 kB         10396 kB                1              218             qcom,system
           qcom,system            28 kB            28 kB                1              219             qcom,system
         PROCESS TOTAL         10424 kB         10424 kB
----------------------
 droid.launcher3:3815
           qcom,system         13920 kB         13920 kB                1             4156             qcom,system
           qcom,system           132 kB           132 kB                1              646             qcom,system
         PROCESS TOTAL         43484 kB         43484 kB
";
        let (procs, total) = parse_dmabuf_dump(sample);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 3815);
        assert_eq!(procs[0].total_pss_kb, 43484);
        assert_eq!(procs[0].max_buf_kb, 13920);
        assert_eq!(procs[1].pid, 2247);
        assert_eq!(procs[1].buf_count, 2);
        assert_eq!(total, 53908);
    }

    #[test]
    fn test_parse_alarm_stats_and_duration() {
        assert_eq!(parse_duration_ms("+1m2s345ms"), 62345);
        let sample = "\
  1000:android +621ms running, 13 wakeups:
    +51ms 4 wakes 4 alarms, last -7m30s756ms:
      *walarm*:com.android.server.audio.action.CHECK_MUSIC_ACTIVE
  u0a164:com.google.android.gms +246ms running, 24 wakeups:
    +134ms 20 wakes 20 alarms, last -1m59s669ms:
      *walarm*:NetworkLocationScanner
";
        let stats = parse_alarm_stats(sample);
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].uid_pkg, "u0a164:com.google.android.gms");
        assert_eq!(stats[0].wakeups, 24);
        assert_eq!(stats[0].top_tag, "*walarm*:NetworkLocationScanner");
    }

    #[test]
    fn test_snapshot_json_roundtrip() {
        let s = Snapshot {
            timestamp: "1763800000".into(),
            device: "onyx".into(),
            build_id: "Yasvara-17".into(),
            uptime_s: 2700.5,
            window_s: 5.0,
            adpf_supported: Some(true),
            used_ram_kb: 4_500_000,
            mi_thermal_fds: 25,
            launcher3_dmabuf_kb: 43484,
            sys_avc_unique: 1,
            ..Default::default()
        };
        let j = s.to_json();
        let parsed = Snapshot::from_json(&j).unwrap();
        assert_eq!(parsed.device, "onyx");
        assert_eq!(parsed.adpf_supported, Some(true));
        assert_eq!(parsed.used_ram_kb, 4_500_000);
        assert_eq!(parsed.mi_thermal_fds, 25);
        assert_eq!(parsed.launcher3_dmabuf_kb, 43484);
        assert_eq!(parsed.sys_avc_unique, 1);
    }
}
