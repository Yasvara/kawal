use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::abi;
use crate::util::*;

// ====================================================== 1. Delta Extractor & Classifier (6.6 -> 6.12)

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeltaBucket {
    XiaomiNew,
    QcomSoc,
    CorePatched,
}

/// Classify a file path changed between stock CLO base and HEAD.
pub fn classify_port_path(status: &str, path: &str) -> DeltaBucket {
    let low = path.to_ascii_lowercase();

    // 1. Platform-specific SM8750 (sun) / SM8735 (tuna) drivers, module lists, configs
    let is_sun_tuna_soc = (low.contains("sun") || low.contains("tuna"))
        && !low.contains("sunxi")
        && !low.contains("sunrpc")
        && !low.contains("sunplus")
        && !low.contains("samsung")
        && !low.contains("sundance")
        && !low.contains("sungem")
        && !low.contains("sunhme")
        && !low.contains("sunbmac")
        && !low.contains("sunvnet")
        && !low.contains("sunqe")
        && !low.contains("suni")
        && !low.contains("sunkbd")
        && !low.contains("sunvdc")
        && !low.contains("sunrise")
        && !low.contains("tsunami")
        && !low.contains("suncore")
        && !low.contains("sunsab")
        && !low.contains("sunsu")
        && !low.contains("sunzilog")
        && !low.contains("sun_esp")
        && !low.contains("sunbpp")
        && !low.contains("sunfire")
        && !low.contains("sunlance")
        && !low.contains("sun_uflash")
        && !low.contains("sunrisepoint")
        && !low.contains("allwinner")
        && !low.contains("rockchip")
        && !low.contains("sparc")
        && !low.contains("arch/m68k/")
        && !low.contains("block/partitions/sun.c")
        && (low.starts_with("drivers/clk/qcom/")
            || low.starts_with("drivers/pinctrl/qcom/")
            || low.starts_with("drivers/interconnect/qcom/")
            || low.starts_with("drivers/phy/qualcomm/")
            || low.starts_with("arch/arm64/configs/vendor/")
            || low.starts_with("modules.list.msm.")
            || low.starts_with("modules.vendor_blocklist.msm.")
            || low.starts_with("build.config.msm."));

    if is_sun_tuna_soc {
        return DeltaBucket::QcomSoc;
    }

    // 2. Xiaomi / Onyx / Yasvara brand-new files or dedicated directories
    let is_xiaomi_dir = path.starts_with("drivers/power/supply/mca/")
        || path.starts_with("drivers/input/fingerprint/mi_fp/")
        || path.starts_with("drivers/misc/hwid/")
        || path.starts_with("drivers/misc/miev/")
        || path.starts_with("drivers/xiaomi/")
        || path.starts_with("drivers/thermal/xiaomi/")
        || path.starts_with("include/linux/mca/")
        || path.starts_with("include/miev/")
        || path.starts_with("include/mi_ubt/")
        || path == "arch/arm64/configs/vendor/onyx_perf.config"
        || path == "drivers/gpio/gpio-mi-t1.c"
        || path.starts_with("drivers/leds/leds-awrgb21024")
        || path.starts_with("drivers/input/misc/si_haptic/")
        || path.starts_with("drivers/input/misc/aw8697")
        || path.starts_with("drivers/input/misc/haptic")
        || path == "include/linux/yasvara_hide.h"
        || path == "include/linux/wrapfd.h"
        || path == "drivers/android/wrapfd.c"
        || path == "net/ipv4/tcp_bbr3.c"
        || low.contains("onyx");

    if is_xiaomi_dir || (status == "A" && (low.contains("xiaomi") || low.contains("yasvara") || low.contains("mi_"))) {
        return DeltaBucket::XiaomiNew;
    }

    DeltaBucket::CorePatched
}

fn auto_detect_clo_base(ctx: &Ctx) -> Option<String> {
    for candidate in [
        "refs/remotes/codelinaro-qcom/kernel.lnx.6.6.r16-rel",
        "refs/remotes/codelinaro-qcom/kernel.lnx.6.6.r15-rel",
        "refs/remotes/codelinaro-qcom/kernel.lnx.6.6.r14-rel",
        "refs/remotes/codelinaro-qcom/kernel.lnx.6.6.r12-rel",
        "refs/remotes/codelinaro-qcom/kernel.lnx.6.6.r1-rel",
        "refs/remotes/clo/kernel.lnx.6.6.r16-rel",
    ] {
        let (rc, _, _) = git_rc(ctx, &["rev-parse", "--verify", "--quiet", candidate]);
        if rc == 0 {
            return Some(candidate.to_string());
        }
    }
    None
}

fn auto_detect_latest_stable_tag(ctx: &Ctx) -> Option<String> {
    let out = git(ctx, &["tag", "-l", "v6.6.*"]);
    let mut best: Option<(u64, String)> = None;
    for ln in out.lines() {
        let t = ln.trim();
        if let Some(sub) = t.strip_prefix("v6.6.").and_then(|s| s.parse::<u64>().ok()) {
            if best.as_ref().map_or(true, |(b, _)| sub > *b) {
                best = Some((sub, t.to_string()));
            }
        }
    }
    best.map(|(_, t)| t)
}

fn ls_tree_blob_map(repo: &Path, rev: &str) -> HashMap<String, String> {
    let out = git_in(repo, &["ls-tree", "-r", rev]);
    let mut map = HashMap::with_capacity(90_000);
    for ln in out.lines() {
        let Some((meta, path)) = ln.split_once('\t') else { continue };
        let mut it = meta.split_whitespace();
        let _mode = it.next();
        let kind = it.next();
        let sha = it.next();
        if kind == Some("blob") {
            if let Some(s) = sha {
                map.insert(path.to_string(), s.to_string());
            }
        }
    }
    map
}

fn target_has_path(ctx: &Ctx, target: &str, target_blobs: Option<&HashMap<String, String>>, path: &str) -> bool {
    if let Some(map) = target_blobs {
        map.contains_key(path)
    } else {
        Path::new(target).join(path).exists() || ctx.ws_root.join(target).join(path).exists()
    }
}

pub fn cmd_port_delta(
    ctx: &Ctx,
    base_opt: Option<&str>,
    head: &str,
    target_opt: Option<&str>,
    show_all: bool,
) -> i32 {
    let base = match base_opt {
        Some(b) => b.to_string(),
        None => match auto_detect_clo_base(ctx) {
            Some(b) => b,
            None => {
                eprintln!("!! cannot auto-detect CLO 6.6 base ref; pass --base <ref>");
                return 2;
            }
        },
    };
    let stable_tag = auto_detect_latest_stable_tag(ctx);

    println!("==========================================================================================");
    println!("ktool port delta: {} -> {}", base, head);
    if let Some(ref st) = stable_tag {
        println!("  stable filter : {st} (files byte-identical to {st} are marked STABLE-SUBSUMED)");
    }
    if let Some(t) = target_opt {
        println!("  6.12 target   : {t}");
    }
    println!("==========================================================================================");

    let ns = git(ctx, &["diff", "--name-status", &base, head]);
    let head_blobs = ls_tree_blob_map(&ctx.repo, head);
    let stable_blobs = stable_tag.as_deref().map(|st| ls_tree_blob_map(&ctx.repo, st));

    // If target is a git ref in ctx.repo, load its blob map; otherwise treat as filesystem directory
    let target_blobs: Option<HashMap<String, String>> = target_opt.and_then(|t| {
        if Path::new(t).is_dir() || ctx.ws_root.join(t).is_dir() {
            None
        } else {
            let (rc, _, _) = git_rc(ctx, &["rev-parse", "--verify", "--quiet", t]);
            if rc == 0 {
                Some(ls_tree_blob_map(&ctx.repo, t))
            } else {
                None
            }
        }
    });

    let mut xiaomi_files: Vec<(String, String)> = Vec::new();
    let mut soc_files: Vec<(String, String)> = Vec::new();
    let mut core_files: Vec<(String, String)> = Vec::new();
    let mut subsumed_count = 0usize;
    let mut ignored_non_arm_count = 0usize;

    for ln in ns.lines() {
        let mut parts = ln.split('\t');
        let Some(raw_st) = parts.next() else { continue };
        let st = raw_st.chars().next().map(|c| c.to_string()).unwrap_or_default();
        let path = match st.as_str() {
            "R" | "C" => match parts.nth(1) {
                Some(p) => p,
                None => continue,
            },
            _ => match parts.next() {
                Some(p) => p,
                None => continue,
            },
        };

        if IGNORED_PREFIXES.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        // Check if file is byte-identical to latest Linux 6.6 stable tag (subsumed by 6.12!)
        if let Some(ref sb) = stable_blobs {
            if let (Some(hb), Some(stb)) = (head_blobs.get(path), sb.get(path)) {
                if hb == stb {
                    subsumed_count += 1;
                    continue;
                }
            }
            // Deleted in HEAD and also absent in stable tag
            if st == "D" && !sb.contains_key(path) {
                subsumed_count += 1;
                continue;
            }
        }

        // Skip clearly non-arm64 arch churn from stable merges unless --all
        if !show_all
            && (path.starts_with("arch/") && !path.starts_with("arch/arm64/"))
        {
            ignored_non_arm_count += 1;
            continue;
        }

        match classify_port_path(&st, path) {
            DeltaBucket::XiaomiNew => xiaomi_files.push((st, path.to_string())),
            DeltaBucket::QcomSoc => soc_files.push((st, path.to_string())),
            DeltaBucket::CorePatched => core_files.push((st, path.to_string())),
        }
    }

    // Group Xiaomi/Yasvara files by top-3 directory prefix
    let mut xiaomi_dirs: BTreeMap<String, usize> = BTreeMap::new();
    for (_, p) in &xiaomi_files {
        let segs: Vec<&str> = p.split('/').collect();
        let key = if segs.len() >= 4 {
            format!("{}/{}/{}/{}", segs[0], segs[1], segs[2], segs[3])
        } else if segs.len() >= 3 {
            format!("{}/{}/{}", segs[0], segs[1], segs[2])
        } else {
            p.clone()
        };
        *xiaomi_dirs.entry(key).or_default() += 1;
    }

    // Group CorePatched files by top-2 directory prefix
    let mut core_dirs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (st, p) in &core_files {
        let segs: Vec<&str> = p.split('/').collect();
        let key = if segs.len() >= 2 {
            format!("{}/{}", segs[0], segs[1])
        } else {
            p.clone()
        };
        core_dirs.entry(key).or_default().push((st.clone(), p.clone()));
    }

    println!("\nSummary:");
    println!("  STABLE-SUBSUMED (auto-superseded by 6.12) : {:>5} files", subsumed_count);
    if ignored_non_arm_count > 0 {
        println!("  NON-ARM64 ARCH (skipped; --all to show)   : {:>5} files", ignored_non_arm_count);
    }
    println!("  XIAOMI/YASVARA-NEW (copy + adapt to 6.12) : {:>5} files", xiaomi_files.len());
    println!("  QCOM-SOC (sun/tuna platform drivers/cfgs) : {:>5} files", soc_files.len());
    println!("  CORE-PATCHED (audit & forward-port)       : {:>5} files", core_files.len());

    println!("\n[1] XIAOMI/YASVARA-NEW directories ({} files):", xiaomi_files.len());
    for (dir, cnt) in &xiaomi_dirs {
        println!("  {:>4}  {dir}", cnt);
    }

    println!("\n[2] QCOM-SOC (sun/tuna) files ({} files):", soc_files.len());
    let mut missing_soc = 0usize;
    for (st, p) in &soc_files {
        let tgt_note = match target_opt {
            Some(t) => {
                if target_has_path(ctx, t, target_blobs.as_ref(), p) {
                    " [EXISTS-IN-TARGET]"
                } else {
                    missing_soc += 1;
                    " [MISSING-IN-TARGET!]"
                }
            }
            None => "",
        };
        println!("  [{st}] {p}{tgt_note}");
    }
    if target_opt.is_some() {
        println!("  -> sun/tuna target parity: {} missing / {} total", missing_soc, soc_files.len());
    }

    println!("\n[3] CORE-PATCHED subsystems ({} files across {} dirs):", core_files.len(), core_dirs.len());
    let mut ranked: Vec<(&String, &Vec<(String, String)>)> = core_dirs.iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
    for (dir, list) in ranked.iter().take(if show_all { 200 } else { 35 }) {
        let built_cnt = list.iter().filter(|(_, p)| is_built_file(ctx, p)).count();
        println!("  {:>4} ({:>3} built)  {dir}", list.len(), built_cnt);
        if show_all || list.len() <= 5 {
            for (st, p) in list.iter().take(if show_all { 500 } else { 5 }) {
                let btag = if is_built_file(ctx, p) { "BUILT" } else { "unbuilt" };
                println!("         [{st}][{btag}] {p}");
            }
        }
    }
    if !show_all && ranked.len() > 35 {
        println!("  ... (+{} more dirs; pass --all for full listing)", ranked.len() - 35);
    }
    0
}

// ====================================================== 2. Breaking Kernel API Scanner (6.6 -> 6.12 / 6.18)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSev {
    Error,
    Warn,
}

#[derive(Debug, Clone)]
pub struct ApiRule {
    pub id: &'static str,
    pub min_target_minor: u32, // 12 for 6.12, 18 for 6.18
    pub sev: ApiSev,
    pub pattern: &'static str, // ripgrep regex
    pub since: &'static str,
    pub fix_hint: &'static str,
}

const API_RULES: &[ApiRule] = &[
    // --- 6.7 .. 6.12 breaking kernel APIs ---
    ApiRule {
        id: "E608-strlcpy",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bstrlcpy\s*\(",
        since: "6.8",
        fix_hint: "removed in 6.8 -> replace with strscpy()",
    },
    ApiRule {
        id: "E608-eventfd-2arg",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\beventfd_signal\s*\([^,)]+,",
        since: "6.8",
        fix_hint: "2-arg eventfd_signal(ctx, n) removed in 6.8 -> eventfd_signal(ctx)",
    },
    ApiRule {
        id: "E609-sysctl-table",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bregister_sysctl_table\s*\(",
        since: "6.9",
        fix_hint: "removed in 6.9 -> use register_sysctl(path, table) without .child/sentinel",
    },
    ApiRule {
        id: "E609-blkdev-open",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\b(blkdev_get_by_path|blkdev_get_by_dev|blkdev_put)\s*\(",
        since: "6.9",
        fix_hint: "removed in 6.9 -> bdev_file_open_by_path() / bdev_file_open_by_dev() + fput()",
    },
    ApiRule {
        id: "E609-blk-mq-alloc-disk",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bblk_mq_alloc_disk\s*\([^,)]+,\s*[^,)]+\)",
        since: "6.9",
        fix_hint: "6.9 changed blk_mq_alloc_disk(set, lim, queuedata) to take struct queue_limits *",
    },
    ApiRule {
        id: "E610-thermal-reg",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bthermal_zone_device_register\s*\(",
        since: "6.10",
        fix_hint: "removed/replaced -> thermal_zone_device_register_with_trips()",
    },
    ApiRule {
        id: "E610-thermal-trip",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\b(thermal_zone_get_trip|get_trip_temp|get_trip_type|get_trip_hyst)\b",
        since: "6.9",
        fix_hint: "thermal trip ops removed in 6.9-6.11 -> pass static struct thermal_trip array + for_each_thermal_trip()",
    },
    ApiRule {
        id: "E610-dummy-netdev-ret",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"(=|if\s*\(|return\s+)\s*init_dummy_netdev\s*\(",
        since: "6.10",
        fix_hint: "init_dummy_netdev() returns void in 6.10+",
    },
    ApiRule {
        id: "E611-plat-remove-new",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\.remove_new\s*=",
        since: "6.11",
        fix_hint: ".remove_new removed in 6.11/6.12 -> rename to .remove (returns void)",
    },
    ApiRule {
        id: "E611-plat-remove-int",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bint\s+[a-zA-Z0-9_]*remove[a-zA-Z0-9_]*\s*\(\s*struct\s+(platform_device|i2c_client|spi_device)\s*\*",
        since: "6.11",
        fix_hint: "platform/i2c/spi .remove callback returns void in 6.11+",
    },
    ApiRule {
        id: "E611-of-gpio-flags",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bof_get_named_gpio_flags\s*\(",
        since: "6.11",
        fix_hint: "removed in 6.11 -> of_get_named_gpio() or devm_gpiod_get()",
    },
    ApiRule {
        id: "E611-class-create-2arg",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bclass_create\s*\(\s*THIS_MODULE\s*,",
        since: "6.4",
        fix_hint: "class_create(name) takes 1 argument (drop THIS_MODULE)",
    },
    ApiRule {
        id: "E611-class-nonconst-dev",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"\.(devnode|uevent)\s*=\s*[a-zA-Z0-9_]+",
        since: "6.10",
        fix_hint: "verify callback takes `const struct device *` (constified in 6.2-6.11)",
    },
    ApiRule {
        id: "E612-no-llseek",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\bno_llseek\b",
        since: "6.12",
        fix_hint: "no_llseek removed in 6.12 -> remove .llseek (default is non-seekable) or use noop_llseek",
    },
    ApiRule {
        id: "E612-i2c-probe-new",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\.probe_new\s*=",
        since: "6.6",
        fix_hint: ".probe_new removed -> use .probe with 1-arg i2c_client",
    },
    ApiRule {
        id: "E612-vm-flags-direct",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"->vm_flags\s*(\|=|&=|=[^=])",
        since: "6.8",
        fix_hint: "vma->vm_flags is const -> use vm_flags_set() / vm_flags_clear() / vm_flags_init()",
    },
    ApiRule {
        id: "E612-drm-output-poll",
        min_target_minor: 12,
        sev: ApiSev::Error,
        pattern: r"\.output_poll_changed\s*=",
        since: "6.12",
        fix_hint: "drm_mode_config_funcs.output_poll_changed removed in 6.12 -> drm_client_dev_hotplug()",
    },
    ApiRule {
        id: "E612-vma-vm-file-swap",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"->vm_file\s*=",
        since: "6.12",
        fix_hint: "direct vma->vm_file swap -> use vma_set_file(vma, file) in 6.12+",
    },
    ApiRule {
        id: "W612-drm-fop-unsigned-off",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"\.open\s*=\s*drm_open\b",
        since: "6.12",
        fix_hint: "6.12 drm_open_helper rejects open() with -EINVAL unless .fop_flags = FOP_UNSIGNED_OFFSET is set",
    },
    ApiRule {
        id: "W612-iommu-dma-addr-pool",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"qcom,iommu-dma-addr-pool",
        since: "6.12",
        fix_hint: "6.12 qcom-iommu-util drops legacy qcom,iommu-dma-addr-pool unless compat fallback or iommu-addresses DT migration is present",
    },
    ApiRule {
        id: "E612-of-property-count",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"\b(get_user_pages_remote|pin_user_pages_remote)\s*\(",
        since: "6.9",
        fix_hint: "verify vmas parameter removed in 6.5+/6.9+",
    },
    ApiRule {
        id: "E612-power-supply-desc",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"\bpower_supply_get_drvdata\s*\(|\bpower_supply_register\s*\(",
        since: "6.12",
        fix_hint: "audit struct power_supply_desc / no_thermal / property enum changes in 6.12",
    },
    ApiRule {
        id: "E612-snd-soc-dai",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"\bsnd_soc_rtd_to_cpu\b|\bsnd_soc_dai_set_channel_map\b|\.legacy_dai_naming\b",
        since: "6.12",
        fix_hint: "verify ASoC 6.12 DAI / topology / component API updates",
    },
    ApiRule {
        id: "W612-vendor-hook",
        min_target_minor: 12,
        sev: ApiSev::Warn,
        pattern: r"\bregister_trace_android_r?vh_[a-zA-Z0-9_]+\s*\(",
        since: "6.12",
        fix_hint: "Android vendor hook -> verify hook exists & signature matches 6.12 include/trace/hooks/",
    },
    // --- 6.13 .. 6.18 breaking kernel APIs (enabled with --target 6.18) ---
    ApiRule {
        id: "E613-import-ns",
        min_target_minor: 18,
        sev: ApiSev::Error,
        pattern: r#"MODULE_IMPORT_NS\s*\(\s*[A-Za-z_]"#,
        since: "6.13",
        fix_hint: "6.13+ requires quoted string literal: MODULE_IMPORT_NS(\"NS\")",
    },
    ApiRule {
        id: "E615-del-timer",
        min_target_minor: 18,
        sev: ApiSev::Error,
        pattern: r"\b(del_timer|del_timer_sync)\s*\(",
        since: "6.15",
        fix_hint: "removed in 6.15 -> timer_delete() / timer_delete_sync()",
    },
    ApiRule {
        id: "E616-from-timer",
        min_target_minor: 18,
        sev: ApiSev::Error,
        pattern: r"\bfrom_timer\s*\(",
        since: "6.16",
        fix_hint: "removed in 6.16 -> timer_container_of()",
    },
];

/// Check if line `lno_1b` inside `content` is guarded by a `< KERNEL_VERSION(6, X, ...)`
/// preprocessor branch that will be compiled OUT on `target_minor` (e.g. 12).
pub fn is_guarded_for_older_kernel(lines: &[&str], lno_1b: usize, target_minor: u32) -> bool {
    let idx = lno_1b.saturating_sub(1);
    let start = idx.saturating_sub(25);
    let mut depth = 0i32;
    let mut in_else = false;

    for j in (start..idx).rev() {
        let t = lines[j].trim();
        if t.starts_with("#endif") {
            depth += 1;
            continue;
        }
        if t.starts_with("#else") && depth == 0 {
            in_else = true;
            continue;
        }
        if t.starts_with("#if") {
            if depth > 0 {
                depth -= 1;
                continue;
            }
            if t.contains("KERNEL_VERSION") {
                // e.g. `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)` -> inactive on 6.12 if !in_else
                // e.g. `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)` -> inactive on 6.12 if in_else!
                if let Some((maj, min)) = parse_kernel_version_macro(t) {
                    if maj == 6 && min <= target_minor {
                        let is_lt = t.contains('<') && !t.contains(">=");
                        let is_ge = t.contains(">=");
                        if is_lt && !in_else {
                            return true;
                        }
                        if is_ge && in_else {
                            return true;
                        }
                    }
                }
            }
            // Only inspect the innermost enclosing #if
            if !in_else {
                break;
            }
            in_else = false;
        }
    }
    false
}

fn parse_kernel_version_macro(line: &str) -> Option<(u32, u32)> {
    let pos = line.find("KERNEL_VERSION(")?;
    let rest = &line[pos + "KERNEL_VERSION(".len()..];
    let end = rest.find(')')?;
    let mut parts = rest[..end].split(',').map(|s| s.trim());
    let maj = parts.next()?.parse::<u32>().ok()?;
    let min = parts.next()?.parse::<u32>().ok()?;
    Some((maj, min))
}

#[derive(Debug, Clone)]
struct ApiHit {
    rule_id: &'static str,
    sev: ApiSev,
    since: &'static str,
    fix_hint: &'static str,
    scope: String, // e.g. "kernel:mca" or "modules:camera-kernel"
    file: String,
    line: usize,
    snippet: String,
}

fn scope_label(is_module: bool, rel_path: &str) -> String {
    let segs: Vec<&str> = rel_path.split('/').collect();
    if is_module {
        if segs.len() >= 3 && segs[0] == "qcom" && segs[1] == "opensource" {
            return format!("mod:{}", segs[2]);
        }
        if !segs.is_empty() {
            return format!("mod:{}", segs[0]);
        }
        return "mod:root".to_string();
    }
    if rel_path.starts_with("drivers/power/supply/mca/") {
        return "kern:mca".to_string();
    }
    if rel_path.starts_with("drivers/input/fingerprint/mi_fp/") {
        return "kern:mi_fp".to_string();
    }
    if rel_path.starts_with("drivers/xiaomi/") {
        return "kern:xiaomi".to_string();
    }
    if segs.len() >= 3 {
        format!("kern:{}/{}/{}", segs[0], segs[1], segs[2])
    } else {
        format!("kern:{rel_path}")
    }
}

fn scan_roots_for_apis(
    roots: &[(bool, PathBuf, String)], // (is_module, abs_dir, rel_prefix)
    target_minor: u32,
    threads: usize,
) -> Vec<ApiHit> {
    let active_rules: Vec<&ApiRule> = API_RULES
        .iter()
        .filter(|r| r.min_target_minor <= target_minor)
        .collect();

    // Run each rule in parallel across roots using rg
    let tasks: Vec<(&ApiRule, bool, PathBuf, String)> = active_rules
        .iter()
        .flat_map(|rule| {
            roots
                .iter()
                .map(move |(is_mod, dir, pref)| (*rule, *is_mod, dir.clone(), pref.clone()))
        })
        .collect();

    let per_task: Vec<Vec<ApiHit>> = par_map(&tasks, threads, |(rule, is_mod, dir, pref)| {
        let mut hits = Vec::new();
        if !dir.exists() {
            return hits;
        }
        let (_, out) = rg(
            dir,
            &["-n", "--no-heading", "-g", "*.c", "-g", "*.h", rule.pattern, "."],
        );
        if out.is_empty() {
            return hits;
        }
        // Cache read files per task to check preprocessor version guards
        let mut file_cache: HashMap<String, String> = HashMap::new();
        for ln in out.lines() {
            let mut parts = ln.splitn(3, ':');
            let Some(raw_f) = parts.next() else { continue };
            let Some(lno_s) = parts.next() else { continue };
            let Some(text) = parts.next() else { continue };
            let Ok(lno) = lno_s.parse::<usize>() else { continue };

            // Skip single-line comments
            let trim = text.trim();
            if trim.starts_with("//") || trim.starts_with("/*") || trim.starts_with('*') {
                continue;
            }
            let rel_local = raw_f.strip_prefix("./").unwrap_or(raw_f);
            let full_path = if dir.is_file() {
                dir.clone()
            } else {
                dir.join(rel_local)
            };
            let rel_display = if pref.is_empty() {
                rel_local.to_string()
            } else if dir.is_file() {
                pref.clone()
            } else {
                format!("{pref}/{rel_local}")
            };

            let content = file_cache
                .entry(full_path.to_string_lossy().into_owned())
                .or_insert_with(|| fs::read_to_string(&full_path).unwrap_or_default());
            let clines: Vec<&str> = content.lines().collect();
            if is_guarded_for_older_kernel(&clines, lno, target_minor) {
                continue;
            }

            hits.push(ApiHit {
                rule_id: rule.id,
                sev: rule.sev,
                since: rule.since,
                fix_hint: rule.fix_hint,
                scope: scope_label(*is_mod, &rel_display),
                file: rel_display,
                line: lno,
                snippet: truncate_str(trim, 90).to_string(),
            });
        }
        hits
    });

    per_task.into_iter().flatten().collect()
}

fn scan_module_version_highwater(modules_dir: &Path) -> BTreeMap<String, (u32, u32, usize)> {
    let mut out_map: BTreeMap<String, (u32, u32, usize)> = BTreeMap::new();
    let (_, raw) = rg(
        modules_dir,
        &["-n", "--no-heading", "-g", "*.c", "-g", "*.h", r"KERNEL_VERSION\(\s*6,\s*[0-9]+,"],
    );
    for ln in raw.lines() {
        let mut parts = ln.splitn(3, ':');
        let Some(f) = parts.next() else { continue };
        let _lno = parts.next();
        let Some(code) = parts.next() else { continue };
        let mod_name = scope_label(true, f);
        if let Some((maj, min)) = parse_kernel_version_macro(code) {
            let ent = out_map.entry(mod_name).or_insert((0, 0, 0));
            if (maj, min) > (ent.0, ent.1) {
                ent.0 = maj;
                ent.1 = min;
            }
            ent.2 += 1;
        }
    }
    out_map
}

pub fn cmd_port_api_scan(
    ctx: &Ctx,
    target: &str,
    scope: &str,
    detail: bool,
    guards_only: bool,
) -> i32 {
    let target_minor: u32 = match target {
        "6.12" | "12" | "5.0" => 12,
        "6.18" | "18" | "6.0" => 18,
        other => {
            eprintln!("unsupported --target `{other}` (use 6.12 or 6.18)");
            return 2;
        }
    };

    println!("==========================================================================================");
    println!(
        "ktool port api-scan: Linux 6.6 -> 6.{target_minor} breaking-API audit (scope={scope}{})",
        if guards_only { ", guards-only" } else { "" }
    );
    println!("==========================================================================================");

    let mut err_cnt = 0usize;
    if !guards_only {
    let mut roots: Vec<(bool, PathBuf, String)> = Vec::new();
    if scope == "all" || scope == "kernel" {
        let custom_kernel_paths = [
            "drivers/power/supply/mca",
            "drivers/input/fingerprint/mi_fp",
            "drivers/input/misc/si_haptic",
            "drivers/input/misc/aw8697",
            "drivers/misc/hwid",
            "drivers/misc/miev",
            "drivers/xiaomi",
            "drivers/thermal/xiaomi",
            "drivers/gpio/gpio-mi-t1.c",
            "drivers/leds/leds-awrgb21024.c",
            "drivers/android/wrapfd.c",
            "net/ipv4/tcp_bbr3.c",
        ];
        for p in custom_kernel_paths {
            let full = ctx.repo.join(p);
            if full.exists() {
                roots.push((false, full, p.to_string()));
            }
        }
    }
    if (scope == "all" || scope == "modules") && ctx.modules.is_dir() {
        roots.push((true, ctx.modules.clone(), String::new()));
    }

    let hits = scan_roots_for_apis(&roots, target_minor, ctx.threads);
    err_cnt = hits.iter().filter(|h| h.sev == ApiSev::Error).count();
    let warn_cnt = hits.iter().filter(|h| h.sev == ApiSev::Warn).count();

    // Group by rule_id
    let mut by_rule: BTreeMap<&'static str, Vec<&ApiHit>> = BTreeMap::new();
    let mut by_scope: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for h in &hits {
        by_rule.entry(h.rule_id).or_default().push(h);
        let e = by_scope.entry(h.scope.clone()).or_default();
        if h.sev == ApiSev::Error { e.0 += 1; } else { e.1 += 1; }
    }

    println!("\nSummary: {} HARD ERRORS (must fix for 6.{target_minor}), {} WARNINGS (audit)", err_cnt, warn_cnt);

    println!("\n[1] Hits by breaking-API rule:");
    for (rid, list) in &by_rule {
        let first = list[0];
        let tag = if first.sev == ApiSev::Error { "ERR " } else { "WARN" };
        let uniq_files: BTreeSet<&str> = list.iter().map(|h| h.file.as_str()).collect();
        println!(
            "  [{tag}] {:<22} {:>4} hits ({:>3} files) [since {}]  {}",
            rid,
            list.len(),
            uniq_files.len(),
            first.since,
            first.fix_hint
        );
        if detail {
            for h in list.iter().take(12) {
                println!("         {}:{}  {}", h.file, h.line, h.snippet);
            }
            if list.len() > 12 {
                println!("         ... (+{} more)", list.len() - 12);
            }
        }
    }

    println!("\n[2] Breakdown by driver/module (sorted by hard errors):");
    let mut ranked: Vec<(&String, &(usize, usize))> = by_scope.iter().collect();
    ranked.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| b.1.1.cmp(&a.1.1)));
    for (sc, (e, w)) in &ranked {
        println!("  {:<28} {:>4} errors  {:>4} warnings", sc, e, w);
    }

    if (scope == "all" || scope == "modules") && ctx.modules.is_dir() {
        let hw = scan_module_version_highwater(&ctx.modules);
        println!("\n[3] sm8735-modules LINUX_VERSION_CODE readiness (max KERNEL_VERSION(6,X) guard per module):");
        for (m, (maj, min, cnt)) in &hw {
            let ready = if *min >= target_minor { "6.12-AWARE" } else { "NEEDS-PORT" };
            println!("  {:<28} max={}.{:<2} ({:>3} guards)  [{ready}]", m, maj, min, cnt);
        }
    }
    }

    // [4] SM8735 / onyx 6.12 regression invariants (learned from real bring-up bugs)
    let mut reg_fails = 0usize;
    if target_minor >= 12 {
        println!("\n[4] SM8735 / onyx 6.12 bring-up regression guards:");
        let checks: Vec<(&str, PathBuf, &str, bool, &str)> = vec![
            (
                "clk-branch halt polarity",
                ctx.repo.join("drivers/clk/qcom/clk-branch.c"),
                "invert = (br->halt_check == BRANCH_HALT_ENABLE)",
                false,
                "must use `& BRANCH_HALT_ENABLE` (otherwise GPU GMU VOTED clocks timeout)",
            ),
            (
                "qcom-iommu fastmap pool",
                ctx.repo.join("drivers/iommu/qcom-iommu-util.c"),
                "qcom,iommu-dma-addr-pool",
                true,
                "WCN7750 icnss2 needs qcom,iommu-dma-addr-pool compat or DT iommu-addresses",
            ),
            (
                "SPS BAM v1.7 4K mapping",
                ctx.repo.join("drivers/soc/qcom/sps/sps.c"),
                "SPS_BAM_NDP_V1_7_4K",
                true,
                "SM8735 QCE BAM 0x1dc4000 aborts without SPS_BAM_NDP_V1_7_4K",
            ),
            (
                "wireless reg.db -ENODATA",
                ctx.repo.join("net/wireless/reg.c"),
                "-ENODATA",
                true,
                "missing regulatory.db triggers retry storm unless -ENODATA is returned",
            ),
            (
                "qcom-reboot-reason 0x20",
                ctx.repo.join("drivers/power/reset/qcom-reboot-reason.c"),
                "RESTART_REASON_NORMAL",
                true,
                "warm reboot leaves panel black without Xiaomi 0x20 normal-reboot cookie",
            ),
            (
                "6.12 statmount/listmount hide",
                ctx.repo.join("fs/namespace.c"),
                "yasvara_eval_ns_mount",
                true,
                "6.12 statmount/listmount bypasses proc_namespace yasvara_hide",
            ),
            (
                "DRM FOP_UNSIGNED_OFFSET",
                ctx.modules.join("qcom/opensource/display-drivers/msm/msm_drv.c"),
                "FOP_UNSIGNED_OFFSET",
                true,
                "6.12 drm_open_helper returns -EINVAL without FOP_UNSIGNED_OFFSET",
            ),
            (
                "DRM cont_splash BL handoff",
                ctx.modules.join("qcom/opensource/display-drivers/msm/sde/sde_connector.c"),
                "initial_bl_restored",
                true,
                "first-frame DMS skips initial backlight_update_status() after warm reboot",
            ),
            (
                "Dynamic SCS disabled",
                ctx.repo.join("arch/arm64/configs/vendor/onyx_perf.config"),
                "# CONFIG_UNWIND_PATCH_PAC_INTO_SCS is not set",
                true,
                "Dynamic SCS + Clang 21 faults in __pi_scs_handle_fde_frame",
            ),
            (
                "devfreq_cdev managed link",
                ctx.repo.join("drivers/thermal/qcom/qti_devfreq_cdev.c"),
                "device_link_del(",
                false,
                "device_link_del() on DL_FLAG_AUTOPROBE_CONSUMER triggers 2 boot WARNING splats & WARN taint",
            ),
            (
                "UFS H8 xo parent clock",
                ctx.repo.join("drivers/phy/qualcomm/phy-qcom-ufs.c"),
                "ufs_qcom_phy->ref_clk_parent",
                true,
                "ufs_qcom_phy_set_src_clk_h8_enter() fails -22 on tuna without ref_clk_parent (RPMH_CXO_CLK)",
            ),
            (
                "tuna DT UFS ref_clk_parent",
                ctx.devicetrees.join("qcom/tuna.dtsi"),
                "\"ref_clk_parent\"",
                true,
                "tuna.dtsi ufsphy_mem needs ref_clk_parent=<&rpmhcc RPMH_CXO_CLK> for UFS H8 symbol mux",
            ),
        ];
        for (label, path, needle, want_present, hint) in checks {
            if !path.is_file() {
                continue;
            }
            let txt = fs::read_to_string(&path).unwrap_or_default();
            let has = txt.contains(needle);
            let ok = has == want_present;
            if ok {
                println!("  [PASS] {:<30} ({})", label, path.file_name().unwrap_or_default().to_string_lossy());
            } else {
                println!("  [FAIL] {:<30} — {}", label, hint);
                reg_fails += 1;
            }
        }
        // Function-scoped check: qcom_dload_panic() must select REBOOT_WARM to preserve ramoops across panics
        let dload_path = ctx.repo.join("drivers/power/reset/qcom-dload-mode.c");
        if dload_path.is_file() {
            let txt = fs::read_to_string(&dload_path).unwrap_or_default();
            let panic_ok = txt
                .split("qcom_dload_panic(")
                .nth(1)
                .and_then(|rest| rest.split("\n}").next())
                .is_some_and(|body| body.contains("reboot_mode = REBOOT_WARM"));
            if panic_ok {
                println!("  [PASS] {:<30} (qcom-dload-mode.c)", "qcom-dload panic REBOOT_WARM");
            } else {
                println!("  [FAIL] {:<30} — qcom_dload_panic() must set reboot_mode = REBOOT_WARM to preserve ramoops", "qcom-dload panic REBOOT_WARM");
                reg_fails += 1;
            }
        }
        // Compound guard: if onyx_perf.config sets CONFIG_INIT_STACK_NONE=y, Makefile MUST preserve KBUILD_EXTMOD zero-init
        let perf_cfg = ctx.repo.join("arch/arm64/configs/vendor/onyx_perf.config");
        if perf_cfg.is_file() {
            let ptxt = fs::read_to_string(&perf_cfg).unwrap_or_default();
            if ptxt.lines().any(|l| l.trim() == "CONFIG_INIT_STACK_NONE=y") {
                let mtxt = fs::read_to_string(ctx.repo.join("Makefile")).unwrap_or_default();
                let extmod_ok = mtxt
                    .split("ifdef CONFIG_INIT_STACK_NONE")
                    .nth(1)
                    .is_some_and(|s| s.contains("KBUILD_EXTMOD") && s.contains("-ftrivial-auto-var-init=zero"));
                if extmod_ok {
                    println!("  [PASS] {:<30} (Makefile)", "INIT_STACK_NONE extmod zero");
                } else {
                    println!("  [FAIL] {:<30} — CONFIG_INIT_STACK_NONE=y requires KBUILD_EXTMOD zero-init in Makefile", "INIT_STACK_NONE extmod zero");
                    reg_fails += 1;
                }
            }
            if ptxt.lines().any(|l| l.trim() == "CONFIG_LTO_CLANG_FULL=y" || l.trim() == "CONFIG_LTO_CLANG_THIN=y") {
                let btf_off = ptxt.lines().any(|l| l.trim() == "# CONFIG_DEBUG_INFO_BTF is not set");
                let modver_off = ptxt.lines().any(|l| l.trim() == "# CONFIG_MODVERSIONS is not set");
                if btf_off && modver_off {
                    println!("  [PASS] {:<30} (onyx_perf.config)", "LTO + Rust (BTF & MODVERSIONS off)");
                } else {
                    println!("  [FAIL] {:<30} — LTO with DEBUG_INFO_BTF=y or MODVERSIONS=y silently disables CONFIG_RUST / rust_binder.ko", "LTO + Rust (BTF & MODVERSIONS off)");
                    reg_fails += 1;
                }
            }
        }
    }

    if (!guards_only && err_cnt > 0) || reg_fails > 0 { 1 } else { 0 }
}

// ====================================================== 3. Kconfig Migration Auditor

fn collect_kconfig_symbols(kernel_dir: &Path) -> HashSet<String> {
    let (_, out) = rg(
        kernel_dir,
        &["--no-filename", "--no-line-number", "-g", "*Kconfig*", r"^\s*(menu)?config\s+[A-Za-z0-9_]+"],
    );
    let mut syms = HashSet::with_capacity(20_000);
    for ln in out.lines() {
        let mut it = ln.split_whitespace();
        let kw = it.next().unwrap_or("");
        if kw == "config" || kw == "menuconfig" {
            if let Some(sym) = it.next() {
                syms.insert(sym.to_string());
            }
        }
    }
    syms
}

pub fn cmd_port_config_check(ctx: &Ctx, frag_path: &Path, target_dir_opt: Option<&Path>) -> i32 {
    let target_dir = target_dir_opt.unwrap_or(&ctx.repo);
    let resolved_frag = if frag_path.is_file() {
        frag_path.to_path_buf()
    } else {
        ctx.repo.join(frag_path)
    };
    let Ok(txt) = fs::read_to_string(&resolved_frag) else {
        eprintln!("cannot read config fragment: {}", resolved_frag.display());
        return 2;
    };

    println!("==========================================================================================");
    println!("ktool port config-check: {} vs {}", resolved_frag.display(), target_dir.display());
    println!("==========================================================================================");

    let valid = collect_kconfig_symbols(target_dir);
    let mut enabled_ok = 0usize;
    let mut disabled_ok = 0usize;
    let mut missing_enabled: Vec<(usize, String, String)> = Vec::new();
    let mut missing_disabled: Vec<(usize, String)> = Vec::new();

    for (idx, raw) in txt.lines().enumerate() {
        let lno = idx + 1;
        let t = raw.trim();
        if let Some(rest) = t.strip_prefix("CONFIG_") {
            if let Some((sym, val)) = rest.split_once('=') {
                if valid.contains(sym) {
                    enabled_ok += 1;
                } else {
                    missing_enabled.push((lno, sym.to_string(), val.to_string()));
                }
            }
        } else if let Some(rest) = t.strip_prefix("# CONFIG_") {
            if let Some(sym) = rest.strip_suffix(" is not set") {
                if valid.contains(sym) {
                    disabled_ok += 1;
                } else {
                    missing_disabled.push((lno, sym.to_string()));
                }
            }
        }
    }

    println!("  Kconfig symbols indexed : {}", valid.len());
    println!("  Fragment enabled  (OK)  : {}", enabled_ok);
    println!("  Fragment disabled (OK)  : {}", disabled_ok);
    println!("  MISSING enabled  (WARN) : {}", missing_enabled.len());
    println!("  MISSING disabled (INFO) : {}", missing_disabled.len());

    if !missing_enabled.is_empty() {
        println!("\nEnabled symbols NOT found in target Kconfig (must port driver or rename config!):");
        for (lno, sym, val) in &missing_enabled {
            println!("  L{:<4} CONFIG_{sym}={val}", lno);
        }
    }
    if !missing_disabled.is_empty() {
        println!("\nDisabled symbols NOT found in target Kconfig (obsolete/renamed upstream):");
        for (lno, sym) in missing_disabled.iter().take(40) {
            println!("  L{:<4} # CONFIG_{sym} is not set", lno);
        }
        if missing_disabled.len() > 40 {
            println!("  ... (+{} more)", missing_disabled.len() - 40);
        }
    }

    if missing_enabled.is_empty() { 0 } else { 1 }
}

// ====================================================== 4. DeviceTree Compatible Parity Checker

fn extract_dts_compatibles(dt_dir: &Path) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let qcom_dir = dt_dir.join("qcom");
    let scan_dir = if qcom_dir.is_dir() { &qcom_dir } else { dt_dir };
    let (_, out) = rg(
        scan_dir,
        &[
            "-n",
            "--no-heading",
            "-g", "*onyx*.dts*",
            "-g", "*tuna*.dts*",
            "-g", "sun*.dts*",
            r#"compatible\s*="#,
        ],
    );
    for ln in out.lines() {
        let mut parts = ln.splitn(3, ':');
        let Some(file) = parts.next() else { continue };
        let _lno = parts.next();
        let Some(code) = parts.next() else { continue };
        let Some((_, rhs)) = code.split_once('=') else { continue };
        let mut in_q = false;
        let mut cur = String::new();
        for ch in rhs.chars() {
            if ch == '"' {
                if in_q {
                    if !cur.is_empty() && !cur.starts_with("simple-bus") && cur != "fixed-clock" {
                        map.entry(cur.clone()).or_default().push(file.to_string());
                    }
                    cur.clear();
                    in_q = false;
                } else {
                    in_q = true;
                }
            } else if in_q {
                cur.push(ch);
            }
        }
    }
    for v in map.values_mut() {
        v.sort();
        v.dedup();
    }
    map
}

fn collect_driver_compatibles(dirs: &[&Path]) -> HashSet<String> {
    let mut set = HashSet::with_capacity(16_000);
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let (_, out) = rg(
            dir,
            &[
                "--no-filename",
                "--no-line-number",
                "-g", "*.c",
                "-g", "*.h",
                r#"\.compatible\s*=\s*"[^"]+"|of_device_is_compatible\s*\([^,]+,\s*"[^"]+"|of_find_compatible_node\s*\([^,]+,\s*[^,]+,\s*"[^"]+""#,
            ],
        );
        for ln in out.lines() {
            let mut in_q = false;
            let mut cur = String::new();
            for ch in ln.chars() {
                if ch == '"' {
                    if in_q {
                        if !cur.is_empty() {
                            set.insert(cur.clone());
                        }
                        cur.clear();
                        in_q = false;
                    } else {
                        in_q = true;
                    }
                } else if in_q {
                    cur.push(ch);
                }
            }
        }
    }
    set
}

pub fn cmd_port_dt_compat(ctx: &Ctx, target_kernel_opt: Option<&Path>) -> i32 {
    let target_kernel = target_kernel_opt.unwrap_or(&ctx.repo);
    println!("==========================================================================================");
    println!(
        "ktool port dt-compat: onyx/tuna/sun DT compatibles vs {} + sm8735-modules",
        target_kernel.display()
    );
    println!("==========================================================================================");

    if !ctx.devicetrees.is_dir() {
        eprintln!("!! devicetrees dir not found: {}", ctx.devicetrees.display());
        return 2;
    }

    let dts_compats = extract_dts_compatibles(&ctx.devicetrees);
    let mut drv_dirs = vec![target_kernel];
    if ctx.modules.is_dir() {
        drv_dirs.push(&ctx.modules);
    }
    let drv_compats = collect_driver_compatibles(&drv_dirs);

    // Filter out non-driver generic/board/metadata compatible strings
    let is_meta_compat = |c: &str| {
        c.starts_with("qcom,tuna-")
            || c.starts_with("qcom,sun-")
            || c == "qcom,tuna"
            || c == "qcom,sun"
            || c == "qcom,sunp"
            || c.starts_with("xiaomi,onyx")
            || c == "arm,armv8"
            || c == "arm,cortex-a720"
            || c == "arm,cortex-x4"
            || c == "arm,psci-1.0"
            || c == "shared-dma-pool"
            || c == "removed-dma-pool"
            || c == "restricted-dma-pool"
            || c == "regulator-fixed"
            || c == "gpio-keys"
            || c == "fixed-factor-clock"
            || c == "cache"
            || c == "syscon"
            || c == "simple-mfd"
            || c == "operating-points-v2"
            || c == "arm,idle-state"
            || c == "arm,pmuv3"
            || c.contains("qcom,dummy")
    };

    let mut matched = 0usize;
    let mut unmatched_onyx: Vec<(String, Vec<String>)> = Vec::new();
    let mut unmatched_other: Vec<(String, Vec<String>)> = Vec::new();

    for (c, files) in &dts_compats {
        if drv_compats.contains(c) || is_meta_compat(c) {
            matched += 1;
        } else if files.iter().any(|f| f.contains("onyx")) {
            unmatched_onyx.push((c.clone(), files.clone()));
        } else {
            unmatched_other.push((c.clone(), files.clone()));
        }
    }

    println!("  Total unique DT compatibles (onyx/tuna/sun) : {}", dts_compats.len());
    println!("  Matched in kernel + modules (or generic)    : {}", matched);
    println!("  Unmatched in onyx*.dtsi (PRIORITY CHECK)    : {}", unmatched_onyx.len());
    println!("  Unmatched in tuna/sun*.dtsi                 : {}", unmatched_other.len());

    if !unmatched_onyx.is_empty() {
        println!("\nUnmatched ONYX compatibles:");
        for (c, files) in &unmatched_onyx {
            println!("  {:<46} ({})", c, files.join(", "));
        }
    }
    if !unmatched_other.is_empty() {
        println!("\nUnmatched TUNA/SUN compatibles (top 40):");
        for (c, files) in unmatched_other.iter().take(40) {
            println!("  {:<46} ({})", c, files.iter().take(2).cloned().collect::<Vec<_>>().join(", "));
        }
        if unmatched_other.len() > 40 {
            println!("  ... (+{} more)", unmatched_other.len() - 40);
        }
    }
    0
}

// ====================================================== 5. Zero-KABI-Break Gate (`ktool port kabi-check`)

fn extract_vendor_hooks_used(dirs: &[&Path]) -> BTreeMap<String, Vec<String>> {
    let mut hooks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let (_, out) = rg(
            dir,
            &[
                "-n",
                "--no-heading",
                "-g", "*.c",
                "-g", "*.h",
                r"\bregister_trace_(android_r?vh_[a-zA-Z0-9_]+)\s*\(",
            ],
        );
        for ln in out.lines() {
            let mut parts = ln.splitn(3, ':');
            let Some(file) = parts.next() else { continue };
            let _lno = parts.next();
            let Some(code) = parts.next() else { continue };
            if let Some(pos) = code.find("register_trace_android_") {
                let rest = &code[pos + "register_trace_".len()..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    hooks.entry(name).or_default().push(file.to_string());
                }
            }
        }
    }
    for v in hooks.values_mut() {
        v.sort();
        v.dedup();
    }
    hooks
}

fn collect_target_vendor_hooks(target_kernel: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let hooks_dir = target_kernel.join("include/trace/hooks");
    if !hooks_dir.is_dir() {
        return map;
    }
    let (_, out) = rg(
        &hooks_dir,
        &[
            "-n",
            "--no-heading",
            "-g", "*.h",
            r"DECLARE_(RESTRICTED_)?HOOK\s*\(\s*(android_r?vh_[a-zA-Z0-9_]+)",
        ],
    );
    for ln in out.lines() {
        let mut parts = ln.splitn(3, ':');
        let Some(file) = parts.next() else { continue };
        let Some(lno) = parts.next() else { continue };
        let Some(code) = parts.next() else { continue };
        if let Some(pos) = code.find("android_") {
            let rest = &code[pos..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                map.insert(name, format!("include/trace/hooks/{file}:{lno}"));
            }
        }
    }
    map
}

fn check_kabi_reserve_integrity(target_kernel: &Path, upstream_ref_opt: Option<&str>) -> (usize, Vec<String>) {
    let mut drops = Vec::new();
    let Some(up_ref) = upstream_ref_opt else {
        return (0, drops);
    };
    let diff = git_in(
        target_kernel,
        &["diff", "-U0", up_ref, "--", "include/linux/", "include/net/", "include/scsi/", "include/sound/"],
    );
    let mut cur_file = String::new();
    for ln in diff.lines() {
        if let Some(p) = ln.strip_prefix("+++ b/") {
            cur_file = p.trim().to_string();
        } else if let Some(r) = ln.strip_prefix('-') {
            if !ln.starts_with("---")
                && (r.contains("ANDROID_KABI_RESERVE") || r.contains("ANDROID_OEM_DATA"))
            {
                drops.push(format!("{cur_file}: removed `{}`", r.trim()));
            }
        }
    }
    (drops.len(), drops)
}

pub fn cmd_port_kabi_check(
    ctx: &Ctx,
    target_dir: &Path,
    upstream_base_opt: Option<&str>,
) -> i32 {
    println!("==========================================================================================");
    println!("ktool port kabi-check: Zero-KABI-Break Pre-Build Gate");
    println!("  target kernel : {}", target_dir.display());
    if let Some(u) = upstream_base_opt {
        println!("  upstream base : {u}");
    }
    println!("==========================================================================================");

    let mut failures = 0usize;

    // Gate A: GKI ABI files (6.6 android/abi_gki_aarch64* OR 6.12 gki/aarch64/symbols/*) + KABI reserve slot preservation
    println!("\n[Gate A] GKI KABI symbol lists & ANDROID_KABI_RESERVE integrity:");
    let android_dir = target_dir.join("android");
    let gki_sym_dir = target_dir.join("gki/aarch64/symbols");
    let mut abi_lists = Vec::new();
    if let Ok(rd) = fs::read_dir(&gki_sym_dir) {
        for ent in rd.flatten() {
            abi_lists.push(ent.file_name().to_string_lossy().into_owned());
        }
    }
    if abi_lists.is_empty() {
        if let Ok(rd) = fs::read_dir(&android_dir) {
            for ent in rd.flatten() {
                let n = ent.file_name().to_string_lossy().into_owned();
                if n.starts_with("abi_gki_aarch64") {
                    abi_lists.push(n);
                }
            }
        }
    }
    abi_lists.sort();
    let has_qcom = abi_lists.iter().any(|n| n == "abi_gki_aarch64_qcom" || n == "qcom");
    let has_xiaomi = abi_lists.iter().any(|n| n == "abi_gki_aarch64_xiaomi" || n == "xiaomi");
    println!(
        "  ABI lists found: {} (qcom={}, xiaomi={})",
        abi_lists.len(),
        if has_qcom { "YES" } else { "NO" },
        if has_xiaomi { "YES" } else { "NO" }
    );
    let (drop_cnt, drops) = check_kabi_reserve_integrity(target_dir, upstream_base_opt);
    if drop_cnt == 0 {
        println!("  [PASS] 0 ANDROID_KABI_RESERVE / ANDROID_OEM_DATA deletions vs upstream base");
    } else {
        failures += 1;
        println!("  [FAIL] {drop_cnt} KABI/OEM reserve slot(s) deleted:");
        for d in drops.iter().take(15) {
            println!("         {d}");
        }
    }

    // Gate B: UAPI stability check (if upstream_base_opt given or diffing current 6.6 vs target)
    println!("\n[Gate B] UAPI stability (prebuilt /vendor/lib64/*.so HAL compatibility):");
    let uapi_diff = if let Some(u) = upstream_base_opt {
        git_in(
            target_dir,
            &["diff", "-U3", u, "HEAD", "--", "include/uapi/", "arch/arm64/include/uapi/"],
        )
    } else if fs::canonicalize(target_dir).ok() != fs::canonicalize(&ctx.repo).ok() {
        let (_, out, _) = run_cmd(
            "diff",
            &[
                "-ruN",
                &ctx.repo.join("include/uapi").to_string_lossy(),
                &target_dir.join("include/uapi").to_string_lossy(),
            ],
            &ctx.ws_root,
            None,
        );
        out
    } else {
        String::new()
    };
    if uapi_diff.is_empty() {
        println!("  [PASS] 0 UAPI diffs in checked range");
    } else {
        let uapi_hits = abi::audit_uapi_diff(&uapi_diff);
        // Highlight QCOM/DRM/Media/Binder/USB/Input UAPI mutations
        let critical: Vec<&String> = uapi_hits
            .iter()
            .filter(|h| {
                h.contains("msm")
                    || h.contains("qcom")
                    || h.contains("drm")
                    || h.contains("videodev")
                    || h.contains("v4l2")
                    || h.contains("binder")
                    || h.contains("dma-heap")
                    || h.contains("ion")
                    || h.contains("sound")
                    || h.contains("input")
            })
            .collect();
        if uapi_hits.is_empty() {
            println!("  [PASS] 0 breaking UAPI struct/ioctl/macro mutations");
        } else {
            println!(
                "  [WARN] {} UAPI finding(s) ({} in HAL-critical subsystems):",
                uapi_hits.len(),
                critical.len()
            );
            for h in critical.iter().take(15) {
                println!("         [HAL-CRIT] {h}");
            }
            for h in uapi_hits.iter().filter(|x| !critical.contains(x)).take(10) {
                println!("         {h}");
            }
        }
    }

    // Gate C: Android Vendor Hooks parity
    println!("\n[Gate C] Android Vendor Hooks (android_vh_* / android_rvh_*) parity:");
    let mut hook_consumers: Vec<&Path> = Vec::new();
    let mca_dir = ctx.repo.join("drivers/power/supply/mca");
    let xm_dir = ctx.repo.join("drivers/xiaomi");
    if mca_dir.is_dir() {
        hook_consumers.push(&mca_dir);
    }
    if xm_dir.is_dir() {
        hook_consumers.push(&xm_dir);
    }
    if ctx.modules.is_dir() {
        hook_consumers.push(&ctx.modules);
    }
    let used_hooks = extract_vendor_hooks_used(&hook_consumers);
    let target_hooks = collect_target_vendor_hooks(target_dir);
    let mut missing_hooks = Vec::new();
    for (hook, files) in &used_hooks {
        if !target_hooks.contains_key(hook) {
            missing_hooks.push((hook.clone(), files.clone()));
        }
    }
    println!(
        "  Used by Xiaomi + sm8735-modules: {} unique hooks | Defined in target: {}",
        used_hooks.len(),
        target_hooks.len()
    );
    if missing_hooks.is_empty() {
        println!("  [PASS] 100% of vendor hooks exist in target include/trace/hooks/");
    } else {
        failures += 1;
        println!("  [FAIL] {} vendor hook(s) MISSING in target kernel:", missing_hooks.len());
        for (h, files) in &missing_hooks {
            println!("         {:<44} used by {}", h, files.iter().take(2).cloned().collect::<Vec<_>>().join(", "));
        }
    }

    // Gate D: onyx_perf.config Kconfig parity
    println!("\n[Gate D] onyx_perf.config Kconfig parity against target:");
    let onyx_cfg = ctx.repo.join("arch/arm64/configs/vendor/onyx_perf.config");
    if onyx_cfg.is_file() {
        let valid = collect_kconfig_symbols(target_dir);
        let txt = fs::read_to_string(&onyx_cfg).unwrap_or_default();
        let mut missing_en = Vec::new();
        for raw in txt.lines() {
            if let Some(rest) = raw.trim().strip_prefix("CONFIG_") {
                if let Some((sym, _)) = rest.split_once('=') {
                    if !valid.contains(sym) {
                        missing_en.push(sym.to_string());
                    }
                }
            }
        }
        if missing_en.is_empty() {
            println!("  [PASS] 100% of enabled CONFIG_* in onyx_perf.config exist in target Kconfig");
        } else {
            println!(
                "  [WARN] {} enabled CONFIG_* in onyx_perf.config missing in target Kconfig (port drivers or update config):",
                missing_en.len()
            );
            for s in missing_en.iter().take(20) {
                println!("         CONFIG_{s}");
            }
            if missing_en.len() > 20 {
                println!("         ... (+{} more)", missing_en.len() - 20);
            }
        }
    }

    println!("\n------------------------------------------------------------------------------------------");
    if failures == 0 {
        println!("kabi-check verdict: PASS (0 hard KABI/hook failures)");
        0
    } else {
        println!("kabi-check verdict: FAIL ({failures} gate failure(s) — fix before building!)");
        1
    }
}

// ====================================================== 6. Smart KP 5.0 soc-repo Overlay Engine

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverlayAction {
    SkipMeta,
    SkipGkiSystemDlkm,
    NewFile,
    QcomReplace,
    MakefileMerge,
    KconfigMerge,
    KabiReview,
}

fn bare_or_repo_git(git_path: &Path, args: &[&str]) -> (i32, String, String) {
    if git_path.join("HEAD").is_file() && !git_path.join(".git").exists() {
        let mut full = Vec::with_capacity(args.len() + 2);
        full.push("--git-dir");
        full.push(".");
        full.extend_from_slice(args);
        run_cmd("git", &full, git_path, None)
    } else {
        run_cmd("git", args, git_path, None)
    }
}

fn bare_ls_tree_blobs(git_path: &Path, rev: &str) -> HashMap<String, String> {
    let (_, out, _) = bare_or_repo_git(git_path, &["ls-tree", "-r", rev]);
    let mut map = HashMap::with_capacity(8000);
    for ln in out.lines() {
        let Some((meta, path)) = ln.split_once('\t') else { continue };
        let mut it = meta.split_whitespace();
        let _mode = it.next();
        let kind = it.next();
        let sha = it.next();
        if kind == Some("blob") {
            if let Some(s) = sha {
                map.insert(path.to_string(), s.to_string());
            }
        }
    }
    map
}

fn bare_show_bytes(git_path: &Path, rev: &str, path: &str) -> Option<Vec<u8>> {
    let spec = format!("{rev}:{path}");
    let mut cmd = std::process::Command::new("git");
    if git_path.join("HEAD").is_file() && !git_path.join(".git").exists() {
        cmd.args(["--git-dir", "."]);
    }
    let out = cmd.args(["show", &spec]).current_dir(git_path).output().ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

fn bare_show_str(git_path: &Path, rev: &str, path: &str) -> Option<String> {
    bare_show_bytes(git_path, rev, path).map(|b| String::from_utf8_lossy(&b).into_owned())
}

pub fn classify_soc_overlay_file(path: &str, exists_in_common: bool) -> OverlayAction {
    let fname = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or("");

    // Rule 1: Build meta / Bazel / Kleaf / scripts / top-level root files — NEVER overwrite common
    if path == "Makefile"
        || path == "Kconfig.msm"
        || path == "Kconfig.qtvm"
        || path == "COPYING"
        || path == "Android.bp"
        || path == "BUILD.bazel"
        || path == "BUILD.dtc"
        || path == "bazel.WORKSPACE"
        || path == "device.bazelrc"
        || path == "build.targets"
        || path == "build_with_bazel.py"
        || path == "flatten_kconfig.sh"
        || path == "ack2soc.sh"
        || path.starts_with('.')
        || path.starts_with("scripts/")
        || path.starts_with("Documentation/")
        || path.starts_with("tools/")
        || path.starts_with("ack2soc/")
        || path.starts_with("kleaf-scripts/")
        || path.starts_with("configs/")
        || path.starts_with("build/")
        || path.starts_with("build.config.")
        || path.starts_with("modules-lists/")
        || path.starts_with("qcom_build_extensions/")
        || fname.ends_with(".bzl")
        || fname == "BUILD.bazel"
    {
        return OverlayAction::SkipMeta;
    }

    // Rule 2: GKI system_dlkm drivers owned by kp5-common (keep 6.12 native ZRAM/zsmalloc/stmmac!)
    if path.starts_with("drivers/block/zram/")
        || path == "mm/zsmalloc.c"
        || path == "mm/Makefile"
        || path == "include/linux/zsmalloc.h"
        || path.starts_with("drivers/net/ethernet/stmicro/")
        || path == "include/linux/stmmac.h"
        || path.starts_with("drivers/net/pcs/")
        || path == "kernel/locking/locktorture.c"
        || path == "kernel/locking/Makefile"
        || path == "kernel/rcu/rcutorture.c"
        || path == "kernel/rcu/Makefile"
        || path == "kernel/torture.c"
    {
        return OverlayAction::SkipGkiSystemDlkm;
    }

    if !exists_in_common {
        return OverlayAction::NewFile;
    }

    // Overlapping Makefiles & Kconfigs MUST be smart-merged, never blindly replaced!
    if fname == "Makefile" || fname == "Kbuild" {
        return OverlayAction::MakefileMerge;
    }
    if fname == "Kconfig" || fname.starts_with("Kconfig.") {
        return OverlayAction::KconfigMerge;
    }

    // Overlapping headers in include/linux/ — allow ONLY known QCOM/subsystem-private headers;
    // flag anything else as KabiReview!
    if path.starts_with("include/linux/") {
        let qcom_priv_hdr = path.starts_with("include/linux/soc/qcom/")
            || path.starts_with("include/linux/firmware/qcom/")
            || path.starts_with("include/linux/remoteproc/qcom")
            || path.starts_with("include/linux/rpmsg/qcom")
            || path.starts_with("include/linux/iio/adc/qcom")
            || matches!(
                path,
                "include/linux/adreno-smmu-priv.h"
                    | "include/linux/arm_ffa.h"
                    | "include/linux/coresight.h"
                    | "include/linux/io-pgtable-arm.h"
                    | "include/linux/mhi.h"
                    | "include/linux/slimbus.h"
            );
        return if qcom_priv_hdr {
            OverlayAction::QcomReplace
        } else {
            OverlayAction::KabiReview
        };
    }

    OverlayAction::QcomReplace
}

/// Parse Kconfig `config`/`menuconfig` symbol blocks from text -> Vec<(symbol_name, full_block)>.
pub fn parse_kconfig_blocks(txt: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = txt.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        let sym = trimmed
            .strip_prefix("config ")
            .or_else(|| trimmed.strip_prefix("menuconfig "))
            .and_then(|r| r.split_whitespace().next());
        if let Some(s) = sym {
            let start = i;
            i += 1;
            while i < lines.len() {
                let l = lines[i];
                let t = l.trim_start();
                if !l.is_empty()
                    && !l.starts_with(' ')
                    && !l.starts_with('\t')
                    && !t.starts_with('#')
                {
                    break;
                }
                i += 1;
            }
            let block = lines[start..i].join("\n");
            blocks.push((s.to_string(), block));
        } else {
            i += 1;
        }
    }
    blocks
}

/// Extract Kbuild target names defined in a Makefile (`obj-$(...) += foo.o`, `foo-objs`, `foo-y`).
pub fn extract_makefile_targets(txt: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in txt.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((lhs, rhs)) = line.split_once("+=").or_else(|| line.split_once(":=")) {
            let l = lhs.trim();
            if l.starts_with("obj-") {
                for tok in rhs.split_whitespace() {
                    if tok != "\\" && (tok.ends_with(".o") || tok.ends_with('/')) {
                        out.insert(tok.to_string());
                    }
                }
            } else if l.ends_with("-objs") || l.ends_with("-y") {
                out.insert(l.to_string());
            }
        }
    }
    out
}

/// Merge a soc-repo Makefile into a common Makefile without deleting any common targets.
/// Returns `(merged_content, added_lines, colliding_targets)`.
pub fn smart_merge_makefile(common_txt: &str, soc_txt: &str) -> (String, usize, Vec<String>) {
    let common_targets = extract_makefile_targets(common_txt);
    let mut additions = Vec::new();
    let mut collisions = Vec::new();

    // Join backslash-continued logical lines from soc_txt
    let mut logical: Vec<String> = Vec::new();
    let mut cur = String::new();
    for raw in soc_txt.lines() {
        let t = raw.trim_end();
        if t.ends_with('\\') {
            cur.push_str(raw);
            cur.push('\n');
        } else {
            cur.push_str(raw);
            logical.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        logical.push(cur);
    }

    for entry in logical {
        let first = entry.lines().next().unwrap_or("").trim();
        if first.is_empty()
            || first.starts_with('#')
            || first.starts_with("ccflags-y += -I$(src)")
        {
            continue;
        }
        let targets = extract_makefile_targets(&entry);
        if targets.is_empty() {
            // Keep conditional/ccflags lines not already verbatim in common
            if !common_txt.contains(first) {
                additions.push(entry);
            }
            continue;
        }
        let dup: Vec<String> = targets.intersection(&common_targets).cloned().collect();
        if dup.is_empty() {
            additions.push(entry);
        } else {
            // Check if the exact line is already present; if different, record collision
            let norm_soc: String = entry.split_whitespace().collect::<Vec<_>>().join(" ");
            let already_same = common_txt
                .lines()
                .any(|l| l.split_whitespace().collect::<Vec<_>>().join(" ") == norm_soc);
            if !already_same {
                collisions.extend(dup);
            }
        }
    }
    collisions.sort();
    collisions.dedup();

    let added_cnt = additions.len();
    let mut merged = common_txt.to_string();
    if !additions.is_empty() {
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
        merged.push_str("\n# --- KP 5.0 soc-repo additions ---\n");
        for a in &additions {
            merged.push_str(a);
            merged.push('\n');
        }
    }
    (merged, added_cnt, collisions)
}

/// Merge a soc-repo Kconfig into a common Kconfig: append ONLY brand-new config blocks,
/// reporting any duplicate symbol names instead of causing Kconfig redefinition errors.
pub fn smart_merge_kconfig(common_txt: &str, soc_txt: &str) -> (String, usize, Vec<String>) {
    let common_syms: HashSet<String> = parse_kconfig_blocks(common_txt)
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    let soc_blocks = parse_kconfig_blocks(soc_txt);

    let mut new_blocks = Vec::new();
    let mut dup_syms = Vec::new();
    for (sym, blk) in soc_blocks {
        if common_syms.contains(&sym) {
            dup_syms.push(sym);
        } else {
            new_blocks.push(blk);
        }
    }

    // Also pick up any `source "..."` lines from soc_txt not present in common_txt
    let mut new_sources = Vec::new();
    for raw in soc_txt.lines() {
        let t = raw.trim();
        if t.starts_with("source ") {
            let cleaned = t.replace("$(KCONFIG_EXT_PREFIX)", "");
            if !common_txt.contains(&cleaned) {
                new_sources.push(cleaned);
            }
        }
    }

    let added_cnt = new_blocks.len() + new_sources.len();
    let mut merged = common_txt.to_string();
    if added_cnt > 0 {
        // Insert before a trailing `endmenu` or `endif` if present, otherwise append
        let mut insert_block = String::from("\n# --- KP 5.0 soc-repo additions ---\n");
        for s in &new_sources {
            insert_block.push_str(s);
            insert_block.push('\n');
        }
        for b in &new_blocks {
            insert_block.push('\n');
            insert_block.push_str(b);
            insert_block.push('\n');
        }
        if let Some(pos) = merged.rfind("\nendmenu") {
            merged.insert_str(pos, &insert_block);
        } else {
            if !merged.ends_with('\n') {
                merged.push('\n');
            }
            merged.push_str(&insert_block);
        }
    }
    (merged, added_cnt, dup_syms)
}

pub fn cmd_port_overlay_soc(
    ctx: &Ctx,
    soc_git: &Path,
    soc_ref: &str,
    common_opt: Option<(&Path, &str)>,
    apply: bool,
) -> i32 {
    println!("==========================================================================================");
    println!(
        "ktool port overlay-soc: {} ({}) [{}]",
        soc_git.display(),
        soc_ref,
        if apply { "APPLY" } else { "DRY-RUN" }
    );
    println!("==========================================================================================");

    let soc_blobs = bare_ls_tree_blobs(soc_git, soc_ref);
    if soc_blobs.is_empty() {
        eprintln!("!! failed to list blobs from {} at {}", soc_git.display(), soc_ref);
        return 2;
    }

    // Determine common file set (either from --common bare repo or live ctx.repo worktree)
    let common_blobs: Option<HashMap<String, String>> =
        common_opt.map(|(cg, cr)| bare_ls_tree_blobs(cg, cr));

    let mut counts: BTreeMap<OverlayAction, usize> = BTreeMap::new();
    let mut mf_merges: Vec<(String, usize, Vec<String>)> = Vec::new();
    let mut kc_merges: Vec<(String, usize, Vec<String>)> = Vec::new();
    let mut kabi_reviews: Vec<String> = Vec::new();
    let mut identical_skipped = 0usize;

    let mut paths: Vec<String> = soc_blobs.keys().cloned().collect();
    paths.sort();

    for path in &paths {
        let in_common = match &common_blobs {
            Some(m) => m.contains_key(path),
            None => ctx.repo.join(path).exists(),
        };
        // Skip byte-identical overlapping files immediately
        if let Some(ref cm) = common_blobs {
            if cm.get(path) == soc_blobs.get(path) {
                identical_skipped += 1;
                continue;
            }
        }

        let act = classify_soc_overlay_file(path, in_common);
        *counts.entry(act).or_default() += 1;

        match act {
            OverlayAction::SkipMeta | OverlayAction::SkipGkiSystemDlkm => {}
            OverlayAction::KabiReview => {
                kabi_reviews.push(path.clone());
            }
            OverlayAction::NewFile | OverlayAction::QcomReplace => {
                if apply {
                    if let Some(bytes) = bare_show_bytes(soc_git, soc_ref, path) {
                        let dst = ctx.repo.join(path);
                        if let Some(par) = dst.parent() {
                            let _ = fs::create_dir_all(par);
                        }
                        if let Err(e) = fs::write(&dst, bytes) {
                            eprintln!("!! write failed for {path}: {e}");
                            return 1;
                        }
                    }
                }
            }
            OverlayAction::MakefileMerge => {
                let common_txt = match common_opt {
                    Some((cg, cr)) => bare_show_str(cg, cr, path).unwrap_or_default(),
                    None => fs::read_to_string(ctx.repo.join(path)).unwrap_or_default(),
                };
                let soc_txt = bare_show_str(soc_git, soc_ref, path).unwrap_or_default();
                let (merged, added, colls) = smart_merge_makefile(&common_txt, &soc_txt);
                if apply && added > 0 {
                    if let Err(e) = fs::write(ctx.repo.join(path), merged) {
                        eprintln!("!! write failed for {path}: {e}");
                        return 1;
                    }
                }
                mf_merges.push((path.clone(), added, colls));
            }
            OverlayAction::KconfigMerge => {
                let common_txt = match common_opt {
                    Some((cg, cr)) => bare_show_str(cg, cr, path).unwrap_or_default(),
                    None => fs::read_to_string(ctx.repo.join(path)).unwrap_or_default(),
                };
                let soc_txt = bare_show_str(soc_git, soc_ref, path).unwrap_or_default();
                let (merged, added, dups) = smart_merge_kconfig(&common_txt, &soc_txt);
                if apply && added > 0 {
                    if let Err(e) = fs::write(ctx.repo.join(path), merged) {
                        eprintln!("!! write failed for {path}: {e}");
                        return 1;
                    }
                }
                kc_merges.push((path.clone(), added, dups));
            }
        }
    }

    println!("\nClassification across {} soc-repo files ({} identical skipped):", paths.len(), identical_skipped);
    println!("  NEW-FILE (disjoint QCOM drivers/hdrs) : {:>5}", counts.get(&OverlayAction::NewFile).unwrap_or(&0));
    println!("  QCOM-REPLACE (QCOM-owned overlays)    : {:>5}", counts.get(&OverlayAction::QcomReplace).unwrap_or(&0));
    println!("  MAKEFILE-MERGE (smart target merge)   : {:>5}", counts.get(&OverlayAction::MakefileMerge).unwrap_or(&0));
    println!("  KCONFIG-MERGE (smart symbol merge)    : {:>5}", counts.get(&OverlayAction::KconfigMerge).unwrap_or(&0));
    println!("  KABI-REVIEW (non-QCOM include/linux/) : {:>5}", counts.get(&OverlayAction::KabiReview).unwrap_or(&0));
    println!("  SKIP-META (Bazel/scripts/root)        : {:>5}", counts.get(&OverlayAction::SkipMeta).unwrap_or(&0));
    println!("  SKIP-GKI-SYSTEM-DLKM (zram/stmmac)    : {:>5}", counts.get(&OverlayAction::SkipGkiSystemDlkm).unwrap_or(&0));

    if !kabi_reviews.is_empty() {
        println!("\n[!] KABI-REVIEW headers (NOT auto-overwritten — inspect before replacing!):");
        for p in &kabi_reviews {
            println!("  {p}");
        }
    } else {
        println!("\n[PASS] 0 non-QCOM core Linux headers touched by soc-repo!");
    }

    let mf_with_coll: Vec<_> = mf_merges.iter().filter(|(_, _, c)| !c.is_empty()).collect();
    println!(
        "\n[Makefile merges]: {} files total, {} with target collisions (check obj/objs overrides):",
        mf_merges.len(),
        mf_with_coll.len()
    );
    for (p, added, colls) in &mf_with_coll {
        println!("  {:<46} +{:>2} new  COLLISIONS: {}", p, added, colls.join(", "));
    }

    let kc_with_dup: Vec<_> = kc_merges.iter().filter(|(_, _, d)| !d.is_empty()).collect();
    println!(
        "\n[Kconfig merges]: {} files total, {} with existing symbols skipped (prevents redef errors):",
        kc_merges.len(),
        kc_with_dup.len()
    );
    for (p, added, dups) in &kc_with_dup {
        let preview: Vec<_> = dups.iter().take(6).cloned().collect();
        let extra = if dups.len() > 6 { format!(" (+{} more)", dups.len() - 6) } else { String::new() };
        println!("  {:<46} +{:>2} new  SKIPPED-DUPS({}): {}{}", p, added, dups.len(), preview.join(", "), extra);
    }

    0
}

// ====================================================== 7. Starlark .bzl -> Kbuild .config Converter

pub fn parse_bzl_config_dict(txt: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in txt.lines() {
        let t = raw.trim();
        if !t.starts_with("\"CONFIG_") {
            continue;
        }
        let Some((kpart, vpart)) = t.split_once(':') else { continue };
        let key = kpart.trim().trim_matches('"');
        let raw_val = vpart
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches(',')
            .trim()
            .trim_matches('"')
            .replace("\\\"", "\"");
        let val = raw_val.trim_matches('"');
        match val {
            "n" => out.push(format!("# {key} is not set")),
            "y" | "m" => out.push(format!("{key}={val}")),
            v if v.chars().all(|c| c.is_ascii_digit() || c == 'x' || c == 'X' || c == '-') && !v.is_empty() => {
                out.push(format!("{key}={v}"));
            }
            v => out.push(format!("{key}=\"{v}\"")),
        }
    }
    out
}

pub fn cmd_port_bzl2config(
    soc_git: &Path,
    soc_ref: &str,
    bzl_path: &str,
    out_opt: Option<&Path>,
) -> i32 {
    let txt = if soc_git.is_file() {
        fs::read_to_string(soc_git).unwrap_or_default()
    } else {
        bare_show_str(soc_git, soc_ref, bzl_path).unwrap_or_default()
    };
    if txt.is_empty() {
        eprintln!("!! could not read {bzl_path} from {} ({soc_ref})", soc_git.display());
        return 2;
    }
    let lines = parse_bzl_config_dict(&txt);
    let mut rendered = format!("# Auto-converted from {bzl_path} ({soc_ref}) via ktool port bzl2config\n");
    for l in &lines {
        rendered.push_str(l);
        rendered.push('\n');
    }
    if let Some(outp) = out_opt {
        if let Err(e) = fs::write(outp, &rendered) {
            eprintln!("!! write failed for {}: {e}", outp.display());
            return 1;
        }
        println!("wrote {} config entries -> {}", lines.len(), outp.display());
    } else {
        println!("# {} config entries parsed from {bzl_path}:", lines.len());
        for l in lines.iter().take(40) {
            println!("{l}");
        }
        if lines.len() > 40 {
            println!("# ... (+{} more; pass --out <file> to write full fragment)", lines.len() - 40);
        }
    }
    0
}

// ====================================================== 8. Instant Kbuild/Kconfig Pre-Make Auditor

pub fn cmd_port_kbuild_audit(ctx: &Ctx, target_opt: Option<&Path>) -> i32 {
    let root = target_opt.unwrap_or(&ctx.repo);
    println!("==========================================================================================");
    println!("ktool port kbuild-audit: Kconfig source/dup-symbol & Makefile target check ({})", root.display());
    println!("==========================================================================================");

    let mut errors = 0usize;

    // 1. Check all `source "..."` lines in Kconfig* files point to existing files
    let (_, src_out) = rg(
        root,
        &["-n", "--no-heading", "-g", "*Kconfig*", r#"^\s*source\s+"[^"]+""#],
    );
    let mut missing_sources = Vec::new();
    for ln in src_out.lines() {
        let mut parts = ln.splitn(3, ':');
        let Some(kf) = parts.next() else { continue };
        let Some(lno) = parts.next() else { continue };
        let Some(code) = parts.next() else { continue };
        if kf.starts_with("Documentation/") || kf.starts_with("tools/") || kf.starts_with("scripts/") {
            continue;
        }
        if let Some(q1) = code.find('"') {
            if let Some(q2) = code[q1 + 1..].find('"') {
                let target = &code[q1 + 1..q1 + 1 + q2];
                if target.contains('$') || target.contains('*') {
                    continue;
                }
                if !root.join(target).is_file() {
                    missing_sources.push(format!("{kf}:{lno} -> missing `{target}`"));
                }
            }
        }
    }
    if missing_sources.is_empty() {
        println!("  [PASS] 0 broken Kconfig `source \"...\"` includes");
    } else {
        errors += missing_sources.len();
        println!("  [FAIL] {} broken Kconfig `source` path(s):", missing_sources.len());
        for m in missing_sources.iter().take(25) {
            println!("         {m}");
        }
    }

    // 2. Check duplicate `config FOO` within the SAME Kconfig file (classic merge artifact!)
    let (_, cfg_out) = rg(
        root,
        &["-n", "--no-heading", "-g", "*Kconfig*", r"^(menu)?config\s+[A-Za-z0-9_]+"],
    );
    let mut per_file_seen: HashMap<(String, String), usize> = HashMap::new();
    let mut same_file_dups = Vec::new();
    for ln in cfg_out.lines() {
        let mut parts = ln.splitn(3, ':');
        let Some(kf) = parts.next() else { continue };
        let Some(lno_s) = parts.next() else { continue };
        let Some(code) = parts.next() else { continue };
        let Ok(lno) = lno_s.parse::<usize>() else { continue };
        let sym = code.split_whitespace().nth(1).unwrap_or("");
        if sym.is_empty() {
            continue;
        }
        if let Some(prev) = per_file_seen.insert((kf.to_string(), sym.to_string()), lno) {
            same_file_dups.push(format!("{kf}: duplicate `config {sym}` at L{prev} and L{lno}"));
        }
    }
    if same_file_dups.is_empty() {
        println!("  [PASS] 0 same-file duplicate Kconfig symbols");
    } else {
        errors += same_file_dups.len();
        println!("  [FAIL] {} duplicate Kconfig symbol(s) inside same file:", same_file_dups.len());
        for d in same_file_dups.iter().take(25) {
            println!("         {d}");
        }
    }

    // 3. Check all QCOM/Xiaomi Makefiles for missing `.c` source targets referenced directly
    let check_dirs = [
        "drivers/clk/qcom",
        "drivers/pinctrl/qcom",
        "drivers/interconnect/qcom",
        "drivers/soc/qcom",
        "drivers/thermal/qcom",
        "drivers/usb/dwc3",
        "drivers/ufs/host",
        "drivers/power/supply/mca",
        "drivers/xiaomi",
    ];
    let mut missing_objs = Vec::new();
    for rel in check_dirs {
        let dir = root.join(rel);
        let mk = dir.join("Makefile");
        let Ok(txt) = fs::read_to_string(&mk) else { continue };
        // Collect composite module names (foo-objs / foo-y) so we don't flag foo.o as missing foo.c
        let mut composites: HashSet<String> = HashSet::new();
        for raw in txt.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if let Some((lhs, _)) = line.split_once("+=").or_else(|| line.split_once(":=")) {
                let l = lhs.trim();
                if let Some(stem) = l.strip_suffix("-objs").or_else(|| l.strip_suffix("-y")) {
                    composites.insert(format!("{stem}.o"));
                }
            }
        }
        for (idx, raw) in txt.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if let Some((lhs, rhs)) = line.split_once("+=").or_else(|| line.split_once(":=")) {
                if !lhs.trim().starts_with("obj-") {
                    continue;
                }
                for tok in rhs.split_whitespace() {
                    if let Some(stem) = tok.strip_suffix(".o") {
                        if composites.contains(tok) || stem.contains('$') {
                            continue;
                        }
                        if !dir.join(format!("{stem}.c")).is_file()
                            && !dir.join(format!("{stem}.S")).is_file()
                        {
                            missing_objs.push(format!("{rel}/Makefile:L{} -> `{tok}` has no .c/.S or -objs", idx + 1));
                        }
                    }
                }
            }
        }
    }
    if missing_objs.is_empty() {
        println!("  [PASS] 0 dangling .o targets in checked QCOM/Xiaomi Makefiles");
    } else {
        errors += missing_objs.len();
        println!("  [FAIL] {} dangling Makefile target(s):", missing_objs.len());
        for m in missing_objs.iter().take(25) {
            println!("         {m}");
        }
    }

    println!("------------------------------------------------------------------------------------------");
    println!("kbuild-audit verdict: {}", if errors == 0 { "PASS" } else { "FAIL" });
    if errors == 0 { 0 } else { 1 }
}

// ====================================================== 9. Cross-Module QCOM Header Diff Auditor

pub fn cmd_port_header_diff(
    ctx: &Ctx,
    soc_git: &Path,
    soc_ref: &str,
    common_opt: Option<(&Path, &str)>,
) -> i32 {
    println!("==========================================================================================");
    println!("ktool port header-diff: QCOM/driver header contract (6.6 HEAD vs KP 5.0 {soc_ref})");
    println!("==========================================================================================");

    // Find every `#include <...>` used across sm8735-modules & Xiaomi drivers
    let mut consumers: Vec<PathBuf> = Vec::new();
    if ctx.modules.is_dir() {
        consumers.push(ctx.modules.clone());
    }
    for sub in ["drivers/power/supply/mca", "drivers/xiaomi", "drivers/input/fingerprint/mi_fp", "drivers/thermal/xiaomi"] {
        let p = ctx.repo.join(sub);
        if p.is_dir() {
            consumers.push(p);
        }
    }

    let mut used_headers: BTreeMap<String, usize> = BTreeMap::new();
    for dir in &consumers {
        let (_, out) = rg(
            dir,
            &["--no-filename", "--no-line-number", "-g", "*.c", "-g", "*.h", r#"^\s*#\s*include\s*<[^>]+>"#],
        );
        for ln in out.lines() {
            if let (Some(a), Some(b)) = (ln.find('<'), ln.find('>')) {
                if b > a + 1 {
                    let h = ln[a + 1..b].trim();
                    *used_headers.entry(h.to_string()).or_default() += 1;
                }
            }
        }
    }

    let soc_blobs = bare_ls_tree_blobs(soc_git, soc_ref);
    let common_blobs = common_opt
        .map(|(cg, cr)| bare_ls_tree_blobs(cg, cr))
        .unwrap_or_default();

    let mut missing = Vec::new();
    let mut from_soc = Vec::new();
    let mut from_common = 0usize;

    for (hdr, cnt) in &used_headers {
        // Check include/<hdr>, include/uapi/<hdr>, arch/arm64/include/<hdr>, arch/arm64/include/uapi/<hdr>, or generated/module-local
        let candidates = [
            format!("include/{hdr}"),
            format!("include/uapi/{hdr}"),
            format!("arch/arm64/include/{hdr}"),
            format!("arch/arm64/include/uapi/{hdr}"),
        ];
        let in_soc = candidates.iter().any(|c| soc_blobs.contains_key(c));
        let in_common = candidates.iter().any(|c| common_blobs.contains_key(c));
        if in_soc {
            from_soc.push((hdr.clone(), *cnt));
        } else if in_common {
            from_common += 1;
        } else {
            // Ignore module-local headers (e.g. <linux/qseecom.h> inside securemsm, <media/cam_*.h>, <dt-bindings/...>, <generated/...>)
            if hdr.starts_with("generated/")
                || hdr.starts_with("uapi/media/cam_")
                || hdr.starts_with("media/cam_")
                || hdr.starts_with("linux/mca/")
                || hdr.starts_with("miev/")
                || hdr.starts_with("mi_ubt/")
            {
                continue;
            }
            // Also check if header exists inside sm8735-modules itself!
            let exists_in_66_kern = candidates.iter().any(|c| ctx.repo.join(c).is_file());
            if exists_in_66_kern {
                missing.push((hdr.clone(), *cnt));
            }
        }
    }

    println!("  Unique `<...>` headers included by modules + Xiaomi : {}", used_headers.len());
    println!("  Resolved in kp5-common (6.12.92)                    : {}", from_common);
    println!("  Resolved in kp5-soc-repo (KP 5.0)                   : {}", from_soc.len());
    println!("  MISSING in KP 5.0 (existed in 6.6 kernel!)          : {}", missing.len());

    if !missing.is_empty() {
        println!("\n[!] Headers present in 6.6 kernel & included by modules/Xiaomi, but ABSENT in KP 5.0:");
        missing.sort_by(|a, b| b.1.cmp(&a.1));
        for (h, cnt) in &missing {
            println!("  {:>4} includes  <{h}>", cnt);
        }
    } else {
        println!("\n[PASS] 100% of 6.6 kernel headers included by modules/Xiaomi exist in KP 5.0!");
    }

    println!("\nTop QCOM soc-repo headers depended on by modules/Xiaomi:");
    from_soc.sort_by(|a, b| b.1.cmp(&a.1));
    for (h, cnt) in from_soc.iter().take(25) {
        println!("  {:>4} includes  <{h}>", cnt);
    }

    if missing.is_empty() { 0 } else { 1 }
}

// ====================================================== 10. Build Log Error Triage (`ktool port build-diag`)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildDiagEntry {
    pub category: &'static str,
    pub file: String,
    pub line: String,
    pub msg: String,
}

fn classify_build_error(msg: &str) -> &'static str {
    let low = msg.to_ascii_lowercase();
    if low.contains("file not found") || low.contains("no such file or directory") {
        "missing-header"
    } else if low.contains("incompatible function pointer") && (low.contains("remove") || low.contains("void (")) {
        "void-remove"
    } else if low.contains("too few arguments") || low.contains("too many arguments") || low.contains("conflicting types") {
        "signature-mismatch"
    } else if low.contains("undeclared identifier") || low.contains("implicit declaration") || low.contains("call to undeclared") {
        "undeclared-ident"
    } else if low.contains("no member named") || low.contains("no field named") || low.contains("incomplete definition of type") {
        "missing-member"
    } else if low.contains("incompatible pointer") || low.contains("incompatible integer") || low.contains("incompatible function pointer") {
        "type-mismatch"
    } else if low.contains("undefined!") && low.contains("modpost") {
        "modpost-undef"
    } else if low.contains("duplicate symbol") || low.contains("undefined symbol") {
        "linker-error"
    } else if low.contains("syntax error") || low.contains("unable to parse") {
        "dtc-or-syntax"
    } else {
        "other"
    }
}

pub fn parse_build_diagnostics(log: &str) -> Vec<BuildDiagEntry> {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();

    for raw in log.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // 1. Modpost undefined symbol
        if let Some(rest) = line.strip_prefix("ERROR: modpost:") {
            let key = ("modpost".to_string(), "0".to_string(), rest.trim().to_string());
            if seen.insert(key) {
                out.push(BuildDiagEntry {
                    category: "modpost-undef",
                    file: "modpost".to_string(),
                    line: "0".to_string(),
                    msg: rest.trim().to_string(),
                });
            }
            continue;
        }
        // 2. ld.lld errors
        if line.starts_with("ld.lld: error:") || line.starts_with("ld: error:") {
            let msg = line.split_once("error:").map(|(_, r)| r.trim()).unwrap_or(line);
            let key = ("ld.lld".to_string(), "0".to_string(), msg.to_string());
            if seen.insert(key) {
                out.push(BuildDiagEntry {
                    category: classify_build_error(msg),
                    file: "ld.lld".to_string(),
                    line: "0".to_string(),
                    msg: msg.to_string(),
                });
            }
            continue;
        }
        // 3. DTC errors (`Error: path:line.col ...`)
        if let Some(rest) = line.strip_prefix("Error:") {
            let key = ("dtc".to_string(), "0".to_string(), rest.trim().to_string());
            if seen.insert(key) {
                out.push(BuildDiagEntry {
                    category: "dtc-or-syntax",
                    file: "dtc".to_string(),
                    line: "0".to_string(),
                    msg: rest.trim().to_string(),
                });
            }
            continue;
        }
        // 4. Clang/GCC errors (`path:line:col: error: msg` or `fatal error: msg`)
        let err_pos = line.find(": error: ").or_else(|| line.find(": fatal error: "));
        if let Some(pos) = err_pos {
            let loc = &line[..pos];
            let msg = line[pos..]
                .trim_start_matches(": fatal error: ")
                .trim_start_matches(": error: ")
                .trim();
            let mut loc_parts = loc.split(':');
            let file_raw = loc_parts.next().unwrap_or(loc);
            let lno = loc_parts.next().unwrap_or("0");
            // Strip absolute workspace prefix for readability
            let file = file_raw
                .rsplit_once("/sm8735/")
                .map(|(_, r)| r.to_string())
                .or_else(|| file_raw.rsplit_once("/sm8735-modules/").map(|(_, r)| format!("mod/{r}")))
                .or_else(|| file_raw.rsplit_once("/sm8735-devicetrees/").map(|(_, r)| format!("dt/{r}")))
                .unwrap_or_else(|| file_raw.to_string());
            let key = (file.clone(), lno.to_string(), msg.to_string());
            if seen.insert(key) {
                out.push(BuildDiagEntry {
                    category: classify_build_error(msg),
                    file,
                    line: lno.to_string(),
                    msg: msg.to_string(),
                });
            }
            continue;
        }
        // 5. GNU Make root-cause errors (`path:line: *** ... Stop.` or `make[N]: *** No rule to make target ...`)
        if let Some(idx) = line.find(": *** ") {
            let lhs = &line[..idx];
            let rhs = line[idx + 6..].trim();
            // Skip cascading directory rollup lines like `make[4]: *** [.../Makefile.build:500: dir] Error 2`
            let is_rollup = rhs.starts_with('[') && rhs.contains("] Error ");
            if !is_rollup {
                let (file, lno) = if let Some((f, l)) = lhs.rsplit_once(':') {
                    let f_clean = f
                        .rsplit_once("/sm8735/")
                        .map(|(_, r)| r.to_string())
                        .or_else(|| f.rsplit_once("/sm8735-modules/").map(|(_, r)| format!("mod/{r}")))
                        .unwrap_or_else(|| f.to_string());
                    (f_clean, l.to_string())
                } else {
                    ("make".to_string(), "0".to_string())
                };
                let key = (file.clone(), lno.clone(), rhs.to_string());
                if seen.insert(key) {
                    out.push(BuildDiagEntry {
                        category: "make-error",
                        file,
                        line: lno,
                        msg: rhs.to_string(),
                    });
                }
                continue;
            }
        }
        // 6. Generic tool / rustc / gendwarfksyms / pahole / objtool error lines
        if line.starts_with("error:")
            || line.starts_with("error[E")
            || line.starts_with("gendwarfksyms:")
            || line.starts_with("pahole:")
            || line.contains("FATAL:")
        {
            let key = ("tool".to_string(), "0".to_string(), line.to_string());
            if seen.insert(key) {
                out.push(BuildDiagEntry {
                    category: if line.starts_with("error[E") { "rust-error" } else { "tool-error" },
                    file: "tool".to_string(),
                    line: "0".to_string(),
                    msg: line.to_string(),
                });
            }
        }
    }
    // Fallback: if 0 concrete errors were parsed but make still reported fatal exit, surface last make error
    if out.is_empty() {
        for raw in log.lines() {
            let line = raw.trim();
            if line.contains(": *** [") && line.contains("] Error ") {
                out.push(BuildDiagEntry {
                    category: "make-error",
                    file: "make".to_string(),
                    line: "0".to_string(),
                    msg: line.to_string(),
                });
                break;
            }
        }
    }
    out
}

pub fn cmd_port_build_diag(log_path: &Path, top: usize) -> i32 {
    let Ok(txt) = fs::read_to_string(log_path) else {
        eprintln!("!! cannot read build log: {}", log_path.display());
        return 2;
    };
    let entries = parse_build_diagnostics(&txt);
    println!("==========================================================================================");
    println!("ktool port build-diag: {} ({} unique errors)", log_path.display(), entries.len());
    println!("==========================================================================================");
    if entries.is_empty() {
        println!("  [PASS] 0 compiler/linker/modpost/dtc errors found!");
        return 0;
    }

    let mut by_cat: BTreeMap<&'static str, Vec<&BuildDiagEntry>> = BTreeMap::new();
    let mut by_file: HashMap<&str, usize> = HashMap::new();
    for e in &entries {
        by_cat.entry(e.category).or_default().push(e);
        *by_file.entry(e.file.as_str()).or_default() += 1;
    }

    println!("\n[1] Errors by root-cause category:");
    let mut cats: Vec<_> = by_cat.iter().collect();
    cats.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    for (cat, list) in &cats {
        println!("  {:<20} {:>4} unique errors", cat, list.len());
    }

    println!("\n[2] Top affected files (showing up to {top}):");
    let mut files: Vec<_> = by_file.into_iter().collect();
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    for (f, cnt) in files.iter().take(top) {
        println!("  {:>4}  {f}", cnt);
    }

    println!("\n[3] Sample actionable errors per category:");
    for (cat, list) in &cats {
        println!("  --- {cat} ({}) ---", list.len());
        for e in list.iter().take(10) {
            println!("    {}:{}  {}", e.file, e.line, truncate_str(&e.msg, 110));
        }
        if list.len() > 10 {
            println!("    ... (+{} more)", list.len() - 10);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_port_paths() {
        assert_eq!(
            classify_port_path("A", "drivers/power/supply/mca/mca_business/business_charger/mca_business_charger.c"),
            DeltaBucket::XiaomiNew
        );
        assert_eq!(
            classify_port_path("A", "arch/arm64/configs/vendor/onyx_perf.config"),
            DeltaBucket::XiaomiNew
        );
        assert_eq!(
            classify_port_path("M", "drivers/clk/qcom/gcc-tuna.c"),
            DeltaBucket::QcomSoc
        );
        assert_eq!(
            classify_port_path("M", "drivers/pinctrl/qcom/pinctrl-sun.c"),
            DeltaBucket::QcomSoc
        );
        assert_eq!(
            classify_port_path("M", "drivers/thermal/qcom/tsens.c"),
            DeltaBucket::CorePatched
        );
        // Must NOT misclassify Allwinner sunxi as Qualcomm sun!
        assert_eq!(
            classify_port_path("M", "drivers/clk/sunxi-ng/ccu-sun50i.c"),
            DeltaBucket::CorePatched
        );
    }

    #[test]
    fn test_version_guard_skips_older_kernel_branch() {
        let src = r#"
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
    .llseek = no_llseek,
#else
    .llseek = noop_llseek,
#endif
"#;
        let lines: Vec<&str> = src.lines().collect();
        assert!(is_guarded_for_older_kernel(&lines, 3, 12));
        assert!(!is_guarded_for_older_kernel(&lines, 5, 12));

        let src2 = r#"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    strscpy(dst, src, len);
#else
    strlcpy(dst, src, len);
#endif
"#;
        let lines2: Vec<&str> = src2.lines().collect();
        assert!(is_guarded_for_older_kernel(&lines2, 5, 12));
        assert!(!is_guarded_for_older_kernel(&lines2, 3, 12));
    }

    #[test]
    fn test_smart_merge_makefile_preserves_common_builtins() {
        let common = "obj-$(CONFIG_USB_DWC3) += dwc3.o\ndwc3-y := core.o gadget.o\n";
        let soc = "ccflags-y += -I$(src)\nobj-$(CONFIG_USB_DWC3_MSM) += dwc3-msm.o\ndwc3-msm-objs += dwc3-msm-core.o\n";
        let (merged, added, colls) = smart_merge_makefile(common, soc);
        assert!(colls.is_empty(), "expected 0 collisions: {colls:?}");
        assert_eq!(added, 2);
        assert!(merged.contains("dwc3-y := core.o gadget.o"));
        assert!(merged.contains("obj-$(CONFIG_USB_DWC3_MSM) += dwc3-msm.o"));
    }

    #[test]
    fn test_smart_merge_kconfig_skips_redefs() {
        let common = "menu \"Test\"\n\nconfig FOO\n\tbool \"Foo\"\n\nendmenu\n";
        let soc = "config FOO\n\ttristate \"Foo\"\n\nconfig BAR_QCOM\n\ttristate \"Bar\"\n";
        let (merged, added, dups) = smart_merge_kconfig(common, soc);
        assert_eq!(dups, vec!["FOO".to_string()]);
        assert_eq!(added, 1);
        assert!(merged.contains("config BAR_QCOM"));
        assert_eq!(merged.matches("config FOO").count(), 1);
    }

    #[test]
    fn test_bzl_config_converter() {
        let bzl = r#"
sun_perf_config = {
    "CONFIG_ARCH_SUN": "y",
    "CONFIG_ARM_SMMU": "m",
    "CONFIG_ARM_SMMU_QCOM_DEBUG": "n",
    "CONFIG_MINIDUMP_MAX_ENTRIES": "200",
    "CONFIG_MAC80211_RC_DEFAULT": "",
}
"#;
        let out = parse_bzl_config_dict(bzl);
        assert_eq!(
            out,
            vec![
                "CONFIG_ARCH_SUN=y",
                "CONFIG_ARM_SMMU=m",
                "# CONFIG_ARM_SMMU_QCOM_DEBUG is not set",
                "CONFIG_MINIDUMP_MAX_ENTRIES=200",
                "CONFIG_MAC80211_RC_DEFAULT=\"\"",
            ]
        );
    }

    #[test]
    fn test_parse_build_diagnostics() {
        let sample = "\
/ws/src/kernel/xiaomi/sm8735/drivers/foo/bar.c:42:10: fatal error: 'linux/tmelog.h' file not found
/ws/src/kernel/xiaomi/sm8735/drivers/foo/bar.c:42:10: fatal error: 'linux/tmelog.h' file not found
/ws/src/kernel/xiaomi/sm8735/drivers/foo/baz.c:99:12: error: incompatible function pointer types assigning to 'void (*)(struct platform_device *)' from 'int (struct platform_device *)'
ERROR: modpost: \"qcom_tzmem_alloc\" [drivers/firmware/qcom/qcom-scm.ko] undefined!
";
        let diags = parse_build_diagnostics(sample);
        assert_eq!(diags.len(), 3);
        assert_eq!(diags[0].category, "missing-header");
        assert_eq!(diags[0].file, "drivers/foo/bar.c");
        assert_eq!(diags[1].category, "void-remove");
        assert_eq!(diags[2].category, "modpost-undef");
    }
}
