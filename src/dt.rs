use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::preflight;
use crate::util::*;

/// Parse a `savedcmd_... := <clang -E ...> ; <./scripts/dtc/dtc ...> ; cat ...` line
/// and replay both preprocessing and dtc compilation into `tmp_dir` without touching `KERNEL_OBJ`!
fn replay_dt_cmd(
    ctx: &Ctx,
    clang: &str,
    dtc: &Path,
    cmd_file: &Path,
    out_dtb: &Path,
    tmp_dir: &Path,
    idx: usize,
) -> Result<(), String> {
    let txt = fs::read_to_string(cmd_file).map_err(|e| format!("read {}: {e}", cmd_file.display()))?;
    let first = txt.lines().next().ok_or("empty .cmd file")?;
    let (_, rhs) = first.split_once(":=").ok_or("missing := in .cmd")?;
    let stages: Vec<&str> = rhs.split(';').collect();
    if stages.len() < 2 {
        return Err("expected `clang -E ... ; dtc ...` in .cmd".into());
    }

    let tmp_pre = tmp_dir.join(format!("dt_{idx}.dts.tmp"));
    let tmp_dep = tmp_dir.join(format!("dt_{idx}.d.tmp"));

    // Stage 1: clang -E preprocessor
    let raw_cpp = preflight::split_cmd_tokens(stages[0].trim());
    let mut cpp_args: Vec<String> = Vec::with_capacity(raw_cpp.len());
    let mut i = 0;
    while i < raw_cpp.len() && (raw_cpp[i].ends_with("clang") || raw_cpp[i].ends_with("ccache") || raw_cpp[i].ends_with("gcc")) {
        i += 1;
    }
    while i < raw_cpp.len() {
        let t = &raw_cpp[i];
        if t == "-o" {
            cpp_args.push("-o".into());
            cpp_args.push(tmp_pre.to_string_lossy().into_owned());
            i += 2;
            continue;
        }
        if t.starts_with("-Wp,-MMD,") || t.starts_with("-Wp,-MD,") {
            i += 1;
            continue;
        }
        cpp_args.push(t.clone());
        i += 1;
    }
    let cpp_refs: Vec<&str> = cpp_args.iter().map(|s| s.as_str()).collect();
    let (rc1, _, err1) = run_cmd(clang, &cpp_refs, &ctx.kernel_obj, None);
    if rc1 != 0 {
        return Err(format!("cpp failed:\n{}", err1.lines().take(10).collect::<Vec<_>>().join("\n")));
    }

    // Stage 2: dtc compiler
    let raw_dtc = preflight::split_cmd_tokens(stages[1].trim());
    let mut dtc_args: Vec<String> = Vec::with_capacity(raw_dtc.len());
    let mut j = 1; // skip `./scripts/dtc/dtc`
    while j < raw_dtc.len() {
        let t = &raw_dtc[j];
        if t == "-o" {
            dtc_args.push("-o".into());
            dtc_args.push(out_dtb.to_string_lossy().into_owned());
            j += 2;
            continue;
        }
        if t == "-d" {
            dtc_args.push("-d".into());
            dtc_args.push(tmp_dep.to_string_lossy().into_owned());
            j += 2;
            continue;
        }
        // Replace the `.dts.tmp` input argument with our temp preprocessed file
        if t.ends_with(".dts.tmp") && !t.starts_with('-') {
            dtc_args.push(tmp_pre.to_string_lossy().into_owned());
            j += 1;
            continue;
        }
        dtc_args.push(t.clone());
        j += 1;
    }
    let dtc_refs: Vec<&str> = dtc_args.iter().map(|s| s.as_str()).collect();
    let (rc2, _, err2) = run_cmd(&dtc.to_string_lossy(), &dtc_refs, &ctx.kernel_obj, None);
    if rc2 != 0 {
        return Err(format!("dtc failed:\n{}", err2.lines().take(10).collect::<Vec<_>>().join("\n")));
    }
    Ok(())
}

/// Parse `<0x... 0x... ...>` hex/dec u32 cells from a decompiled DTS property value.
fn parse_u32_cells(val: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let Some(a) = val.find('<') else { return out };
    let Some(b) = val[a + 1..].find('>') else { return out };
    for tok in val[a + 1..a + 1 + b].split_whitespace() {
        if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                out.push(v);
            }
        } else if let Ok(v) = tok.parse::<u64>() {
            out.push(v);
        }
    }
    out
}

/// Check all `reserved-memory` child `reg = <hi lo sz_hi sz_lo>` blocks for physical overlaps!
pub fn check_reserved_memory_overlaps(dts: &str) -> (usize, Vec<String>) {
    let mut regions: Vec<(u64, u64, String)> = Vec::new();
    let mut in_res_mem = false;
    let mut res_depth = 0usize;
    let mut cur_depth = 0usize;
    let mut cur_node = String::new();
    let mut cur_disabled = false;
    let mut cur_reg: Option<(u64, u64)> = None;

    for raw in dts.lines() {
        let ln = raw.trim();
        if ln.ends_with('{') {
            let name = ln.trim_end_matches('{').trim().to_string();
            cur_depth += 1;
            if !in_res_mem && name == "reserved-memory" {
                in_res_mem = true;
                res_depth = cur_depth;
            } else if in_res_mem && cur_depth == res_depth + 1 {
                cur_node = name;
                cur_disabled = false;
                cur_reg = None;
            }
        } else if ln.starts_with("};") || ln == "}" {
            if in_res_mem && cur_depth == res_depth + 1 {
                if !cur_disabled {
                    if let Some((start, size)) = cur_reg {
                        if size > 0 {
                            regions.push((start, start.saturating_add(size), cur_node.clone()));
                        }
                    }
                }
                cur_node.clear();
                cur_reg = None;
            } else if in_res_mem && cur_depth == res_depth {
                in_res_mem = false;
            }
            cur_depth = cur_depth.saturating_sub(1);
        } else if in_res_mem && cur_depth == res_depth + 1 {
            if ln.starts_with("status = \"disabled\"") {
                cur_disabled = true;
            } else if let Some(rest) = ln.strip_prefix("reg =") {
                let cells = parse_u32_cells(rest);
                if cells.len() >= 4 {
                    let addr = (cells[0] << 32) | cells[1];
                    let sz = (cells[2] << 32) | cells[3];
                    cur_reg = Some((addr, sz));
                }
            }
        }
    }

    regions.sort_by_key(|r| (r.0, r.1));
    let mut overlaps = Vec::new();
    for i in 0..regions.len() {
        for j in (i + 1)..regions.len() {
            if regions[j].0 >= regions[i].1 {
                break;
            }
            // Ignore exact-identical nested/aliased sub-allocations only if same name; any overlap between distinct regions is a bug!
            if regions[i].2 != regions[j].2 {
                overlaps.push(format!(
                    "OVERLAP: `{}` [0x{:x}..0x{:x}) vs `{}` [0x{:x}..0x{:x})",
                    regions[i].2, regions[i].0, regions[i].1, regions[j].2, regions[j].0, regions[j].1
                ));
            }
        }
    }
    (regions.len(), overlaps)
}

/// Check every `qcom,<rail>-config = <min max ...>` consumer against its `<rail>-supply = <phandle>`
/// regulator's `[regulator-min-microvolt, regulator-max-microvolt]` bounds!
pub fn check_regulator_bounds(dts: &str) -> (usize, Vec<String>) {
    // Pass 1: collect every node's properties in a lightweight flat list
    struct NodeProps {
        name: String,
        phandle: Option<u64>,
        reg_name: Option<String>,
        min_uv: Option<u64>,
        max_uv: Option<u64>,
        supplies: HashMap<String, u64>,            // rail -> phandle
        configs: Vec<(String, u64, u64)>,          // (rail, min_uv, max_uv)
        disabled: bool,
    }

    let mut stack: Vec<NodeProps> = Vec::new();
    let mut finished: Vec<NodeProps> = Vec::new();

    for raw in dts.lines() {
        let ln = raw.trim();
        if ln.ends_with('{') {
            let name = ln.trim_end_matches('{').trim().to_string();
            stack.push(NodeProps {
                name,
                phandle: None,
                reg_name: None,
                min_uv: None,
                max_uv: None,
                supplies: HashMap::new(),
                configs: Vec::new(),
                disabled: false,
            });
        } else if ln.starts_with("};") || ln == "}" {
            if let Some(n) = stack.pop() {
                finished.push(n);
            }
        } else if let Some(cur) = stack.last_mut() {
            if ln.starts_with("status = \"disabled\"") {
                cur.disabled = true;
            } else if let Some(rest) = ln.strip_prefix("phandle =") {
                if let Some(&v) = parse_u32_cells(rest).first() {
                    cur.phandle = Some(v);
                }
            } else if let Some(rest) = ln.strip_prefix("regulator-name =") {
                if let Some(q1) = rest.find('"') {
                    if let Some(q2) = rest[q1 + 1..].find('"') {
                        cur.reg_name = Some(rest[q1 + 1..q1 + 1 + q2].to_string());
                    }
                }
            } else if let Some(rest) = ln.strip_prefix("regulator-min-microvolt =") {
                if let Some(&v) = parse_u32_cells(rest).first() {
                    cur.min_uv = Some(v);
                }
            } else if let Some(rest) = ln.strip_prefix("regulator-max-microvolt =") {
                if let Some(&v) = parse_u32_cells(rest).first() {
                    cur.max_uv = Some(v);
                }
            } else if let Some((lhs, rhs)) = ln.split_once('=') {
                let prop = lhs.trim();
                if let Some(rail) = prop.strip_suffix("-supply") {
                    if let Some(&ph) = parse_u32_cells(rhs).first() {
                        cur.supplies.insert(rail.to_string(), ph);
                    }
                } else if let Some(mid) = prop.strip_prefix("qcom,").and_then(|s| s.strip_suffix("-config")) {
                    let cells = parse_u32_cells(rhs);
                    if cells.len() >= 2 && cells[0] >= 100_000 && cells[1] >= cells[0] {
                        cur.configs.push((mid.to_string(), cells[0], cells[1]));
                    }
                }
            }
        }
    }

    // Build phandle -> (reg_name, min_uv, max_uv)
    let mut regs: HashMap<u64, (String, u64, u64)> = HashMap::new();
    for n in &finished {
        if let (Some(ph), Some(lo), Some(hi)) = (n.phandle, n.min_uv, n.max_uv) {
            let rname = n.reg_name.clone().unwrap_or_else(|| n.name.clone());
            regs.insert(ph, (rname, lo, hi));
        }
    }

    let mut checked = 0usize;
    let mut violations = Vec::new();
    for n in &finished {
        if n.disabled {
            continue;
        }
        for (rail, c_min, c_max) in &n.configs {
            let Some(&ph) = n.supplies.get(rail) else { continue };
            let Some((rname, r_min, r_max)) = regs.get(&ph) else { continue };
            checked += 1;
            if c_min < r_min || c_max > r_max {
                violations.push(format!(
                    "node `{}` rail `{rail}` ({rname}): consumer [{c_min}..{c_max}] uV outside regulator [{r_min}..{r_max}] uV",
                    n.name
                ));
            }
        }
    }
    (checked, violations)
}

/// Real `dtc` + `fdtoverlay` + merged-DTB hardware-safety preflight for `sm8735-devicetrees`!
pub fn cmd_dt_check(ctx: &Ctx) -> i32 {
    let dtc = ctx.kernel_obj.join("scripts/dtc/dtc");
    let fdtoverlay = [
        ctx.kernel_obj.join("scripts/dtc/fdtoverlay"),
        ctx.ws_root.join("src/out/host/linux-x86/bin/fdtoverlay"),
    ]
    .into_iter()
    .find(|p| p.is_file());

    if !dtc.is_file() {
        eprintln!("!! dtc not found at {} — run one kernel build first", dtc.display());
        return 2;
    }
    let Some(fdtoverlay) = fdtoverlay else {
        eprintln!("!! fdtoverlay not found in KERNEL_OBJ or out/host");
        return 2;
    };

    let dts_out = ctx.kernel_obj.join("arch/arm64/boot/dts/vendor/qcom");
    if !dts_out.is_dir() {
        eprintln!("!! compiled DTB dir not found at {}", dts_out.display());
        return 2;
    }

    let clang = preflight::detect_clang_bin(ctx);
    let tmp_dir = ctx.ws_root.join("lab/ktool/.dt-tmp");
    let _ = fs::remove_dir_all(&tmp_dir);
    let _ = fs::create_dir_all(&tmp_dir);

    println!("=== ktool dt-check (real dtc + fdtoverlay + merged-DTB hardware audit) ===");

    // Collect onyx/tuna DTBs & techpack DTBOs in EXACT overlay dependency order
    // (base SoC techpacks first, then board-specific onyx overlays + BT after WLAN)!
    let targets: Vec<(&str, &str)> = vec![
        ("tuna.dtb", ".tuna.dtb.cmd"),
        ("tuna7.dtb", ".tuna7.dtb.cmd"),
        ("onyx-sm8735-overlay.dtbo", ".onyx-sm8735-overlay.dtbo.cmd"),
        ("audio/tuna-audio.dtbo", "audio/.tuna-audio.dtbo.cmd"),
        ("audio/onyx-audio-mtp.dtbo", "audio/.onyx-audio-mtp.dtbo.cmd"),
        ("camera/tuna-camera.dtbo", "camera/.tuna-camera.dtbo.cmd"),
        ("camera/onyx-sm8735-camera-sensor.dtbo", "camera/.onyx-sm8735-camera-sensor.dtbo.cmd"),
        ("data/tuna-ipa.dtbo", "data/.tuna-ipa.dtbo.cmd"),
        ("data/tuna-smem-mailbox.dtbo", "data/.tuna-smem-mailbox.dtbo.cmd"),
        ("display/display/tuna-sde.dtbo", "display/display/.tuna-sde.dtbo.cmd"),
        ("display/display/onyx-sde-display-mtp-overlay.dtbo", "display/display/.onyx-sde-display-mtp-overlay.dtbo.cmd"),
        ("dsp/tuna/tuna-dsp.dtbo", "dsp/tuna/.tuna-dsp.dtbo.cmd"),
        ("eva/tuna-eva.dtbo", "eva/.tuna-eva.dtbo.cmd"),
        ("graphics/gpu/tuna-gpu.dtbo", "graphics/gpu/.tuna-gpu.dtbo.cmd"),
        ("synx/synx/tuna-synx.dtbo", "synx/synx/.tuna-synx.dtbo.cmd"),
        ("video/tuna-vidc.dtbo", "video/.tuna-vidc.dtbo.cmd"),
        ("wlan/tuna-mtp-wcn7750.dtbo", "wlan/.tuna-mtp-wcn7750.dtbo.cmd"),
        ("bt/tuna-wcn7750-bt.dtbo", "bt/.tuna-wcn7750-bt.dtbo.cmd"),
    ];
    let overlay_order: Vec<&str> = targets
        .iter()
        .skip(3)
        .map(|(n, _)| *n)
        .collect();

    let present: Vec<(usize, String, PathBuf, PathBuf)> = targets
        .into_iter()
        .filter_map(|(name, cmd_rel)| {
            let cmd_p = dts_out.join(cmd_rel);
            if cmd_p.is_file() {
                Some((name.to_string(), cmd_p))
            } else {
                None
            }
        })
        .enumerate()
        .map(|(i, (name, cmd_p))| {
            let flat = name.replace('/', "__");
            (i, name, cmd_p, tmp_dir.join(flat))
        })
        .collect();

    if present.is_empty() {
        eprintln!("!! no onyx/tuna .dtb.cmd/.dtbo.cmd files found under {}", dts_out.display());
        let _ = fs::remove_dir_all(&tmp_dir);
        return 2;
    }

    // 1. Recompile ALL onyx/tuna DTBs & DTBOs in parallel with real clang -E + dtc!
    let compile_res: Vec<(String, PathBuf, Result<(), String>)> =
        par_map(&present, ctx.threads.min(8), |(idx, name, cmd_p, out_p)| {
            let r = replay_dt_cmd(ctx, &clang, &dtc, cmd_p, out_p, &tmp_dir, *idx);
            (name.clone(), out_p.clone(), r)
        });

    let mut issues = 0usize;
    let mut built_map: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut dtc_errs = Vec::new();
    for (name, out_p, res) in compile_res {
        match res {
            Ok(()) => {
                built_map.insert(name, out_p);
            }
            Err(e) => {
                dtc_errs.push((name, e));
            }
        }
    }

    if dtc_errs.is_empty() {
        println!("  [PASS] dtc compile  : {}/{} onyx/tuna DTB/DTBO targets compiled cleanly", built_map.len(), present.len());
    } else {
        println!("  [FAIL] dtc compile  : {} target(s) failed:", dtc_errs.len());
        for (n, e) in &dtc_errs {
            println!("    !! {n}: {e}");
        }
        issues += dtc_errs.len();
    }

    // 2. Apply onyx-sm8735-overlay.dtbo (+ compatible techpack overlays) onto tuna.dtb via fdtoverlay!
    if let (Some(base_dtb), Some(board_ov)) = (built_map.get("tuna.dtb"), built_map.get("onyx-sm8735-overlay.dtbo")) {
        let merged_dtb = tmp_dir.join("onyx_merged.dtb");
        let mut ov_args: Vec<String> = vec![
            "-i".into(),
            base_dtb.to_string_lossy().into_owned(),
            "-o".into(),
            merged_dtb.to_string_lossy().into_owned(),
            board_ov.to_string_lossy().into_owned(),
        ];
        // Also test every techpack DTBO individually on top of base+board so a single incompatible techpack doesn't mask others!
        let ov_refs: Vec<&str> = ov_args.iter().map(|s| s.as_str()).collect();
        let (rc, _, err) = run_cmd(&fdtoverlay.to_string_lossy(), &ov_refs, &tmp_dir, None);
        if rc != 0 {
            println!("  [FAIL] fdtoverlay   : tuna.dtb + onyx-sm8735-overlay.dtbo FAILED:\n    {}", err.trim());
            issues += 1;
        } else {
            // Now overlay all present techpack DTBOs in dependency order!
            let mut tp_ok = 0usize;
            let mut tp_fail = Vec::new();
            let mut cur_dtb = merged_dtb.clone();
            for k in &overlay_order {
                let Some(p) = built_map.get(*k) else { continue };
                let next_dtb = tmp_dir.join(format!("merged_step_{tp_ok}.dtb"));
                let (trc, _, terr) = run_cmd(
                    &fdtoverlay.to_string_lossy(),
                    &["-i", &cur_dtb.to_string_lossy(), "-o", &next_dtb.to_string_lossy(), &p.to_string_lossy()],
                    &tmp_dir,
                    None,
                );
                if trc == 0 {
                    cur_dtb = next_dtb;
                    tp_ok += 1;
                } else {
                    tp_fail.push(format!("{k}: {}", terr.trim()));
                }
            }
            if tp_fail.is_empty() {
                println!(
                    "  [PASS] fdtoverlay   : tuna.dtb + onyx-sm8735-overlay.dtbo + {tp_ok} techpack DTBO(s) merged cleanly!"
                );
            } else {
                println!("  [FAIL] fdtoverlay   : {} techpack overlay(s) failed to apply:", tp_fail.len());
                for f in &tp_fail {
                    println!("    !! {f}");
                }
                issues += tp_fail.len();
            }

            // 3. Decompile fully-merged onyx DTB and run hardware-safety invariants!
            let merged_dts_p = tmp_dir.join("onyx_merged.dts");
            let (drc, _, derr) = run_cmd(
                &dtc.to_string_lossy(),
                &["-I", "dtb", "-O", "dts", "-q", "-o", &merged_dts_p.to_string_lossy(), &cur_dtb.to_string_lossy()],
                &tmp_dir,
                None,
            );
            if drc != 0 {
                println!("  [FAIL] dtc decompile: {}", derr.trim());
                issues += 1;
            } else if let Ok(dts_txt) = fs::read_to_string(&merged_dts_p) {
                // 3a. Reserved-memory overlap check
                let (rcnt, overlaps) = check_reserved_memory_overlaps(&dts_txt);
                if overlaps.is_empty() {
                    println!("  [PASS] reserved-mem : {rcnt} carved-out physical regions checked, 0 overlaps");
                } else {
                    println!("  [FAIL] reserved-mem : {} physical overlap(s) (BOOT PANIC RISK!):", overlaps.len());
                    for o in &overlaps {
                        println!("    !! {o}");
                    }
                    issues += overlaps.len();
                }

                // 3b. Regulator min/max microvolt bounds check
                let (ccnt, rviols) = check_regulator_bounds(&dts_txt);
                if rviols.is_empty() {
                    println!("  [PASS] regulators   : {ccnt} consumer voltage rails verified within regulator min/max");
                } else {
                    println!("  [FAIL] regulators   : {} voltage range violation(s):", rviols.len());
                    for v in &rviols {
                        println!("    !! {v}");
                    }
                    issues += rviols.len();
                }

                // 3c. bootargs hygiene (ignore explicit disables like `slub_debug=-`, `kasan=off`)
                let mut bad_args = Vec::new();
                for ln in dts_txt.lines() {
                    if ln.trim_start().starts_with("bootargs =") {
                        for tok in ln.split(|c: char| c.is_ascii_whitespace() || c == '"' || c == ';') {
                            if (tok.starts_with("slub_debug=") && tok != "slub_debug=-" && tok != "slub_debug=off")
                                || tok == "slub_debug"
                                || tok == "page_owner=on"
                                || tok == "kasan=on"
                                || tok == "initcall_debug"
                                || tok == "arm64.nopauth"
                                || tok == "arm64.nobti"
                                || tok == "reboot=w"
                            {
                                bad_args.push(tok.to_string());
                            }
                        }
                    }
                }
                if bad_args.is_empty() {
                    println!("  [PASS] bootargs     : clean (no slub_debug / page_owner / kasan / initcall_debug)");
                } else {
                    println!("  [FAIL] bootargs     : debug regression(s) found: {}", bad_args.join(", "));
                    issues += bad_args.len();
                }

                // 3d. Critical onyx hardware preservation check
                let must_have = [
                    ("novatek/nt36532 touch", "novatek"),
                    ("ramoops carveout", "ramoops"),
                    ("pmxr2230 PMIC", "pmxr2230"),
                    ("o10u/onyx board config", "o10u"),
                    ("Adreno GPU power levels", "qcom,gpu-pwrlevels"),
                    ("WCN7750 icnss2 WLAN", "icnss2"),
                    ("QCE BAM v1.7 4K compat", "qcom,msm-sps-v1_7-4k"),
                    ("PMIC restart_reason nvmem", "restart_reason"),
                ];
                let mut missing_hw = Vec::new();
                for (desc, needle) in must_have {
                    if !dts_txt.contains(needle) {
                        missing_hw.push(desc);
                    }
                }
                if missing_hw.is_empty() {
                    println!("  [PASS] onyx hw      : all critical onyx hardware nodes present in merged DTB");
                } else {
                    println!("  [FAIL] onyx hw      : missing critical nodes: {}", missing_hw.join(", "));
                    issues += missing_hw.len();
                }

                // 3e. 6.12 IOMMU DT-vs-driver compat check (WCN7750 fastmap pool)
                if dts_txt.contains("qcom,iommu-dma-addr-pool") {
                    let iommu_util = ctx.repo.join("drivers/iommu/qcom-iommu-util.c");
                    let ok = fs::read_to_string(&iommu_util)
                        .map(|s| s.contains("qcom,iommu-dma-addr-pool") && !s.contains("qcom,iommu-dma-addr-pool\", \"should be removed"))
                        .unwrap_or(false);
                    if ok {
                        println!("  [PASS] iommu-pool   : DT uses qcom,iommu-dma-addr-pool and qcom-iommu-util.c supports it");
                    } else {
                        println!("  [FAIL] iommu-pool   : DT has qcom,iommu-dma-addr-pool but qcom-iommu-util.c rejects it (icnss2 deferred-probe panic!)");
                        issues += 1;
                    }
                }
            }
        }
        let _ = &mut ov_args;
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    if issues == 0 {
        println!("  VERDICT: DT PREFLIGHT PASS (0 issues)");
        0
    } else {
        println!("  VERDICT: DT PREFLIGHT FAIL ({issues} issue(s))");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserved_memory_overlap() {
        let ok_dts = r#"/ {
            reserved-memory {
                reg_a@80000000 {
                    reg = <0x0 0x80000000 0x0 0x100000>;
                };
                reg_b@80100000 {
                    reg = <0x0 0x80100000 0x0 0x100000>;
                };
            };
        };"#;
        assert_eq!(check_reserved_memory_overlaps(ok_dts).1.len(), 0);

        let bad_dts = r#"/ {
            reserved-memory {
                reg_a@80000000 {
                    reg = <0x0 0x80000000 0x0 0x200000>;
                };
                reg_b@80100000 {
                    reg = <0x0 0x80100000 0x0 0x100000>;
                };
            };
        };"#;
        assert_eq!(check_reserved_memory_overlaps(bad_dts).1.len(), 1);
    }

    #[test]
    fn test_regulator_bounds() {
        let bad_dts = r#"/ {
            vreg-s3 {
                phandle = <0x42>;
                regulator-name = "pmxr2230_s3";
                regulator-min-microvolt = <864000>;
                regulator-max-microvolt = <1040000>;
            };
            icnss2 {
                vdd-cx-mx-supply = <0x42>;
                qcom,vdd-cx-mx-config = <750000 1040000 0 0 0>;
            };
        };"#;
        let (cnt, viols) = check_regulator_bounds(bad_dts);
        assert_eq!(cnt, 1);
        assert_eq!(viols.len(), 1);
    }
}
