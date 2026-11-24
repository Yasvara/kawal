mod abi;
mod bloblogs;
mod boot;
mod buildguard;
mod clo;
mod device;
mod dt;
mod elf;
mod explain;
mod gate;
mod kconfig_audit;
mod lognoise;
mod merge_intel;
mod port;
mod preflight;
mod romops;
mod runtime_audit;
mod search;
mod sync;
mod util;
mod verify;

use std::env;
use std::path::PathBuf;
use std::process;

use util::Ctx;

const HELP: &str = r#"kawal -- fast Rust kernel guard, merge driver, ELF/DTB auditor & crash/leak forensics (16-core + rg)

USAGE:
  kawal [-R <repo>] <command> [args...]

MERGE & CONFLICT TRIAGE:
  merge     <tag>                      GPG-signed merge w/ rerere=false + auto-fix bindings symlink
  merge3    <base> <theirs> [--dry-run] explicit-base 3-way merge (for squashed CLO/ACK trees!) + auto-triage
  triage    [--apply-safe]             16-core conflict classifier (ACK-KMI-GUARD / KBUILD-GUARD /
                                       CLO-SOC-OWNED / HEADER-WATCH / HYBRID / strict SAFE-THEIRS)
                                       + HUGE-LOCAL-DELTA & co-header drift warnings
  status                               list unmerged paths w/ [BUILT]/[unbuilt] + conflict code
  explain   [-s] [-c <sha>] [--no-hunks] [--no-patch] [files...]
                                       -s: <1s batched triage table of all conflicts (ALL-DUP/HAS-REV/MISS)
                                       default: full dossier (incoming WHY, Fixes: revert check, local
                                       divergence, 3-way :1:..:3: upstream intent, missing-symbol audit)
  dup-check [files...]                 16-core 3-way test: ALREADY-IN-HEAD vs CONTEXT-ONLY vs REAL-CONFLICT
  backport-check <repo.git> [--apply-clean] <shas...|@file>
                                       16-core patch status scanner (IN-LOG/ALREADY/CLEAN/CLEAN-C1/ADAPT)
                                       with [BUILT]/[ACK]/[CLO] risk tags & optional clean auto-apply
  why       <sym|sha|file:L[-E]> [paths...] [-n N]
                                       fast git archaeology: WHY merged, reverted, dropped, or changed
  flow      <symbol> [paths...] [--no-struct]
                                       rg-powered definitions, struct fields & callers w/ enclosing func

PRE-BUILD HIDDEN-MERGE GATES:
  markers                              rg scan for stray conflict markers
  audit     <tag>                      per-file numstat audit vs upstream + dangle scan
  dangle    [--built-only] [base head] batched rg check of newly introduced members/calls
  reverts   [pattern]                  list reverts tagged w/ KABI
  landmines <base> <tag>               new code vs still-active KABI header deletions
  vendorapi <base> <tag>               changed include/ prototypes vs vendor & sm8735-modules
  partial   <base> <tag> [--built-only] 16-core per-commit replay (BOTH!/SPLIT/ABSENT, skips byte-identical)
  dup-scan  <base> [head] [--all]      detect dup macros/funcs/locals/structs/fallthrough-labels & lock drift
  header-drop <from> <to> [--all]      detect upstream header +defs lost via --ours but still used in HEAD
  kconfig-audit [base] [head] [--config <f>]
                                       live Kconfig `source`-graph reachability vs vendor fragments +
                                       dropped `source`/`config`/`obj-$(CONFIG_*)` guard
  merge-audit <pre> [head] [--up-base <ref> --theirs <ref>] [--all]
                                       forensic tree-hash wipe detector (WIPED->THEIRS, DIFF-BLOAT >3x,
                                       HELD-OURS missed-upstream-fix advisory)
  struct-loss <base> [head] [--all]    detect vanished struct fields still referenced via ->
  verify    <from> [to] [--base <ref>] [--all]
                                       FULL 16-gate version-to-version merge verifier (merge-chain, GPG,
                                       markers, dup-scan, struct-loss, dangle, landmines, vendorapi,
                                       partial/absent, boot-risk, abi-audit, sem-audit, build-guard,
                                       ack-clash, header-drop, kconfig, merge-audit + verdict table)
  preflight [base] [--built-only] [--show-new] [--link] [--no-deps] [--no-guard] [files...]
                                       16-core REAL `clang` pre-flight check using Kbuild .o.cmd flags
                                       (+ auto new -I dirs, sibling fallback for new .c, build-guard).
                                       --built-only: skip speculative [NEW] unbuilt sibling files.
                                       --link: compile native ELF64 .o & verify 100% of MODPOST symbols!
  build-guard [base] [head]            5-gate build/sandbox guard: RO-source writes, Bazel-vs-Kbuild
                                       drift, UAPI bare-type hygiene, Soong Android.bp dups, +x scripts
  dt-check                             real dtc + fdtoverlay + merged-DTB audit (reserved-memory
                                       overlaps, regulator voltage bounds, bootargs, onyx hw nodes)
  boot-risk <from> [to] [--base <ref>] splash-hang blast-radius tiers, moved-block double-exec detector,
                                       DT clock/prop/IRQ string verifier vs sm8735-devicetrees, &
                                       removed EXPORT_SYMBOL / Android vendor-hook guard
  abi-audit <base> [head]              UAPI struct/ioctl stability, include/ KABI layout drift, &
                                       sm8735-modules KERNEL_VERSION(6,7..19) backport trap scanner
  sem-audit <base> [head] [--up <tag>] per-function lock/clock balance, early-return lock leaks & UAF
  img-audit [--save-baseline] [--log <file>]
                                       POST-BUILD pre-flash gate: UTS_RELEASE, image sync, pure-Rust
                                       ELF64 .ko audit (vermagic, depends=, symbols, CRCs, boot-order,
                                       modules.load*), .config/LTO/symvers hygiene, & build log scan
  live-audit [-s <serial>] [--full]    POST-FLASH adb kernel check (--full runs full `kawal health`)
  crash-log [-s <serial>] [--slots N]  decode /sys/fs/pstore, shutdown-checkpoints, blackbox & mtdoops slots
  health    [-s <serial>] [--only <secs>] [--full] [--dump-avc] [--json]
                                       single-shot full ADB device health audit (identity, kernel,
                                       HALs/services/restart-loops, boot-scoped crashes/ANRs,
                                       grouped SELinux AVCs, touch/THP/display, power/CPU/GPU/thermals,
                                       RAM/PSI/storage/net, & deduplicated logcat error + noise digest)
  runtime-audit [-s <serial>] [--window N] [--only <secs>] [--top N] [--full]
                [--save <file>] [--diff <file>] [--json]
                                       deep live power/memory/leak/daemon forensic audit: clean idle
                                       CPU & ctx-switch delta, DT-attributed I2C/SPI IRQs, cpuidle &
                                       wakelocks, RAM/ZRAM/slab/*PERS*/ADPF/lazy-daemons, FD & DMA-BUF
                                       leak hunter, vendor daemon bloat, alarms/jobs, AVCs, + baseline diff
  log-noise [-s <serial>] [--lines N] [--min N] [--level V,D,I,W,E] [--all] [--no-blobs] [--json]
                                       hunt noisy V/D/I/W/E logcat spam, map PIDs -> exact prebuilt
                                       Xiaomi/vendor ELF in vendor/xiaomi/onyx/proprietary/, check
                                       liblog imports & log.tag.* props, & emit ELF-PATCH vs PROP plan
  blob-logs <target...> [-f <pat>] [-l V,D,I,W,E] [--emit-fixup] [--limit N] [--json]
                                       AArch64 ELF (llvm-objdump/readelf) & APK/DEX (dexdump) log
                                       callsite + log-level global/prop tracer w/ verified-unique
                                       extract-files.py `sig_replace` patch generator
  check     <base> <tag> [--all]       alias for pre-build gate (markers+dangle+landmines+vendorapi+partial)
  config    <baseline> [current]       diff generated .config for hardening/debug regressions
  clo-delta <clo_ref> [stable_ref]     deduplicated QCOM driver commits in CLO ref not in HEAD
  clo       diff <old.xml> <new.xml> [--filter <pat>] [--check-local <src_root>]
                                       side-by-side CLO/Android manifest XML diff (<refs> + <project>)
  clo       probe <subpath> <cache.git> <target_rev> [--filter <pat>]
                                       blob-SHA1 fork-point fingerprinter for squashed Xiaomi repos!
  clo       merge <subpath> <cache.git> <base> <target> [--dry-run]
                                       true 3-way file merge preserving Xiaomi/custom code automatically

MAJOR KERNEL PORTING (6.6 -> 6.12 / KP 5.0 -> 6.18):
  port      delta [--base <ref>] [--head <ref>] [--target <dir|ref>] [--all]
                                       classify custom delta (XIAOMI-NEW, QCOM-SOC sun/tuna, CORE-PATCHED)
                                       filtering out Linux stable-subsumed files + target parity check
  port      api-scan [--target 6.12|6.18] [--scope kernel|modules|all] [--detail] [--guards-only]
                                       16-core preprocessor-aware 6.7..6.12/6.18 breaking-API scanner
                                       across Xiaomi drivers & sm8735-modules + LINUX_VERSION_CODE map
  port      kabi-check <target_dir> [--upstream <ref>]
                                       4-gate zero-KABI-break checker: GKI symbol lists & KABI reserve
                                       slots, UAPI HAL compat, Android vendor hooks, & onyx_perf Kconfig
  port      config-check <fragment> [target_kernel_dir]
                                       validate every CONFIG_* in a fragment against target Kconfig tree
  port      dt-compat [target_kernel_dir]
                                       verify every onyx/tuna/sun DT compatible has a driver match
  port      overlay-soc <soc.git> <ref> [--common <common.git> <ref>] [--apply]
                                       smart KP 5.0 soc-repo -> Kbuild integrator (preserves common
                                       built-ins, merges Makefiles/Kconfigs, guards core KABI headers)
  port      bzl2config <soc.git> <ref> <configs/sun_perf.bzl> [--out <file>]
                                       convert KP 5.0 Starlark .bzl config dict to Kbuild .config
  port      kbuild-audit [kernel_dir]  pre-make gate: broken Kconfig sources, dup configs, dangling .o
  port      header-diff <soc.git> <ref> [--common <common.git> <ref>]
                                       verify all `<...>` kernel headers used by modules/Xiaomi in KP 5.0

ROM / KERNEL / MODULE SYNC & LINEAGE DECOUPLING:
  sync      latest [--all|--qssi|--vendor|--kernel|--techpacks|--aosp|--lineage] [--fetch-xml]
                                       live upstream radar vs local workspace (CLO QSSI 17, Pakala vendor,
                                       KP 4.0, Linux 6.6 LTS, 9 techpacks, AOSP 17, LineageOS 24.0)
  sync      fetch <tag> [--out <file>] [--with-techpacks]
                                       download any CLO manifest XML (LA.QSSI/LA.VENDOR/KERNEL.PLATFORM/TP)
  sync      status [--filter <pat>] [--dirty] [--ported] [--drift]
                                       16-core dashboard of all ~1000 ROM repos (PORTED/CLO/LINEAGE/DIRTY)
  sync      plan <new.xml> [--old <old.xml>] [--filter <pat>] [--commits]
                                       pre-bump planner: MANUAL-MERGE vs AUTO-FF vs SHADOWED-LINEAGE
  sync      apply <new.xml> [--old <old.xml>] [--dry-run] [-j N] [--filter <pat>] [--include-prebuilts] [--update-manifest]
                                       safe parallel CLO fast-forwarder (never touches ported/dirty repos)
  sync      merge <new.xml> [--old <old.xml>] [--dry-run] [-j N] [--filter <pat>] [--update-manifest]
                                       promisor-safe in-memory merge-tree + GPG-signed CLO merger for MANUAL-MERGE repos
  prebuilts [--check-upstream] [--filter <pat>]
                                       toolchain & SDK inventory (Clang/Rust/Go/SDK/JDK/R8/module_sdk) + live AOSP/CLO radar
  hygiene   [--fix-tmppacks]           16-core workspace gate (SPEC tags, wip dumps, GPG sigs, detached dirty, tmp_pack cleanup)
  push      [--apply] [--filter <pat>] [--all]
                                       pre-push audit & safe batch pusher across Yasvara/device/kernel remotes
  decouple  [--filter <pat>] [--scan-refs] [--check-delta]
                                       LineageOS decoupling audit (unused SoCs, CLO overrides, apps, live refs)

GLOBAL FLAGS & ENV:
  -R, --repo <path>    operate on any git repo (sm8735, sm8735-modules, devicetrees, ROM repos)
  YASVARA_KERNEL / YASVARA_MODULES / YASVARA_KERNEL_OBJ
"#;

fn main() {
    // Restore default SIGPIPE behavior so `kawal ... | head` exits cleanly without panicking.
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn signal(sig: i32, handler: usize) -> usize;
        }
        signal(13, 0);
    }

    let raw: Vec<String> = env::args().skip(1).collect();
    if raw.is_empty() || raw[0] == "-h" || raw[0] == "--help" {
        print!("{HELP}");
        return;
    }

    let mut repo_override: Option<String> = None;
    let mut i = 0;
    while i < raw.len() {
        if (raw[i] == "-R" || raw[i] == "--repo") && i + 1 < raw.len() {
            repo_override = Some(raw[i + 1].clone());
            i += 2;
        } else {
            break;
        }
    }
    if i >= raw.len() {
        print!("{HELP}");
        process::exit(1);
    }

    let cmd = raw[i].as_str();
    let args = &raw[i + 1..];
    let ctx = Ctx::new(repo_override.as_deref());

    let rc = match cmd {
        "merge" => {
            if args.is_empty() {
                eprintln!("usage: kawal merge <tag>");
                2
            } else {
                gate::cmd_merge(&ctx, &args[0])
            }
        }
        "merge3" => {
            let mut dry = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--dry-run" || a == "--dry" {
                    dry = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            if pos.len() < 2 {
                eprintln!("usage: kawal merge3 <base> <theirs> [--dry-run]");
                2
            } else {
                merge_intel::cmd_merge3(&ctx, pos[0], pos[1], dry)
            }
        }
        "triage" => {
            let apply_safe = args.iter().any(|a| a == "--apply-safe");
            merge_intel::cmd_triage(&ctx, None, None, apply_safe)
        }
        "header-drop" => {
            let mut all = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--all" {
                    all = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            if pos.len() < 2 {
                eprintln!("usage: kawal header-drop <from> <to> [--all]");
                2
            } else {
                merge_intel::cmd_header_drop(&ctx, pos[0], pos[1], all)
            }
        }
        "kconfig-audit" => {
            let mut extra_cfgs: Vec<PathBuf> = Vec::new();
            let mut pos: Vec<&str> = Vec::new();
            let mut k = 0;
            while k < args.len() {
                if (args[k] == "--config" || args[k] == "-c") && k + 1 < args.len() {
                    extra_cfgs.push(PathBuf::from(&args[k + 1]));
                    k += 2;
                } else {
                    pos.push(args[k].as_str());
                    k += 1;
                }
            }
            let base = pos.first().copied();
            let head = pos.get(1).copied().unwrap_or("HEAD");
            kconfig_audit::cmd_kconfig_audit(&ctx, base, head, &extra_cfgs)
        }
        "merge-audit" => {
            let mut all = false;
            let mut up_base: Option<&str> = None;
            let mut theirs: Option<&str> = None;
            let mut pos: Vec<&str> = Vec::new();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--all" => all = true,
                    "--up-base" | "--upstream-base" if k + 1 < args.len() => {
                        up_base = Some(args[k + 1].as_str());
                        k += 1;
                    }
                    "--theirs" if k + 1 < args.len() => {
                        theirs = Some(args[k + 1].as_str());
                        k += 1;
                    }
                    other => pos.push(other),
                }
                k += 1;
            }
            if pos.is_empty() {
                eprintln!("usage: kawal merge-audit <pre> [head] [--up-base <ref> --theirs <ref>] [--all]");
                2
            } else {
                kconfig_audit::cmd_merge_audit(
                    &ctx,
                    pos[0],
                    pos.get(1).copied().unwrap_or("HEAD"),
                    up_base,
                    theirs,
                    all,
                )
            }
        }
        "backport-check" => {
            let mut apply_clean = false;
            let mut pos: Vec<String> = Vec::new();
            for a in args {
                if a == "--apply-clean" {
                    apply_clean = true;
                } else {
                    pos.push(a.clone());
                }
            }
            if pos.len() < 2 {
                eprintln!("usage: kawal backport-check <upstream.git> [--apply-clean] <shas...|@file>");
                2
            } else {
                merge_intel::cmd_backport_check(&ctx, &pos[0], &pos[1..], apply_clean)
            }
        }
        "status" => gate::cmd_status(&ctx),
        "markers" => gate::cmd_markers(&ctx),
        "explain" => {
            let mut summary = false;
            let mut show_hunks = true;
            let mut show_patch = true;
            let mut commit: Option<String> = None;
            let mut files = Vec::new();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "-s" | "--summary" => summary = true,
                    "--no-hunks" => show_hunks = false,
                    "--no-patch" => show_patch = false,
                    "-c" | "--commit" if k + 1 < args.len() => {
                        commit = Some(args[k + 1].clone());
                        k += 1;
                    }
                    other => files.push(other.to_string()),
                }
                k += 1;
            }
            explain::cmd_explain(&ctx, &files, commit.as_deref(), show_hunks, show_patch, summary)
        }
        "dup-check" => explain::cmd_dup_check(&ctx, args),
        "why" => {
            let mut limit = 12usize;
            let mut pos = Vec::new();
            let mut k = 0;
            while k < args.len() {
                if (args[k] == "-n" || args[k] == "--limit") && k + 1 < args.len() {
                    limit = args[k + 1].parse().unwrap_or(12);
                    k += 2;
                } else {
                    pos.push(args[k].clone());
                    k += 1;
                }
            }
            if pos.is_empty() {
                eprintln!("usage: kawal why <sym|sha|file:L[-E]> [paths...] [-n N]");
                2
            } else {
                search::cmd_why(&ctx, &pos[0], &pos[1..], limit)
            }
        }
        "flow" => {
            let mut show_struct = true;
            let mut pos = Vec::new();
            for a in args {
                if a == "--no-struct" {
                    show_struct = false;
                } else {
                    pos.push(a.clone());
                }
            }
            if pos.is_empty() {
                eprintln!("usage: kawal flow <symbol> [paths...] [--no-struct]");
                2
            } else {
                search::cmd_flow(&ctx, &pos[0], &pos[1..], show_struct)
            }
        }
        "audit" => {
            if args.is_empty() {
                eprintln!("usage: kawal audit <tag>");
                2
            } else {
                gate::cmd_audit(&ctx, &args[0])
            }
        }
        "dangle" => {
            let mut built_only = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--built-only" {
                    built_only = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            let rng = if pos.len() >= 2 { Some((pos[0], pos[1])) } else { None };
            gate::cmd_dangle(&ctx, rng, built_only)
        }
        "reverts" => gate::cmd_reverts(&ctx, args.first().map(|s| s.as_str()).unwrap_or("")),
        "landmines" => {
            if args.len() < 2 {
                eprintln!("usage: kawal landmines <base> <tag>");
                2
            } else {
                gate::cmd_landmines(&ctx, &args[0], &args[1])
            }
        }
        "vendorapi" => {
            if args.len() < 2 {
                eprintln!("usage: kawal vendorapi <base> <tag>");
                2
            } else {
                gate::cmd_vendorapi(&ctx, &args[0], &args[1])
            }
        }
        "partial" => {
            let mut built_only = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--built-only" {
                    built_only = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            if pos.len() < 2 {
                eprintln!("usage: kawal partial <base> <tag> [--built-only]");
                2
            } else {
                gate::cmd_partial(&ctx, pos[0], pos[1], built_only)
            }
        }
        "dup-scan" => {
            let mut all = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--all" {
                    all = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            if pos.is_empty() {
                eprintln!("usage: kawal dup-scan <base> [head] [--all]");
                2
            } else {
                verify::cmd_dup_scan(&ctx, pos[0], pos.get(1).copied().unwrap_or("HEAD"), all)
            }
        }
        "struct-loss" => {
            let mut all = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--all" {
                    all = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            if pos.is_empty() {
                eprintln!("usage: kawal struct-loss <base> [head] [--all]");
                2
            } else {
                verify::cmd_struct_loss(&ctx, pos[0], pos.get(1).copied().unwrap_or("HEAD"), all)
            }
        }
        "verify" => {
            let mut all = false;
            let mut base_ov: Option<&str> = None;
            let mut pos = Vec::new();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--all" => all = true,
                    "--base" | "-b" if k + 1 < args.len() => {
                        base_ov = Some(args[k + 1].as_str());
                        k += 1;
                    }
                    other => pos.push(other),
                }
                k += 1;
            }
            if pos.is_empty() {
                eprintln!("usage: kawal verify <from> [to] [--base <ref>] [--all]");
                2
            } else {
                verify::cmd_verify(&ctx, pos[0], pos.get(1).copied(), base_ov, all)
            }
        }
        "preflight" => {
            let mut with_deps = true;
            let mut link_check = false;
            let mut run_guard = true;
            let mut built_only = false;
            let mut show_new = false;
            let mut base: Option<String> = None;
            let mut files: Vec<String> = Vec::new();
            for a in args {
                if a == "--no-deps" {
                    with_deps = false;
                } else if a == "--link" {
                    link_check = true;
                } else if a == "--no-guard" {
                    run_guard = false;
                } else if a == "--built-only" {
                    built_only = true;
                } else if a == "--show-new" {
                    show_new = true;
                } else if a.ends_with(".c") || a.ends_with(".h") {
                    files.push(a.clone());
                } else if base.is_none() {
                    base = Some(a.clone());
                } else {
                    files.push(a.clone());
                }
            }
            preflight::cmd_preflight(
                &ctx,
                base.as_deref(),
                with_deps,
                link_check,
                run_guard,
                built_only,
                show_new,
                &files,
            )
        }
        "build-guard" => {
            let base = args.first().map(|s| s.as_str());
            let head = args.get(1).map(|s| s.as_str()).unwrap_or("HEAD");
            buildguard::cmd_build_guard(&ctx, base, head)
        }
        "dt-check" => dt::cmd_dt_check(&ctx),
        "abi-audit" => {
            if args.is_empty() {
                eprintln!("usage: kawal abi-audit <base> [head]");
                2
            } else {
                abi::cmd_abi_audit(&ctx, &args[0], args.get(1).map(|s| s.as_str()).unwrap_or("HEAD"))
            }
        }
        "sem-audit" => {
            let mut up_to: Option<&str> = None;
            let mut pos = Vec::new();
            let mut k = 0;
            while k < args.len() {
                if (args[k] == "--up" || args[k] == "-u") && k + 1 < args.len() {
                    up_to = Some(args[k + 1].as_str());
                    k += 1;
                } else {
                    pos.push(args[k].as_str());
                }
                k += 1;
            }
            if pos.is_empty() {
                eprintln!("usage: kawal sem-audit <base> [head] [--up <tag>]");
                2
            } else {
                abi::cmd_sem_audit(&ctx, pos[0], pos.get(1).copied().unwrap_or("HEAD"), up_to)
            }
        }
        "boot-risk" => {
            let mut base_ov: Option<&str> = None;
            let mut pos = Vec::new();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--base" | "-b" if k + 1 < args.len() => {
                        base_ov = Some(args[k + 1].as_str());
                        k += 1;
                    }
                    other => pos.push(other),
                }
                k += 1;
            }
            if pos.is_empty() {
                eprintln!("usage: kawal boot-risk <from> [to] [--base <ref>]");
                2
            } else {
                boot::cmd_boot_risk(&ctx, pos[0], pos.get(1).copied(), base_ov)
            }
        }
        "img-audit" => {
            let mut save_base = false;
            let mut log_ov: Option<PathBuf> = None;
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--save-baseline" => save_base = true,
                    "--log" if k + 1 < args.len() => {
                        log_ov = Some(PathBuf::from(&args[k + 1]));
                        k += 1;
                    }
                    _ => {}
                }
                k += 1;
            }
            boot::cmd_img_audit(&ctx, save_base, log_ov.as_deref())
        }
        "live-audit" => {
            let mut full = false;
            let mut serial: Option<String> = None;
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--full" | "--all" => {
                        full = true;
                        k += 1;
                    }
                    "-s" | "--serial" if k + 1 < args.len() => {
                        serial = Some(args[k + 1].clone());
                        k += 2;
                    }
                    _ => k += 1,
                }
            }
            if full {
                device::cmd_health(
                    &ctx,
                    &device::HealthOpts {
                        serial,
                        full: false,
                        ..Default::default()
                    },
                )
            } else {
                boot::cmd_live_audit(&ctx, serial.as_deref())
            }
        }
        "crash-log" | "panic-log" => {
            let mut serial: Option<String> = None;
            let mut slots = 8usize;
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "-s" | "--serial" if k + 1 < args.len() => {
                        serial = Some(args[k + 1].clone());
                        k += 2;
                    }
                    "--slots" | "-n" if k + 1 < args.len() => {
                        slots = args[k + 1].parse().unwrap_or(8);
                        k += 2;
                    }
                    _ => k += 1,
                }
            }
            boot::cmd_crash_log(&ctx, serial.as_deref(), slots)
        }
        "health" => {
            let mut opts = device::HealthOpts::default();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "-s" | "--serial" if k + 1 < args.len() => {
                        opts.serial = Some(args[k + 1].clone());
                        k += 2;
                    }
                    "--only" if k + 1 < args.len() => {
                        let set = opts.only.get_or_insert_with(std::collections::BTreeSet::new);
                        for part in args[k + 1].split(',') {
                            let p = part.trim().to_ascii_lowercase();
                            if !p.is_empty() {
                                set.insert(p);
                            }
                        }
                        k += 2;
                    }
                    "--full" | "-v" | "--verbose" => {
                        opts.full = true;
                        k += 1;
                    }
                    "--dump-avc" | "--avc" => {
                        opts.dump_avc = true;
                        k += 1;
                    }
                    "--json" => {
                        opts.json = true;
                        k += 1;
                    }
                    other => {
                        eprintln!("unknown health flag: {other}");
                        eprintln!("usage: kawal health [-s <serial>] [--only id,kernel,services,crashes,avc,touch,power,sys,logs] [--full] [--dump-avc] [--json]");
                        return;
                    }
                }
            }
            device::cmd_health(&ctx, &opts)
        }
        "runtime-audit" | "perf-audit" => {
            let mut opts = runtime_audit::RuntimeAuditOpts::default();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "-s" | "--serial" if k + 1 < args.len() => {
                        opts.serial = Some(args[k + 1].clone());
                        k += 2;
                    }
                    "-w" | "--window" if k + 1 < args.len() => {
                        opts.window_s = args[k + 1].parse().unwrap_or(5);
                        k += 2;
                    }
                    "--only" if k + 1 < args.len() => {
                        let set = opts.only.get_or_insert_with(std::collections::BTreeSet::new);
                        for part in args[k + 1].split(',') {
                            let p = part.trim().to_ascii_lowercase();
                            if !p.is_empty() {
                                set.insert(p);
                            }
                        }
                        k += 2;
                    }
                    "--top" | "-n" if k + 1 < args.len() => {
                        opts.top = args[k + 1].parse().unwrap_or(12).max(1);
                        k += 2;
                    }
                    "--full" | "-v" | "--verbose" => {
                        opts.full = true;
                        k += 1;
                    }
                    "--save" if k + 1 < args.len() => {
                        opts.save = Some(PathBuf::from(&args[k + 1]));
                        k += 2;
                    }
                    "--diff" if k + 1 < args.len() => {
                        opts.diff = Some(PathBuf::from(&args[k + 1]));
                        k += 2;
                    }
                    "--json" => {
                        opts.json = true;
                        k += 1;
                    }
                    other => {
                        eprintln!("unknown runtime-audit flag: {other}");
                        eprintln!("usage: kawal runtime-audit [-s <serial>] [--window N] [--only cpu,irq,power,mem,fd,dmabuf,daemons,alarms,avc] [--top N] [--full] [--save <file>] [--diff <file>] [--json]");
                        return;
                    }
                }
            }
            runtime_audit::cmd_runtime_audit(&ctx, &opts)
        }
        "log-noise" => {
            let mut opts = lognoise::LogNoiseOpts::default();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "-s" | "--serial" if k + 1 < args.len() => {
                        opts.serial = Some(args[k + 1].clone());
                        k += 2;
                    }
                    "-n" | "--lines" if k + 1 < args.len() => {
                        opts.lines = args[k + 1].parse().unwrap_or(8000);
                        k += 2;
                    }
                    "--min" if k + 1 < args.len() => {
                        opts.min_hits = args[k + 1].parse().unwrap_or(5);
                        k += 2;
                    }
                    "--level" | "--levels" if k + 1 < args.len() => {
                        opts.levels.clear();
                        for tok in args[k + 1].split(',') {
                            for ch in tok.trim().to_ascii_uppercase().chars() {
                                if matches!(ch, 'V' | 'D' | 'I' | 'W' | 'E' | 'F') {
                                    opts.levels.insert(ch);
                                }
                            }
                        }
                        k += 2;
                    }
                    "--include-err" => {
                        opts.levels.insert('E');
                        k += 1;
                    }
                    "--all" => {
                        opts.include_all = true;
                        k += 1;
                    }
                    "--no-blobs" => {
                        opts.resolve_blobs = false;
                        k += 1;
                    }
                    "--json" => {
                        opts.json = true;
                        k += 1;
                    }
                    other => {
                        eprintln!("unknown log-noise flag: {other}");
                        eprintln!("usage: kawal log-noise [-s <serial>] [--lines N] [--min N] [--level V,D,I,W,E] [--all] [--no-blobs] [--json]");
                        return;
                    }
                }
            }
            lognoise::cmd_log_noise(&ctx, &opts)
        }
        "blob-logs" => {
            let mut opts = bloblogs::BlobLogsOpts::default();
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "-f" | "--filter" if k + 1 < args.len() => {
                        opts.filter = Some(args[k + 1].clone());
                        k += 2;
                    }
                    "-l" | "--level" | "--levels" if k + 1 < args.len() => {
                        let set = opts.levels.get_or_insert_with(std::collections::BTreeSet::new);
                        for tok in args[k + 1].split(',') {
                            for ch in tok.trim().to_ascii_uppercase().chars() {
                                if matches!(ch, 'V' | 'D' | 'I' | 'W' | 'E' | 'F' | '?') {
                                    set.insert(ch);
                                }
                            }
                        }
                        k += 2;
                    }
                    "--emit-fixup" | "--fixup" => {
                        opts.emit_fixup = true;
                        k += 1;
                    }
                    "--limit" | "-n" if k + 1 < args.len() => {
                        opts.limit = args[k + 1].parse().unwrap_or(40);
                        k += 2;
                    }
                    "--json" => {
                        opts.json = true;
                        k += 1;
                    }
                    other if !other.starts_with('-') => {
                        opts.targets.push(other.to_string());
                        k += 1;
                    }
                    other => {
                        eprintln!("unknown blob-logs flag: {other}");
                        eprintln!("usage: kawal blob-logs <target...> [-f <pat>] [-l V,D,I,W,E] [--emit-fixup] [--limit N] [--json]");
                        return;
                    }
                }
            }
            bloblogs::cmd_blob_logs(&ctx, &opts)
        }
        "check" => {
            let mut all = false;
            let mut pos = Vec::new();
            for a in args {
                if a == "--all" {
                    all = true;
                } else {
                    pos.push(a.as_str());
                }
            }
            if pos.len() < 2 {
                eprintln!("usage: kawal check <base> <tag> [--all]");
                2
            } else {
                gate::cmd_check(&ctx, pos[0], pos[1], all)
            }
        }
        "config" => {
            if args.is_empty() {
                eprintln!("usage: kawal config <baseline> [current]");
                2
            } else {
                let base = PathBuf::from(&args[0]);
                let cur = args
                    .get(1)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| ctx.kernel_obj.join(".config"));
                gate::cmd_config(&base, &cur)
            }
        }
        "clo" => {
            if args.is_empty() {
                eprintln!("usage: kawal clo <diff|probe|merge> ...");
                2
            } else {
                match args[0].as_str() {
                    "diff" => {
                        let mut flt: Option<&str> = None;
                        let mut chk_local: Option<PathBuf> = None;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            if (args[k] == "--filter" || args[k] == "-f") && k + 1 < args.len() {
                                flt = Some(args[k + 1].as_str());
                                k += 2;
                            } else if args[k] == "--check-local" && k + 1 < args.len() {
                                chk_local = Some(PathBuf::from(&args[k + 1]));
                                k += 2;
                            } else {
                                pos.push(args[k].as_str());
                                k += 1;
                            }
                        }
                        if pos.len() < 2 {
                            eprintln!("usage: kawal clo diff <old.xml> <new.xml> [--filter <pat>] [--check-local <src>]");
                            2
                        } else {
                            clo::cmd_clo_diff(
                                PathBuf::from(pos[0]).as_path(),
                                PathBuf::from(pos[1]).as_path(),
                                flt,
                                chk_local.as_deref(),
                            )
                        }
                    }
                    "probe" => {
                        let mut flt: Option<&str> = None;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            if (args[k] == "--filter" || args[k] == "-f") && k + 1 < args.len() {
                                flt = Some(args[k + 1].as_str());
                                k += 2;
                            } else {
                                pos.push(args[k].as_str());
                                k += 1;
                            }
                        }
                        if pos.len() < 3 {
                            eprintln!("usage: kawal -R <repo> clo probe <subpath> <cache.git> <target_rev> [--filter <pat>]");
                            2
                        } else {
                            clo::cmd_clo_probe(&ctx, pos[0], PathBuf::from(pos[1]).as_path(), pos[2], flt)
                        }
                    }
                    "merge" => {
                        let mut dry = false;
                        let mut pos = Vec::new();
                        for a in &args[1..] {
                            if a == "--dry-run" {
                                dry = true;
                            } else {
                                pos.push(a.as_str());
                            }
                        }
                        if pos.len() < 4 {
                            eprintln!("usage: kawal -R <repo> clo merge <subpath> <cache.git> <base> <target> [--dry-run]");
                            2
                        } else {
                            clo::cmd_clo_merge(&ctx, pos[0], PathBuf::from(pos[1]).as_path(), pos[2], pos[3], dry)
                        }
                    }
                    other => {
                        eprintln!("unknown clo subcommand: {other}");
                        2
                    }
                }
            }
        }
        "clo-delta" => {
            if args.is_empty() {
                eprintln!("usage: kawal clo-delta <clo_ref> [stable_ref]");
                2
            } else {
                gate::cmd_clo_delta(&ctx, &args[0], args.get(1).map(|s| s.as_str()))
            }
        }
        "sync" => {
            if args.is_empty() {
                eprintln!("usage: kawal sync <latest|fetch|status|plan|apply> ...");
                2
            } else {
                match args[0].as_str() {
                    "latest" => {
                        let mut opts = sync::LatestOpts::default();
                        for a in &args[1..] {
                            match a.as_str() {
                                "--all" => {
                                    opts.qssi = true;
                                    opts.vendor = true;
                                    opts.kernel = true;
                                    opts.techpacks = true;
                                    opts.aosp = true;
                                    opts.lineage = true;
                                }
                                "--qssi" | "--framework" => opts.qssi = true,
                                "--vendor" | "--modules" => opts.vendor = true,
                                "--kernel" => opts.kernel = true,
                                "--techpacks" | "--tp" => opts.techpacks = true,
                                "--aosp" => opts.aosp = true,
                                "--lineage" | "--los" => opts.lineage = true,
                                "--fetch-xml" | "--fetch" => opts.fetch_xml = true,
                                other => {
                                    eprintln!("unknown sync latest flag: {other}");
                                    return;
                                }
                            }
                        }
                        sync::cmd_sync_latest(&ctx, opts)
                    }
                    "fetch" => {
                        let mut out_p: Option<PathBuf> = None;
                        let mut with_tp = false;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--out" | "-o" if k + 1 < args.len() => {
                                    out_p = Some(PathBuf::from(&args[k + 1]));
                                    k += 2;
                                }
                                "--with-techpacks" | "--tp" => {
                                    with_tp = true;
                                    k += 1;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.is_empty() {
                            eprintln!("usage: kawal sync fetch <tag> [--out <file>] [--with-techpacks]");
                            2
                        } else {
                            sync::cmd_sync_fetch(&ctx, pos[0], out_p.as_deref(), with_tp)
                        }
                    }
                    "status" => {
                        let mut flt: Option<&str> = None;
                        let mut dirty = false;
                        let mut ported = false;
                        let mut drift = false;
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--filter" | "-f" if k + 1 < args.len() => {
                                    flt = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                "--dirty" => {
                                    dirty = true;
                                    k += 1;
                                }
                                "--ported" => {
                                    ported = true;
                                    k += 1;
                                }
                                "--drift" | "--behind" => {
                                    drift = true;
                                    k += 1;
                                }
                                _ => k += 1,
                            }
                        }
                        sync::cmd_sync_status(&ctx, flt, dirty, ported, drift)
                    }
                    "plan" => {
                        let mut old_p: Option<PathBuf> = None;
                        let mut flt: Option<&str> = None;
                        let mut with_commits = false;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--old" if k + 1 < args.len() => {
                                    old_p = Some(PathBuf::from(&args[k + 1]));
                                    k += 2;
                                }
                                "--filter" | "-f" if k + 1 < args.len() => {
                                    flt = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                "--commits" => {
                                    with_commits = true;
                                    k += 1;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.is_empty() {
                            eprintln!("usage: kawal sync plan <new.xml> [--old <old.xml>] [--filter <pat>] [--commits]");
                            2
                        } else {
                            sync::cmd_sync_plan(
                                &ctx,
                                PathBuf::from(pos[0]).as_path(),
                                old_p.as_deref(),
                                flt,
                                with_commits,
                            )
                        }
                    }
                    "apply" => {
                        let mut old_p: Option<PathBuf> = None;
                        let mut flt: Option<&str> = None;
                        let mut dry = false;
                        let mut jobs = 4usize;
                        let mut inc_pre = false;
                        let mut upd_man = false;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--old" if k + 1 < args.len() => {
                                    old_p = Some(PathBuf::from(&args[k + 1]));
                                    k += 2;
                                }
                                "--filter" | "-f" if k + 1 < args.len() => {
                                    flt = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                "-j" if k + 1 < args.len() => {
                                    jobs = args[k + 1].parse().unwrap_or(4);
                                    k += 2;
                                }
                                "--dry-run" | "--dry" => {
                                    dry = true;
                                    k += 1;
                                }
                                "--include-prebuilts" => {
                                    inc_pre = true;
                                    k += 1;
                                }
                                "--update-manifest" => {
                                    upd_man = true;
                                    k += 1;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.is_empty() {
                            eprintln!("usage: kawal sync apply <new.xml> [--old <old.xml>] [--dry-run] [-j N] [--filter <pat>]");
                            2
                        } else {
                            sync::cmd_sync_apply(
                                &ctx,
                                PathBuf::from(pos[0]).as_path(),
                                old_p.as_deref(),
                                flt,
                                dry,
                                jobs,
                                inc_pre,
                                upd_man,
                            )
                        }
                    }
                    "merge" => {
                        let mut old_p: Option<PathBuf> = None;
                        let mut flt: Option<&str> = None;
                        let mut dry = false;
                        let mut jobs = 3usize;
                        let mut upd_man = false;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--old" if k + 1 < args.len() => {
                                    old_p = Some(PathBuf::from(&args[k + 1]));
                                    k += 2;
                                }
                                "--filter" | "-f" if k + 1 < args.len() => {
                                    flt = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                "-j" if k + 1 < args.len() => {
                                    jobs = args[k + 1].parse().unwrap_or(3);
                                    k += 2;
                                }
                                "--dry-run" | "--dry" => {
                                    dry = true;
                                    k += 1;
                                }
                                "--update-manifest" => {
                                    upd_man = true;
                                    k += 1;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.is_empty() {
                            eprintln!("usage: kawal sync merge <new.xml> [--old <old.xml>] [--dry-run] [-j N] [--filter <pat>] [--update-manifest]");
                            2
                        } else {
                            romops::cmd_sync_merge(
                                &ctx,
                                PathBuf::from(pos[0]).as_path(),
                                old_p.as_deref(),
                                flt,
                                dry,
                                jobs,
                                upd_man,
                            )
                        }
                    }
                    "prebuilts" => {
                        let mut check_up = false;
                        let mut flt: Option<&str> = None;
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--check-upstream" | "--upstream" | "-u" => {
                                    check_up = true;
                                    k += 1;
                                }
                                "--filter" | "-f" if k + 1 < args.len() => {
                                    flt = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                _ => k += 1,
                            }
                        }
                        romops::cmd_prebuilts(&ctx, check_up, flt)
                    }
                    other => {
                        eprintln!("unknown sync subcommand: {other}");
                        2
                    }
                }
            }
        }
        "prebuilts" => {
            let mut check_up = false;
            let mut flt: Option<&str> = None;
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--check-upstream" | "--upstream" | "-u" => {
                        check_up = true;
                        k += 1;
                    }
                    "--filter" | "-f" if k + 1 < args.len() => {
                        flt = Some(args[k + 1].as_str());
                        k += 2;
                    }
                    _ => k += 1,
                }
            }
            romops::cmd_prebuilts(&ctx, check_up, flt)
        }
        "hygiene" => {
            let fix_tmp = args.iter().any(|a| a == "--fix-tmppacks" || a == "--fix");
            romops::cmd_hygiene(&ctx, fix_tmp)
        }
        "push" => {
            let mut apply = false;
            let mut show_all = false;
            let mut flt: Option<&str> = None;
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--apply" => {
                        apply = true;
                        k += 1;
                    }
                    "--all" => {
                        show_all = true;
                        k += 1;
                    }
                    "--filter" | "-f" if k + 1 < args.len() => {
                        flt = Some(args[k + 1].as_str());
                        k += 2;
                    }
                    _ => k += 1,
                }
            }
            romops::cmd_push(&ctx, apply, flt, show_all)
        }
        "decouple" => {
            let mut flt: Option<&str> = None;
            let mut scan_refs = false;
            let mut check_delta = false;
            let mut k = 0;
            while k < args.len() {
                match args[k].as_str() {
                    "--filter" | "-f" if k + 1 < args.len() => {
                        flt = Some(args[k + 1].as_str());
                        k += 2;
                    }
                    "--scan-refs" | "--refs" => {
                        scan_refs = true;
                        k += 1;
                    }
                    "--check-delta" | "--delta" => {
                        check_delta = true;
                        k += 1;
                    }
                    _ => k += 1,
                }
            }
            sync::cmd_decouple(&ctx, flt, scan_refs, check_delta)
        }
        "port" => {
            if args.is_empty() {
                eprintln!("usage: kawal port <delta|api-scan|kabi-check|config-check|dt-compat> [args...]");
                2
            } else {
                match args[0].as_str() {
                    "delta" => {
                        let mut base: Option<&str> = None;
                        let mut head = "HEAD";
                        let mut target: Option<&str> = None;
                        let mut all = false;
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--base" | "-b" if k + 1 < args.len() => {
                                    base = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                "--head" if k + 1 < args.len() => {
                                    head = args[k + 1].as_str();
                                    k += 2;
                                }
                                "--target" | "-t" if k + 1 < args.len() => {
                                    target = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                "--all" => {
                                    all = true;
                                    k += 1;
                                }
                                _ => k += 1,
                            }
                        }
                        port::cmd_port_delta(&ctx, base, head, target, all)
                    }
                    "api-scan" => {
                        let mut target = "6.12";
                        let mut scope = "all";
                        let mut detail = false;
                        let mut guards_only = false;
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--target" | "-t" if k + 1 < args.len() => {
                                    target = args[k + 1].as_str();
                                    k += 2;
                                }
                                "--scope" | "-s" if k + 1 < args.len() => {
                                    scope = args[k + 1].as_str();
                                    k += 2;
                                }
                                "--detail" | "-d" => {
                                    detail = true;
                                    k += 1;
                                }
                                "--guards-only" | "--guards" => {
                                    guards_only = true;
                                    k += 1;
                                }
                                _ => k += 1,
                            }
                        }
                        port::cmd_port_api_scan(&ctx, target, scope, detail, guards_only)
                    }
                    "kabi-check" => {
                        let mut upstream: Option<&str> = None;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--upstream" | "--base" if k + 1 < args.len() => {
                                    upstream = Some(args[k + 1].as_str());
                                    k += 2;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        let target_dir = pos
                            .first()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| ctx.repo.clone());
                        port::cmd_port_kabi_check(&ctx, &target_dir, upstream)
                    }
                    "config-check" => {
                        if args.len() < 2 {
                            eprintln!("usage: kawal port config-check <fragment> [target_kernel_dir]");
                            2
                        } else {
                            let frag = PathBuf::from(&args[1]);
                            let tdir = args.get(2).map(PathBuf::from);
                            port::cmd_port_config_check(&ctx, &frag, tdir.as_deref())
                        }
                    }
                    "dt-compat" => {
                        let tdir = args.get(1).map(PathBuf::from);
                        port::cmd_port_dt_compat(&ctx, tdir.as_deref())
                    }
                    "overlay-soc" => {
                        let mut apply = false;
                        let mut common_git: Option<PathBuf> = None;
                        let mut common_ref: Option<String> = None;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--apply" => {
                                    apply = true;
                                    k += 1;
                                }
                                "--dry-run" => {
                                    apply = false;
                                    k += 1;
                                }
                                "--common" if k + 2 < args.len() => {
                                    common_git = Some(PathBuf::from(&args[k + 1]));
                                    common_ref = Some(args[k + 2].clone());
                                    k += 3;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.len() < 2 {
                            eprintln!("usage: kawal port overlay-soc <soc.git> <ref> [--common <common.git> <ref>] [--apply]");
                            2
                        } else {
                            let copt = common_git
                                .as_deref()
                                .zip(common_ref.as_deref());
                            port::cmd_port_overlay_soc(
                                &ctx,
                                PathBuf::from(pos[0]).as_path(),
                                pos[1],
                                copt,
                                apply,
                            )
                        }
                    }
                    "bzl2config" => {
                        let mut out_p: Option<PathBuf> = None;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--out" | "-o" if k + 1 < args.len() => {
                                    out_p = Some(PathBuf::from(&args[k + 1]));
                                    k += 2;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.len() < 3 {
                            eprintln!("usage: kawal port bzl2config <soc.git> <ref> <path.bzl> [--out <file>]");
                            2
                        } else {
                            port::cmd_port_bzl2config(
                                PathBuf::from(pos[0]).as_path(),
                                pos[1],
                                pos[2],
                                out_p.as_deref(),
                            )
                        }
                    }
                    "kbuild-audit" => {
                        let tdir = args.get(1).map(PathBuf::from);
                        port::cmd_port_kbuild_audit(&ctx, tdir.as_deref())
                    }
                    "header-diff" => {
                        let mut common_git: Option<PathBuf> = None;
                        let mut common_ref: Option<String> = None;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--common" if k + 2 < args.len() => {
                                    common_git = Some(PathBuf::from(&args[k + 1]));
                                    common_ref = Some(args[k + 2].clone());
                                    k += 3;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.len() < 2 {
                            eprintln!("usage: kawal port header-diff <soc.git> <ref> [--common <common.git> <ref>]");
                            2
                        } else {
                            let copt = common_git
                                .as_deref()
                                .zip(common_ref.as_deref());
                            port::cmd_port_header_diff(
                                &ctx,
                                PathBuf::from(pos[0]).as_path(),
                                pos[1],
                                copt,
                            )
                        }
                    }
                    "build-diag" => {
                        let mut top = 25usize;
                        let mut pos = Vec::new();
                        let mut k = 1;
                        while k < args.len() {
                            match args[k].as_str() {
                                "--top" if k + 1 < args.len() => {
                                    top = args[k + 1].parse().unwrap_or(25);
                                    k += 2;
                                }
                                other => {
                                    pos.push(other);
                                    k += 1;
                                }
                            }
                        }
                        if pos.is_empty() {
                            eprintln!("usage: kawal port build-diag <build.log> [--top N]");
                            2
                        } else {
                            port::cmd_port_build_diag(PathBuf::from(pos[0]).as_path(), top)
                        }
                    }
                    other => {
                        eprintln!("unknown port subcommand: {other}");
                        2
                    }
                }
            }
        }
        "-h" | "--help" => {
            print!("{HELP}");
            0
        }
        other => {
            eprintln!("unknown command: {other}\nRun `kawal --help` for usage.");
            2
        }
    };
    process::exit(rc);
}
