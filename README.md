# kawal

**kawal** (*guard / escort*) is a fast, zero-dependency Rust CLI built for Android & Linux kernel maintainers (developed for [Yasvara](https://github.com/Yasvara)).

## Features

- **Pre-build merge, triage & silent-bug gates (`merge`, `merge3`, `triage`, `explain`, `dup-check`, `header-drop`, `kconfig-audit`, `merge-audit`, `backport-check`, `dup-scan`, `verify`, `preflight`, `build-guard`)**:
  - Explicit-base 3-way merges (`merge3 --dry-run`) for squashed CLO/ACK trees with automatic conflict bucketing (`ACK-KMI-GUARD`, `KBUILD-GUARD`, `CLO-SOC-OWNED`, `HEADER-WATCH`, `HYBRID`, strict 0-divergence `SAFE-THEIRS`), `HUGE-LOCAL-DELTA` anti-wipe warnings, and co-changed sibling `.h` drift warnings.
  - 16-gate `verify` catching fallthrough double-cleanup labels (`err_a:` → `err_b:` repeating `device_del()`/`kfree()`), duplicate local declarations, macro-aliased function shadowing, cross-header struct redefinitions, dropped upstream header definitions (`header-drop`), ACK Per-VMA lock / `rust_binder.ko` export / KMI arity clashes (`ack-clash`), orphaned Kconfig `source` trees & dropped vendor `CONFIG_*`/`Makefile` targets (`kconfig-audit`), forensic `--theirs` tree-hash wipes & >3x diff bloat (`merge-audit`), KABI landmines, and per-commit replay (`BOTH!`/`SPLIT`/`ABSENT`).
  - 16-core `backport-check` (`IN-LOG`/`ALREADY`/`CLEAN`/`CLEAN-C1`/`ADAPT` with `[BUILT]`/`[ACK]`/`[CLO]` risk tags and `--apply-clean`) and real `clang` `preflight` (`--built-only`, `--link` ELF64 MODPOST symbol check, auto `kconfig-audit` whenever `Kconfig` changes).
- **Major kernel porting (`port delta`, `port api-scan`, `port kabi-check`, `port overlay-soc`, `port bzl2config`, `port build-diag`)**: Preprocessor-aware breaking-API scanner (6.6 → 6.12 / 6.18), regression guards, and build-log root-cause triage.
- **Devicetree & post-build image safety (`dt-check`, `img-audit`)**: Real `dtc` + `fdtoverlay` + merged-DTB hardware audit (reserved-memory overlaps, regulator bounds, bootargs), plus pure-Rust ELF64 `.ko` binary auditing (vermagic, `depends=`, `SHN_UNDEF`, `__versions` CRCs, partition load order, recovery ramdisk DRM sync, AVB footer, `.config` + LTO/Rust hygiene).
- **Live hardware & crash forensics (`live-audit`, `health`, `runtime-audit`, `crash-log`, `rawdump`, `log-noise`, `blob-logs`)**: Single-shot ADB kernel health check, idle CPU/IRQ/slab/vmalloc/DMA-BUF/FD leak hunting with JSON baseline diffs, and pure-Rust decoding of `/sys/fs/pstore`, `shutdown-checkpoints`, `blackbox`, `mtdoops`, live GPU faults/tombstones, and Qualcomm `Raw_Dmp!` v2 minidumps (`/dev/block/by-name/rawdump` — Gunyah EL2 `HYP_DIAG` + ARM SMMUv2 register decoder, PMIC PON `PLOG` history, Linux 6.12 `printk_ringbuffer` dmesg, Android binary `pmsg` logcat, KASLR/vCPU symbolizer, and Adreno KGSL eventlog).
- **ROM & upstream sync (`sync latest|fetch|status|plan|apply|merge`, `prebuilts`, `hygiene`, `push`)**: Parallel CLO/AOSP/ACK (Gitiles `Makefile` version probe)/LineageOS/Linux LTS (automatic GitHub mirror fallback) tracking and safe GPG-signed merges.

## Installation

```bash
cargo install kawal
```

## Quick Start

```bash
kawal --help
kawal merge3 ack/kp5-base ack/android16-6.12-lts --dry-run
kawal triage
kawal header-drop v6.12.117 v6.12.119
kawal kconfig-audit backup/pre-6.12.119 HEAD
kawal merge-audit backup/pre-6.12.119 HEAD --up-base v6.12.117 --theirs v6.12.119
kawal backport-check /path/to/linux-6.18.git <sha1> <sha2>
kawal verify v6.12.117 v6.12.119
kawal preflight --built-only --link
kawal dt-check
kawal img-audit
kawal live-audit -s <serial>
kawal crash-log -s <serial>
kawal rawdump -s <serial> --save ./rawdump-decoded
kawal runtime-audit -s <serial> --window 5 --full
```

Override workspace paths via environment variables if running outside a Yasvara tree:
`YASVARA_WS`, `YASVARA_KERNEL`, `YASVARA_MODULES`, `YASVARA_DEVICETREES`, `YASVARA_PRODUCT_OUT`, `YASVARA_KERNEL_OBJ`, or `-R <repo>`.

## License

Apache-2.0
