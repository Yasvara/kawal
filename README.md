# kawal

**kawal** (*guard / escort*) is a fast, zero-dependency Rust CLI built for Android & Linux kernel maintainers (developed for [Yasvara](https://github.com/Yasvara)).

## Features

- **Pre-build merge & conflict gates (`merge`, `status`, `explain`, `dup-check`, `verify`, `preflight`, `build-guard`)**: 16-core `rg` + `git` archaeology, dangling symbol checks, KABI landmine detection, per-commit replay (`BOTH!`/`SPLIT`/`ABSENT`), and real `clang` pre-flight compilation checks.
- **Major kernel porting (`port delta`, `port api-scan`, `port kabi-check`, `port overlay-soc`, `port bzl2config`, `port build-diag`)**: Preprocessor-aware breaking-API scanner (6.6 → 6.12 / 6.18), regression guards, and build-log root-cause triage.
- **Devicetree & post-build image safety (`dt-check`, `img-audit`)**: Real `dtc` + `fdtoverlay` + merged-DTB hardware audit (reserved-memory overlaps, regulator bounds, bootargs), plus pure-Rust ELF64 `.ko` binary auditing (vermagic, `depends=`, `SHN_UNDEF`, `__versions` CRCs, partition load order, recovery ramdisk DRM sync, AVB footer, `.config` + LTO/Rust hygiene).
- **Live hardware & crash forensics (`live-audit`, `health`, `runtime-audit`, `crash-log`, `log-noise`, `blob-logs`)**: Single-shot ADB kernel health check, idle CPU/IRQ/slab/vmalloc/DMA-BUF/FD leak hunting with JSON baseline diffs, and pure-Rust decoding of `/sys/fs/pstore`, `shutdown-checkpoints`, `blackbox`, and `mtdoops` partitions.
- **ROM & upstream sync (`sync latest|fetch|status|plan|apply|merge`, `prebuilts`, `hygiene`, `push`)**: Parallel CLO/AOSP/LineageOS/Linux LTS tracking and safe GPG-signed merges.

## Installation

```bash
cargo install kawal
```

## Quick Start

```bash
kawal --help
kawal verify v6.12.92 v6.12.119
kawal dt-check
kawal img-audit
kawal live-audit -s <serial>
kawal crash-log -s <serial>
kawal runtime-audit -s <serial> --window 5 --full
```

Override workspace paths via environment variables if running outside a Yasvara tree:
`YASVARA_WS`, `YASVARA_KERNEL`, `YASVARA_MODULES`, `YASVARA_DEVICETREES`, `YASVARA_PRODUCT_OUT`, `YASVARA_KERNEL_OBJ`, or `-R <repo>`.

## License

Apache-2.0
