//! Automatic AArch64 ELF + APK/DEX log-callsite & log-gate analyzer:
//!   - `ktool blob-logs <target...> [-f <pat>] [-l V,D,I,W,E] [--emit-fixup] [--limit N] [--json]`
//!
//! Combines `llvm-objdump` / `llvm-readelf` (for ELF64 AArch64 prebuilt binaries) and
//! `dexdump` / `jadx` (for `.apk` / `.jar` / `.dex`) with a pure-Rust PT_LOAD virtual-address
//! mapper and backward AArch64 register tracker (`adrp`+`add`+`mov`) to:
//!   1. Discover exported log-level globals (`pal_log_lvl`, `agm_log_lvl`, `hal_log_level`,
//!      `alg_log_level`, `gC2LogLevel`, `ar_log_lvl`, `hal_log_mask`) + initial `.data` values.
//!   2. Discover built-in debug/log system property strings (`vendor.*`, `persist.*`, `ro.*`).
//!   3. Resolve every `__android_log_*` / `ar_log` callsite's priority (`V/D/I/W/E`), tag string,
//!      format string, enclosing function, and whether it is behind a conditional guard (`tbz`/`cbz`).
//!   4. Optionally emit verified-unique `extract-files.py` `blob_fixup().sig_replace(...)` patches
//!      replacing noisy `bl __android_log_*@plt` calls with ABI-safe `mov w0, #0` (`00 00 80 52`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::device::json_escape;
use crate::util::*;

#[derive(Clone, Debug)]
pub struct BlobLogsOpts {
    pub targets: Vec<String>,
    pub filter: Option<String>,
    pub levels: Option<BTreeSet<char>>,
    pub emit_fixup: bool,
    pub limit: usize,
    pub json: bool,
}

impl Default for BlobLogsOpts {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            filter: None,
            levels: None,
            emit_fixup: false,
            limit: 40,
            json: false,
        }
    }
}

// ====================================================== Tool discovery

fn find_llvm_tool(ctx: &Ctx, name: &str) -> String {
    let stable = ctx
        .ws_root
        .join("src/prebuilts/clang/host/linux-x86/llvm-binutils-stable")
        .join(name);
    if stable.is_file() {
        return stable.to_string_lossy().into_owned();
    }
    let clang_root = ctx.ws_root.join("src/prebuilts/clang/host/linux-x86");
    if let Ok(rd) = fs::read_dir(&clang_root) {
        let mut cands: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path().join("bin").join(name))
            .filter(|p| p.is_file())
            .collect();
        cands.sort();
        if let Some(last) = cands.pop() {
            return last.to_string_lossy().into_owned();
        }
    }
    name.to_string()
}

fn find_dexdump(ctx: &Ctx) -> Option<String> {
    let host_bin = ctx.ws_root.join("src/out/host/linux-x86/bin/dexdump");
    if host_bin.is_file() {
        return Some(host_bin.to_string_lossy().into_owned());
    }
    if run_cmd("which", &["dexdump"], &ctx.ws_root, None).0 == 0 {
        return Some("dexdump".to_string());
    }
    None
}

fn resolve_target_path(ctx: &Ctx, raw: &str) -> Option<(PathBuf, String)> {
    let p = PathBuf::from(raw);
    if p.is_file() {
        let rel = p
            .to_string_lossy()
            .split("proprietary/")
            .nth(1)
            .unwrap_or(raw)
            .trim_start_matches('/')
            .to_string();
        return Some((p, rel));
    }
    let clean = raw.trim_start_matches('/');
    let prop = ctx.ws_root.join("src/vendor/xiaomi/onyx/proprietary").join(clean);
    if prop.is_file() {
        return Some((prop, clean.to_string()));
    }
    let out = ctx.product_out.join(clean);
    if out.is_file() {
        return Some((out, clean.to_string()));
    }
    let ws = ctx.ws_root.join(raw);
    if ws.is_file() {
        return Some((ws, clean.to_string()));
    }
    None
}

// ====================================================== Pure-Rust ELF64 PT_LOAD image

#[derive(Clone, Debug)]
struct PtLoad {
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

#[derive(Clone, Debug)]
pub struct ElfImage {
    bytes: Vec<u8>,
    loads: Vec<PtLoad>,
}

impl ElfImage {
    pub fn parse(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
            return None;
        }
        let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().ok()?) as u64;
        let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().ok()?) as u64;
        let mut loads = Vec::new();
        for i in 0..e_phnum {
            let off = (e_phoff + i * e_phentsize) as usize;
            if off + 56 > bytes.len() {
                break;
            }
            let p_type = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
            if p_type == 1 {
                let p_offset = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().ok()?);
                let p_vaddr = u64::from_le_bytes(bytes[off + 16..off + 24].try_into().ok()?);
                let p_filesz = u64::from_le_bytes(bytes[off + 32..off + 40].try_into().ok()?);
                let p_memsz = u64::from_le_bytes(bytes[off + 40..off + 48].try_into().ok()?);
                loads.push(PtLoad {
                    p_offset,
                    p_vaddr,
                    p_filesz,
                    p_memsz,
                });
            }
        }
        Some(ElfImage { bytes, loads })
    }

    pub fn va_to_foff(&self, va: u64) -> Option<usize> {
        for seg in &self.loads {
            if va >= seg.p_vaddr && va < seg.p_vaddr.saturating_add(seg.p_filesz) {
                let foff = seg.p_offset + (va - seg.p_vaddr);
                if (foff as usize) < self.bytes.len() {
                    return Some(foff as usize);
                }
            }
        }
        None
    }

    pub fn va_in_bss(&self, va: u64) -> bool {
        for seg in &self.loads {
            if va >= seg.p_vaddr.saturating_add(seg.p_filesz)
                && va < seg.p_vaddr.saturating_add(seg.p_memsz)
            {
                return true;
            }
        }
        false
    }

    pub fn read_u32_at_va(&self, va: u64) -> Option<u32> {
        let foff = self.va_to_foff(va)?;
        if foff + 4 > self.bytes.len() {
            return None;
        }
        Some(u32::from_le_bytes(self.bytes[foff..foff + 4].try_into().ok()?))
    }

    pub fn read_cstr_at_va(&self, va: u64) -> Option<String> {
        let foff = self.va_to_foff(va)?;
        let max_end = (foff + 180).min(self.bytes.len());
        let slice = &self.bytes[foff..max_end];
        let nul = slice.iter().position(|&b| b == 0)?;
        if nul == 0 {
            return Some(String::new());
        }
        let raw = &slice[..nul];
        if raw.iter().any(|&b| b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f) {
            return None;
        }
        let s = String::from_utf8_lossy(raw)
            .replace('\n', "\\n")
            .replace('\r', "")
            .replace('\t', "\\t");
        Some(s)
    }

    /// Count exact occurrences of a byte needle in the ELF image.
    pub fn count_bytes(&self, needle: &[u8]) -> usize {
        if needle.is_empty() || needle.len() > self.bytes.len() {
            return 0;
        }
        let first = needle[0];
        let nlen = needle.len();
        let limit = self.bytes.len() - nlen;
        let mut count = 0usize;
        let mut off = 0usize;
        while off <= limit {
            let Some(rel) = self.bytes[off..=limit].iter().position(|&b| b == first) else {
                break;
            };
            let pos = off + rel;
            if &self.bytes[pos..pos + nlen] == needle {
                count += 1;
                if count >= 2 {
                    return count;
                }
            }
            off = pos + 1;
        }
        count
    }
}

// ====================================================== AArch64 Callsite Analyzer

#[derive(Clone, Debug)]
struct DisasmInsn {
    va: u64,
    _word: u32,
    mnemonic: String,
    operands: String,
}

#[derive(Clone, Debug)]
struct LogGlobal {
    name: String,
    va: u64,
    kind: String,
    init_desc: String,
}

#[derive(Clone, Debug)]
struct LogCallsite {
    va: u64,
    foff: Option<usize>,
    is_tail_branch: bool,
    /// For Clang tail-merged `b <trampoline>` callsites: VA of instruction right after the shared `bl`.
    trampoline_skip_va: Option<u64>,
    callee: String,
    func: String,
    prio_char: char,
    prio_raw: Option<u64>,
    tag: Option<String>,
    fmt: Option<String>,
    gated: bool,
}

fn parse_disasm_line(line: &str) -> Option<DisasmInsn> {
    // e.g. `    4bd8: 9400043e     \tbl\t0x5cd0 <__android_log_print@plt>`
    let t = line.trim_start();
    let (addr_s, rest) = t.split_once(':')?;
    if addr_s.is_empty() || !addr_s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let va = u64::from_str_radix(addr_s, 16).ok()?;
    let rest = rest.trim_start();
    let mut parts = rest.split_whitespace();
    let word_s = parts.next()?;
    if word_s.len() != 8 || !word_s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let word = u32::from_str_radix(word_s, 16).ok()?;
    let after_word = rest[word_s.len()..].trim_start();
    let mnemonic = parts.next()?.to_string();
    let operands = after_word
        .strip_prefix(&mnemonic)
        .unwrap_or("")
        .trim()
        .to_string();
    Some(DisasmInsn {
        va,
        _word: word,
        mnemonic,
        operands,
    })
}

fn parse_func_header(line: &str) -> Option<String> {
    // `0000000000004b00 <_ZN...Ev>:`
    let lt = line.find('<')?;
    let gt = line.rfind(">:")?;
    if gt > lt + 1 {
        Some(line[lt + 1..gt].to_string())
    } else {
        None
    }
}

fn parse_reg_idx(tok: &str) -> Option<usize> {
    let t = tok.trim().trim_end_matches(',').trim_end_matches(']');
    if t == "xzr" || t == "wzr" {
        return Some(31);
    }
    let rest = t.strip_prefix('x').or_else(|| t.strip_prefix('w'))?;
    let n: usize = rest.parse().ok()?;
    if n <= 30 {
        Some(n)
    } else {
        None
    }
}

fn parse_hex_or_dec(tok: &str) -> Option<u64> {
    let t = tok
        .trim()
        .trim_start_matches('#')
        .split_whitespace()
        .next()?
        .trim_end_matches(',');
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn is_log_callee(operands: &str) -> Option<String> {
    let lt = operands.find('<')?;
    let gt = operands[lt + 1..].find('>')? + lt + 1;
    let sym = &operands[lt + 1..gt];
    if sym.starts_with("__android_log_print")
        || sym.starts_with("__android_log_vprint")
        || sym.starts_with("__android_log_buf_print")
        || sym.starts_with("__android_log_write")
        || sym.starts_with("__android_log_buf_write")
        || sym.starts_with("ar_log@")
        || sym == "ar_log"
        || sym.contains("GrallocSnapDebugger3Log")
    {
        return Some(sym.trim_end_matches("@plt").to_string());
    }
    None
}

fn android_prio_char(val: u64) -> char {
    match val {
        2 => 'V',
        3 => 'D',
        4 => 'I',
        5 => 'W',
        6 => 'E',
        7 => 'F',
        _ => '?',
    }
}

fn ar_log_mask_char(val: u64) -> char {
    match val {
        1 => 'E',
        2 | 4 => 'I',
        8 => 'D',
        16 => 'V',
        _ => '?',
    }
}

/// Replay a short window of instructions right before a log call to resolve
/// `w0..w3` immediates and `x0..x3` `adrp`+`add` `.rodata` string addresses.
fn analyze_call_window(
    window: &[DisasmInsn],
    callee: &str,
    elf: &ElfImage,
) -> (char, Option<u64>, Option<String>, Option<String>, bool) {
    // Find the start of the current call setup (after last call/ret barrier).
    // Allow conditional branches inside the window (they indicate a log-level gate!).
    let mut start = 0usize;
    let mut gated = false;
    for i in (0..window.len()).rev() {
        let m = window[i].mnemonic.as_str();
        if matches!(m, "bl" | "blr" | "ret" | "b") {
            start = i + 1;
            break;
        }
        if matches!(m, "tbz" | "tbnz" | "cbz" | "cbnz") || m.starts_with("b.") {
            gated = true;
        }
    }

    let mut reg_page: [Option<u64>; 32] = [None; 32];
    let mut reg_va: [Option<u64>; 32] = [None; 32];
    let mut reg_imm: [Option<u64>; 32] = [None; 32];
    reg_imm[31] = Some(0); // xzr / wzr
    reg_va[31] = Some(0);

    for insn in &window[start..] {
        let m = insn.mnemonic.as_str();
        let ops: Vec<&str> = insn.operands.split(',').map(str::trim).collect();
        match m {
            "adrp" if ops.len() >= 2 => {
                if let (Some(rd), Some(page)) = (parse_reg_idx(ops[0]), parse_hex_or_dec(ops[1])) {
                    reg_page[rd] = Some(page);
                    reg_va[rd] = Some(page);
                    reg_imm[rd] = None;
                }
            }
            "adr" if ops.len() >= 2 => {
                if let (Some(rd), Some(addr)) = (parse_reg_idx(ops[0]), parse_hex_or_dec(ops[1])) {
                    reg_va[rd] = Some(addr);
                    reg_page[rd] = None;
                }
            }
            "add" if ops.len() >= 3 => {
                if let (Some(rd), Some(rn), Some(off)) = (
                    parse_reg_idx(ops[0]),
                    parse_reg_idx(ops[1]),
                    parse_hex_or_dec(ops[2]),
                ) {
                    if let Some(base) = reg_page[rn].or(reg_va[rn]) {
                        reg_va[rd] = Some(base.wrapping_add(off));
                        reg_page[rd] = None;
                    }
                }
            }
            "mov" | "movz" if ops.len() >= 2 => {
                if let Some(rd) = parse_reg_idx(ops[0]) {
                    if let Some(imm) = parse_hex_or_dec(ops[1]) {
                        reg_imm[rd] = Some(imm);
                        reg_va[rd] = if imm == 0 { Some(0) } else { None };
                        reg_page[rd] = None;
                    } else if let Some(rs) = parse_reg_idx(ops[1]) {
                        reg_imm[rd] = reg_imm[rs];
                        reg_va[rd] = reg_va[rs];
                        reg_page[rd] = reg_page[rs];
                    }
                }
            }
            "orr" if ops.len() >= 3 => {
                // `orr w0, wzr, #0x4` alias
                if let (Some(rd), Some(rn)) = (parse_reg_idx(ops[0]), parse_reg_idx(ops[1])) {
                    if rn == 31 {
                        if let Some(imm) = parse_hex_or_dec(ops[2]) {
                            reg_imm[rd] = Some(imm);
                        } else if let Some(rs) = parse_reg_idx(ops[2]) {
                            reg_imm[rd] = reg_imm[rs];
                            reg_va[rd] = reg_va[rs];
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let read_str = |reg: usize| -> Option<String> {
        match reg_va[reg] {
            Some(0) => Some("(null)".to_string()),
            Some(va) => elf.read_cstr_at_va(va),
            None => None,
        }
    };

    if callee == "__android_log_buf_print" || callee == "__android_log_buf_write" {
        let prio_raw = reg_imm[1];
        let prio_ch = prio_raw.map(android_prio_char).unwrap_or('?');
        (prio_ch, prio_raw, read_str(2), read_str(3), gated)
    } else if callee == "ar_log" {
        let prio_raw = reg_imm[0];
        let prio_ch = prio_raw.map(ar_log_mask_char).unwrap_or('?');
        (prio_ch, prio_raw, read_str(1), read_str(2), gated)
    } else if callee.contains("GrallocSnapDebugger3Log") {
        let prio_raw = reg_imm[1];
        // sdm::DebugLogType: 0=ERROR, 1=WARNING, 2=INFO, 3=DEBUG, 4=VERBOSE
        let prio_ch = match prio_raw {
            Some(0) => 'E',
            Some(1) => 'W',
            Some(2) => 'I',
            Some(3) => 'D',
            Some(4) => 'V',
            _ => '?',
        };
        (prio_ch, prio_raw, read_str(2), read_str(3), gated)
    } else {
        // __android_log_print(prio=w0, tag=x1, fmt=x2, ...)
        let prio_raw = reg_imm[0];
        let prio_ch = prio_raw.map(android_prio_char).unwrap_or('?');
        (prio_ch, prio_raw, read_str(1), read_str(2), gated)
    }
}

fn extract_prop_strings(bytes: &[u8]) -> Vec<String> {
    let mut found = BTreeSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphanumeric() {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'_' | b'-'))
            {
                i += 1;
            }
            let len = i - start;
            if len >= 10 && len <= 80 && (i >= bytes.len() || bytes[i] == 0) {
                if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                    if (s.starts_with("vendor.")
                        || s.starts_with("persist.")
                        || s.starts_with("ro.")
                        || s.starts_with("debug.")
                        || s.starts_with("log."))
                        && s.contains('.')
                    {
                        let low = s.to_ascii_lowercase();
                        if low.contains("log")
                            || low.contains("debug")
                            || low.contains("dbg")
                            || low.contains("level")
                            || low.contains("mask")
                            || low.contains("verb")
                            || low.contains("trace")
                        {
                            found.insert(s.to_string());
                        }
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    found.into_iter().collect()
}

fn discover_log_globals(ctx: &Ctx, readelf: &str, path: &Path, elf: &ElfImage) -> Vec<LogGlobal> {
    let (rc, out, _) = run_cmd(
        readelf,
        &["--dyn-syms", "--wide", &path.to_string_lossy()],
        &ctx.ws_root,
        None,
    );
    if rc != 0 {
        return Vec::new();
    }
    let mut out_vec = Vec::new();
    for ln in out.lines() {
        let p: Vec<&str> = ln.split_whitespace().collect();
        if p.len() < 8 {
            continue;
        }
        let ndx = p[6];
        if ndx == "UND" {
            continue;
        }
        let kind = p[3];
        let name = p[7];
        let low = name.to_ascii_lowercase();
        let interesting = low.contains("log_lvl")
            || low.contains("log_level")
            || low.contains("log_mask")
            || low.contains("loglevel")
            || low.contains("logmask")
            || low.contains("debuglevel")
            || low.contains("debug_level")
            || low == "ar_log"
            || low == "ar_log_init"
            || low.contains("grallocsnapdebugger3log");
        if !interesting {
            continue;
        }
        let Ok(va) = u64::from_str_radix(p[1], 16) else {
            continue;
        };
        let size: u64 = p[2].parse().unwrap_or(0);
        let init_desc = if kind == "OBJECT" {
            if let Some(val) = elf.read_u32_at_va(va) {
                let foff = elf.va_to_foff(va).unwrap_or(0);
                format!("foff=0x{foff:x} init=0x{val:x} ({val})")
            } else if elf.va_in_bss(va) {
                ".bss (init=0)".to_string()
            } else {
                "n/a".to_string()
            }
        } else {
            let foff = elf.va_to_foff(va).map(|x| format!("foff=0x{x:x}")).unwrap_or_default();
            format!("FUNC size={size} {foff}")
        };
        out_vec.push(LogGlobal {
            name: name.to_string(),
            va,
            kind: kind.to_string(),
            init_desc,
        });
    }
    out_vec
}

fn to_hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn to_hex_compact(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

/// Encode AArch64 unconditional branch `b <target_va>` from `src_va` (little-endian 4 bytes).
fn encode_aarch64_b(src_va: u64, target_va: u64) -> Option<[u8; 4]> {
    let diff = (target_va as i64) - (src_va as i64);
    if diff % 4 != 0 {
        return None;
    }
    let imm26 = diff >> 2;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return None;
    }
    let word: u32 = 0x1400_0000 | ((imm26 as u32) & 0x03ff_ffff);
    Some(word.to_le_bytes())
}

/// Build a verified-unique `sig_replace` hex signature around `foff` that replaces:
/// - `bl __android_log_*@plt` -> `mov w0, #0` (`00 00 80 52`, ABI-safe)
/// - Clang tail-merged `b <shared_log_trampoline>` -> `b <after_bl>` (skips only the log call!)
/// - tail-call `b __android_log_*@plt` -> `ret` (`c0 03 5f d6`)
fn build_unique_sig_replace(
    elf: &ElfImage,
    va: u64,
    foff: usize,
    is_tail_branch: bool,
    trampoline_skip_va: Option<u64>,
) -> Option<(String, String)> {
    let replacement: [u8; 4] = if let Some(skip_va) = trampoline_skip_va {
        encode_aarch64_b(va, skip_va)?
    } else if is_tail_branch {
        [0xc0, 0x03, 0x5f, 0xd6] // ret
    } else {
        [0x00, 0x00, 0x80, 0x52] // mov w0, #0
    };
    // Try expanding window: (before_insns, after_insns)
    for (bef, aft) in [(2usize, 0usize), (2, 1), (3, 1), (3, 2), (4, 2)] {
        let start = foff.saturating_sub(bef * 4);
        let end = (foff + 4 + aft * 4).min(elf.bytes.len());
        if end < foff + 4 || (end - start) < 12 {
            continue;
        }
        let orig = &elf.bytes[start..end];
        if elf.count_bytes(orig) == 1 {
            let mut patched = orig.to_vec();
            let rel = foff - start;
            patched[rel..rel + 4].copy_from_slice(&replacement);
            return Some((to_hex_spaced(orig), to_hex_compact(&patched)));
        }
    }
    None
}

fn inspect_elf_blob(ctx: &Ctx, path: &Path, rel: &str, opts: &BlobLogsOpts) -> i32 {
    let Ok(bytes) = fs::read(path) else {
        eprintln!("!! failed to read {}", path.display());
        return 1;
    };
    let Some(elf) = ElfImage::parse(bytes) else {
        eprintln!("!! {} is not a valid 64-bit little-endian ELF", path.display());
        return 1;
    };

    let objdump = find_llvm_tool(ctx, "llvm-objdump");
    let readelf = find_llvm_tool(ctx, "llvm-readelf");

    let globals = discover_log_globals(ctx, &readelf, path, &elf);
    let props = extract_prop_strings(&elf.bytes);

    let (rc, disasm, err) = run_cmd(
        &objdump,
        &["-d", &path.to_string_lossy()],
        &ctx.ws_root,
        None,
    );
    if rc != 0 {
        eprintln!("!! llvm-objdump failed on {}: {}", path.display(), err.trim());
        return 1;
    }

    // Parse disassembly grouped by function so we can detect BOTH direct `bl <log@plt>`
    // callsites AND Clang tail-merged intra-function `b <shared_log_trampoline>` callsites!
    let mut cur_func = String::from("<unknown>");
    let mut func_insns: Vec<DisasmInsn> = Vec::new();
    let mut all_calls: Vec<LogCallsite> = Vec::new();
    let mut prio_hist: BTreeMap<char, usize> = BTreeMap::new();

    let flush_func = |func_name: &str,
                      insns: &[DisasmInsn],
                      elf: &ElfImage,
                      all_calls: &mut Vec<LogCallsite>,
                      prio_hist: &mut BTreeMap<char, usize>| {
        if insns.is_empty() {
            return;
        }
        // Pass 1: find all direct `bl <log@plt>` sites & map their 0..=3 preceding setup insns as trampolines
        // target_va -> (callee, skip_va = bl_va + 4)
        let mut trampolines: BTreeMap<u64, (String, u64)> = BTreeMap::new();
        for (idx, insn) in insns.iter().enumerate() {
            if insn.mnemonic == "bl" && insn.operands.contains('<') {
                if let Some(callee) = is_log_callee(&insn.operands) {
                    let skip_va = insn.va + 4;
                    trampolines.insert(insn.va, (callee.clone(), skip_va));
                    // Up to 3 simple non-branching insns directly before `bl` (e.g., `tst`, `csel`, `mov`)
                    for back in 1..=3usize {
                        if idx < back {
                            break;
                        }
                        let prev = &insns[idx - back];
                        if matches!(
                            prev.mnemonic.as_str(),
                            "bl" | "blr" | "b" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
                        ) || prev.mnemonic.starts_with("b.")
                        {
                            break;
                        }
                        trampolines.insert(prev.va, (callee.clone(), skip_va));
                    }
                }
            }
        }

        // Pass 2: analyze every direct log call AND every `b <trampoline>` callsite
        for (idx, insn) in insns.iter().enumerate() {
            let win_start = idx.saturating_sub(28);
            let window = &insns[win_start..idx];
            if (insn.mnemonic == "bl" || insn.mnemonic == "b") && insn.operands.contains('<') {
                if let Some(callee) = is_log_callee(&insn.operands) {
                    let (prio_char, prio_raw, tag, fmt, gated) = analyze_call_window(window, &callee, elf);
                    *prio_hist.entry(prio_char).or_insert(0) += 1;
                    all_calls.push(LogCallsite {
                        va: insn.va,
                        foff: elf.va_to_foff(insn.va),
                        is_tail_branch: insn.mnemonic == "b",
                        trampoline_skip_va: None,
                        callee,
                        func: func_name.to_string(),
                        prio_char,
                        prio_raw,
                        tag,
                        fmt,
                        gated,
                    });
                    continue;
                }
            }
            if insn.mnemonic == "b" {
                if let Some(target_va) = parse_hex_or_dec(&insn.operands) {
                    if let Some((callee, skip_va)) = trampolines.get(&target_va) {
                        let (prio_char, prio_raw, tag, fmt, gated) = analyze_call_window(window, callee, elf);
                        // Only record as a tail-merged log callsite if it actually set up a log priority or string!
                        if prio_raw.is_some() || fmt.is_some() {
                            *prio_hist.entry(prio_char).or_insert(0) += 1;
                            all_calls.push(LogCallsite {
                                va: insn.va,
                                foff: elf.va_to_foff(insn.va),
                                is_tail_branch: true,
                                trampoline_skip_va: Some(*skip_va),
                                callee: callee.clone(),
                                func: func_name.to_string(),
                                prio_char,
                                prio_raw,
                                tag,
                                fmt,
                                gated,
                            });
                        }
                    }
                }
            }
        }
    };

    for ln in disasm.lines() {
        if let Some(fnm) = parse_func_header(ln) {
            flush_func(&cur_func, &func_insns, &elf, &mut all_calls, &mut prio_hist);
            cur_func = fnm;
            func_insns.clear();
            continue;
        }
        if let Some(insn) = parse_disasm_line(ln) {
            func_insns.push(insn);
        }
    }
    flush_func(&cur_func, &func_insns, &elf, &mut all_calls, &mut prio_hist);

    let flt_low = opts.filter.as_ref().map(|s| s.to_ascii_lowercase());
    let matched: Vec<&LogCallsite> = all_calls
        .iter()
        .filter(|c| {
            if let Some(ref lvls) = opts.levels {
                if !lvls.contains(&c.prio_char) {
                    return false;
                }
            }
            if let Some(ref pat) = flt_low {
                let in_fmt = c.fmt.as_deref().unwrap_or("").to_ascii_lowercase().contains(pat);
                let in_tag = c.tag.as_deref().unwrap_or("").to_ascii_lowercase().contains(pat);
                let in_fn = c.func.to_ascii_lowercase().contains(pat);
                if !(in_fmt || in_tag || in_fn) {
                    return false;
                }
            }
            true
        })
        .collect();

    if opts.json {
        println!("{{");
        println!("  \"target\": {},", json_escape(rel));
        println!("  \"size_bytes\": {},", elf.bytes.len());
        println!("  \"total_log_calls\": {},", all_calls.len());
        println!("  \"matched_calls\": {},", matched.len());
        println!("  \"globals\": [");
        for (i, g) in globals.iter().enumerate() {
            let comma = if i + 1 < globals.len() { "," } else { "" };
            println!(
                "    {{\"name\":{},\"va\":\"0x{:x}\",\"kind\":{},\"info\":{}}}{comma}",
                json_escape(&g.name),
                g.va,
                json_escape(&g.kind),
                json_escape(&g.init_desc)
            );
        }
        println!("  ],");
        println!("  \"props\": [{}],", props.iter().map(|p| json_escape(p)).collect::<Vec<_>>().join(", "));
        println!("  \"callsites\": [");
        for (i, c) in matched.iter().take(opts.limit).enumerate() {
            let comma = if i + 1 < matched.len().min(opts.limit) { "," } else { "" };
            println!(
                "    {{\"va\":\"0x{:x}\",\"foff\":\"0x{:x}\",\"prio\":\"{}\",\"tail\":{},\"gated\":{},\"callee\":{},\"func\":{},\"tag\":{},\"fmt\":{}}}{comma}",
                c.va,
                c.foff.unwrap_or(0),
                c.prio_char,
                c.is_tail_branch,
                c.gated,
                json_escape(&c.callee),
                json_escape(&c.func),
                json_escape(c.tag.as_deref().unwrap_or("")),
                json_escape(c.fmt.as_deref().unwrap_or("")),
            );
        }
        println!("  ]");
        println!("}}");
        return 0;
    }

    println!("========================================================================");
    println!("ktool blob-logs: {rel} ({} bytes)", elf.bytes.len());
    println!("========================================================================");
    let hist_str: String = ['V', 'D', 'I', 'W', 'E', 'F', '?']
        .into_iter()
        .filter_map(|k| prio_hist.get(&k).map(|v| format!("{k}:{v}")))
        .collect::<Vec<_>>()
        .join("  ");
    println!(
        "  log calls: {} total ({}) | matched: {}",
        all_calls.len(),
        if hist_str.is_empty() { "none".into() } else { hist_str },
        matched.len()
    );
    if !globals.is_empty() {
        println!("  globals  :");
        for g in &globals {
            println!("    - {:<42} va=0x{:x}  {}", g.name, g.va, g.init_desc);
        }
    }
    if !props.is_empty() {
        println!("  props    : {}", props.iter().take(12).cloned().collect::<Vec<_>>().join(", "));
    }

    if !matched.is_empty() {
        println!("\n  {:<10} {:<10} {:<5} {:<5} {:<22} {:<18} {}", "VA", "FOFF", "PRIO", "GATE", "CALLEE", "TAG", "FORMAT / MESSAGE");
        for c in matched.iter().take(opts.limit) {
            let foff_s = c.foff.map(|x| format!("0x{x:06x}")).unwrap_or_else(|| "?".into());
            let gate_s = if c.trampoline_skip_va.is_some() {
                "tramp"
            } else {
                match (c.gated, c.is_tail_branch) {
                    (true, true) => "G+T",
                    (true, false) => "gate",
                    (false, true) => "tail",
                    (false, false) => "raw",
                }
            };
            let prio_s = match c.prio_raw {
                Some(v) => format!("{}({v})", c.prio_char),
                None => format!("{}", c.prio_char),
            };
            println!(
                "  0x{:06x}   {:<10} {:<5} {:<5} {:<22} {:<18} {}",
                c.va,
                foff_s,
                prio_s,
                gate_s,
                truncate_str(&c.callee, 22),
                truncate_str(c.tag.as_deref().unwrap_or("(reg)"), 18),
                truncate_str(c.fmt.as_deref().unwrap_or("(reg)"), 78)
            );
        }
        if matched.len() > opts.limit {
            println!("  ... ({} more callsites; pass --limit N or --filter <pat>)", matched.len() - opts.limit);
        }
    }

    if opts.emit_fixup && !matched.is_empty() {
        println!("\n  --- extract-files.py blob_fixup() draft (verified-unique signatures) ---");
        println!("    '{rel}': blob_fixup()");
        let mut emitted = 0usize;
        for c in matched.iter().take(opts.limit) {
            let Some(foff) = c.foff else { continue };
            if let Some((orig, repl)) =
                build_unique_sig_replace(&elf, c.va, foff, c.is_tail_branch, c.trampoline_skip_va)
            {
                let kind_note = if let Some(skip_va) = c.trampoline_skip_va {
                    format!("tramp b -> b 0x{skip_va:x}")
                } else if c.is_tail_branch {
                    "tail-b -> ret (VERIFY return type!)".to_string()
                } else {
                    "bl -> mov w0, #0".to_string()
                };
                println!(
                    "        # 0x{:x} [{} {}] {} | {}",
                    c.va,
                    c.prio_char,
                    kind_note,
                    truncate_str(c.tag.as_deref().unwrap_or(""), 22),
                    truncate_str(c.fmt.as_deref().unwrap_or(&c.func), 60)
                );
                println!("        .sig_replace('{orig}', '{repl}')");
                emitted += 1;
            }
        }
        if emitted == 0 {
            println!("        # (no unique signatures generated)");
        }
    }

    0
}

// ====================================================== APK / JAR / DEX Scanner

fn inspect_dex_apk(ctx: &Ctx, path: &Path, rel: &str, opts: &BlobLogsOpts) -> i32 {
    let Some(dexdump) = find_dexdump(ctx) else {
        eprintln!("!! dexdump not found; build host dexdump or install jadx to inspect {rel}");
        return 1;
    };
    let (rc, out, err) = run_cmd(&dexdump, &["-d", &path.to_string_lossy()], &ctx.ws_root, None);
    if rc != 0 {
        eprintln!("!! dexdump failed on {}: {}", path.display(), err.trim());
        return 1;
    }

    let flt_low = opts.filter.as_ref().map(|s| s.to_ascii_lowercase());
    let mut cur_class = String::new();
    let mut cur_method = String::new();
    let mut recent_str = String::new();
    let mut hits: Vec<(char, String, String, String)> = Vec::new();

    for ln in out.lines() {
        let t = ln.trim();
        if let Some(rest) = t.strip_prefix("Class descriptor  : '") {
            cur_class = rest.trim_end_matches("';").trim_start_matches('L').replace('/', ".");
        } else if t.starts_with("name          : '") {
            cur_method = t
                .trim_start_matches("name          : '")
                .trim_end_matches('\'')
                .to_string();
        } else if t.contains("const-string") {
            if let Some(q1) = t.find('"') {
                if let Some(q2) = t.rfind('"') {
                    if q2 > q1 {
                        recent_str = t[q1 + 1..q2].to_string();
                    }
                }
            }
        } else if t.contains("Landroid/util/Log;.") || t.contains("Landroid/util/Slog;.") {
            let lvl = if t.contains(";.v:") {
                'V'
            } else if t.contains(";.d:") {
                'D'
            } else if t.contains(";.i:") {
                'I'
            } else if t.contains(";.w:") {
                'W'
            } else if t.contains(";.e:") {
                'E'
            } else {
                continue;
            };
            if let Some(ref lvls) = opts.levels {
                if !lvls.contains(&lvl) {
                    continue;
                }
            }
            if let Some(ref pat) = flt_low {
                let hay = format!("{cur_class}.{cur_method} {recent_str}").to_ascii_lowercase();
                if !hay.contains(pat) {
                    continue;
                }
            }
            hits.push((lvl, cur_class.clone(), cur_method.clone(), recent_str.clone()));
        }
    }

    println!("========================================================================");
    println!("ktool blob-logs (DEX/APK): {rel} ({} matching Log/Slog calls)", hits.len());
    println!("========================================================================");
    for (lvl, cls, meth, s) in hits.iter().take(opts.limit) {
        println!(
            "  [{lvl}] {:<48} {:<24} \"{}\"",
            truncate_str(cls, 48),
            truncate_str(meth, 24),
            truncate_str(s, 55)
        );
    }
    0
}

pub fn cmd_blob_logs(ctx: &Ctx, opts: &BlobLogsOpts) -> i32 {
    if opts.targets.is_empty() {
        eprintln!("usage: ktool blob-logs <elf_or_apk...> [-f <pat>] [-l V,D,I,W,E] [--emit-fixup] [--limit N] [--json]");
        return 2;
    }
    let mut overall_rc = 0;
    for raw in &opts.targets {
        let Some((path, rel)) = resolve_target_path(ctx, raw) else {
            eprintln!("!! blob-logs: target not found: {raw}");
            overall_rc = 1;
            continue;
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let rc = if matches!(ext.as_str(), "apk" | "jar" | "dex") {
            inspect_dex_apk(ctx, &path, &rel, opts)
        } else {
            inspect_elf_blob(ctx, &path, &rel, opts)
        };
        if rc != 0 {
            overall_rc = rc;
        }
    }
    overall_rc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_disasm_and_window_resolution() {
        // Synthetic minimal ELF64 with PT_LOAD mapping VA 0x0..0x200 -> file 0x0..0x200
        let mut buf = vec![0u8; 0x200];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // 64-bit
        buf[5] = 1; // LE
        buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());  // e_phnum = 1
        // PT_LOAD at offset 64
        buf[64..68].copy_from_slice(&1u32.to_le_bytes());     // PT_LOAD
        buf[72..80].copy_from_slice(&0u64.to_le_bytes());     // p_offset = 0
        buf[80..88].copy_from_slice(&0u64.to_le_bytes());     // p_vaddr = 0
        buf[96..104].copy_from_slice(&0x200u64.to_le_bytes()); // p_filesz
        buf[104..112].copy_from_slice(&0x200u64.to_le_bytes()); // p_memsz
        // Place tag at 0x120 and fmt at 0x140
        buf[0x120..0x127].copy_from_slice(b"QC2Comp");
        buf[0x140..0x15a].copy_from_slice(b"Skipping empty output buf!");

        let elf = ElfImage::parse(buf).unwrap();
        let sample_lines = [
            "    4bc0: b0000001 \tadrp\tx1, 0x0",
            "    4bc4: 91048021 \tadd\tx1, x1, #0x120",
            "    4bc8: b0000002 \tadrp\tx2, 0x0",
            "    4bcc: 91050042 \tadd\tx2, x2, #0x140",
            "    4bd0: 528000a0 \tmov\tw0, #0x5",
        ];
        let win: Vec<DisasmInsn> = sample_lines
            .iter()
            .map(|l| parse_disasm_line(l).unwrap())
            .collect();
        let (prio, raw, tag, fmt, gated) = analyze_call_window(&win, "__android_log_print", &elf);
        assert_eq!(prio, 'W');
        assert_eq!(raw, Some(5));
        assert_eq!(tag.as_deref(), Some("QC2Comp"));
        assert_eq!(fmt.as_deref(), Some("Skipping empty output buf!"));
        assert!(!gated);
    }

    #[test]
    fn test_unique_sig_replace_generation() {
        let mut buf = vec![0u8; 0x100];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        buf[64..68].copy_from_slice(&1u32.to_le_bytes());
        buf[96..104].copy_from_slice(&0x100u64.to_le_bytes());
        buf[104..112].copy_from_slice(&0x100u64.to_le_bytes());
        // Unique 3-insn sequence at 0xc0..0xcc (bl at 0xc8)
        buf[0xc0..0xc4].copy_from_slice(&[0x80, 0x00, 0x80, 0x52]);
        buf[0xc4..0xc8].copy_from_slice(&[0xe1, 0x03, 0x1f, 0xaa]);
        buf[0xc8..0xcc].copy_from_slice(&[0x3e, 0x04, 0x00, 0x94]);

        let elf = ElfImage::parse(buf).unwrap();
        let (orig, repl) = build_unique_sig_replace(&elf, 0xc8, 0xc8, false, None).unwrap();
        assert_eq!(orig, "80 00 80 52 e1 03 1f aa 3e 04 00 94");
        assert_eq!(repl, "80008052e1031faa00008052");

        // Trampoline branch encoding test: from 0x1b478 skip to 0x1bbac (+0x734 => imm26 = 0x1cd)
        assert_eq!(encode_aarch64_b(0x1b478, 0x1bbac), Some([0xcd, 0x01, 0x00, 0x14]));
    }
}
