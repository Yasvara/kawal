use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::util::*;

/// Parsed metadata from a 64-bit little-endian Linux kernel module (`.ko`).
#[derive(Debug, Default)]
pub struct KoInfo {
    pub path: PathBuf,
    pub partition: String,
    pub mod_name: String,
    pub vermagic: Option<String>,
    pub depends: Vec<String>,
    pub exports: Vec<String>,
    pub undefs: Vec<String>,
    pub versions: Vec<(u64, String)>,
}

fn read_u16_le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn read_u64_le(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

fn read_cstr(buf: &[u8], off: usize) -> &str {
    if off >= buf.len() {
        return "";
    }
    let slice = &buf[off..];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).unwrap_or("")
}

/// Pure-Rust zero-unsafe ELF64 LE parser for `.ko` modules.
pub fn parse_ko_bytes(data: &[u8], path: PathBuf, partition: &str) -> Result<KoInfo, String> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err("not an ELF binary".into());
    }
    if data[4] != 2 || data[5] != 1 {
        return Err("not ELF64 little-endian".into());
    }
    let e_shoff = read_u64_le(data, 40).ok_or("truncated ehdr")? as usize;
    let e_shentsize = read_u16_le(data, 58).ok_or("truncated ehdr")? as usize;
    let e_shnum = read_u16_le(data, 60).ok_or("truncated ehdr")? as usize;
    let e_shstrndx = read_u16_le(data, 62).ok_or("truncated ehdr")? as usize;

    if e_shentsize < 64 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return Err("invalid section header table".into());
    }

    struct Shdr {
        name_off: usize,
        sh_type: u32,
        sh_offset: usize,
        sh_size: usize,
        sh_link: usize,
        sh_entsize: usize,
    }

    let mut shdrs = Vec::with_capacity(e_shnum);
    for idx in 0..e_shnum {
        let base = e_shoff.checked_add(idx * e_shentsize).ok_or("shoff overflow")?;
        if base + 64 > data.len() {
            return Err("truncated section header".into());
        }
        shdrs.push(Shdr {
            name_off: read_u32_le(data, base).unwrap() as usize,
            sh_type: read_u32_le(data, base + 4).unwrap(),
            sh_offset: read_u64_le(data, base + 24).unwrap() as usize,
            sh_size: read_u64_le(data, base + 32).unwrap() as usize,
            sh_link: read_u32_le(data, base + 40).unwrap() as usize,
            sh_entsize: read_u64_le(data, base + 56).unwrap() as usize,
        });
    }

    let shstr_sh = &shdrs[e_shstrndx];
    let shstr = data
        .get(shstr_sh.sh_offset..shstr_sh.sh_offset.saturating_add(shstr_sh.sh_size))
        .ok_or("truncated shstrtab")?;

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().replace('-', "_"))
        .unwrap_or_default();
    let mut info = KoInfo {
        path,
        partition: partition.to_string(),
        mod_name: stem,
        ..Default::default()
    };

    const SHT_SYMTAB: u32 = 2;
    const STB_GLOBAL: u8 = 1;

    for sh in &shdrs {
        let sname = read_cstr(shstr, sh.name_off);
        let Some(sbytes) = data.get(sh.sh_offset..sh.sh_offset.saturating_add(sh.sh_size)) else {
            continue;
        };

        if sname == ".modinfo" {
            for part in sbytes.split(|&b| b == 0) {
                if part.is_empty() {
                    continue;
                }
                let Ok(s) = std::str::from_utf8(part) else { continue };
                if let Some(v) = s.strip_prefix("vermagic=") {
                    info.vermagic = Some(v.trim().to_string());
                } else if let Some(n) = s.strip_prefix("name=") {
                    let norm = n.trim().replace('-', "_");
                    if !norm.is_empty() {
                        info.mod_name = norm;
                    }
                } else if let Some(d) = s.strip_prefix("depends=") {
                    for dep in d.split(',') {
                        let dep = dep.trim().replace('-', "_");
                        if !dep.is_empty() {
                            info.depends.push(dep);
                        }
                    }
                }
            }
        } else if sname == "__ksymtab_strings" {
            for part in sbytes.split(|&b| b == 0) {
                if part.is_empty() {
                    continue;
                }
                if let Ok(sym) = std::str::from_utf8(part) {
                    if !sym.is_empty() && sym.bytes().all(is_ident_char) {
                        info.exports.push(sym.to_string());
                    }
                }
            }
        } else if sname == "__versions" {
            // Linux arm64 struct modversion_info { unsigned long crc (8B); char name[56]; } = 64B
            for chunk in sbytes.chunks_exact(64) {
                let crc = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                let name = read_cstr(&chunk[8..64], 0);
                if !name.is_empty() {
                    info.versions.push((crc, name.to_string()));
                }
            }
        } else if sh.sh_type == SHT_SYMTAB && sh.sh_entsize >= 24 && sh.sh_link < shdrs.len() {
            let str_sh = &shdrs[sh.sh_link];
            let Some(strtab) = data.get(str_sh.sh_offset..str_sh.sh_offset.saturating_add(str_sh.sh_size)) else {
                continue;
            };
            let count = sh.sh_size / sh.sh_entsize;
            for i in 1..count {
                let off = i * sh.sh_entsize;
                if off + 24 > sbytes.len() {
                    break;
                }
                let st_name = read_u32_le(sbytes, off).unwrap() as usize;
                let st_info = sbytes[off + 4];
                let st_shndx = read_u16_le(sbytes, off + 6).unwrap();
                let bind = st_info >> 4;
                // SHN_UNDEF == 0; STB_GLOBAL == 1 (weak undefs are optional and allowed to be unresolved)
                if st_shndx == 0 && bind == STB_GLOBAL {
                    let sym = read_cstr(strtab, st_name);
                    if !sym.is_empty() {
                        info.undefs.push(sym.to_string());
                    }
                }
            }
        }
    }

    Ok(info)
}

pub fn parse_ko_file(path: &Path, partition: &str) -> Result<KoInfo, String> {
    let data = fs::read(path).map_err(|e| format!("read error: {e}"))?;
    parse_ko_bytes(&data, path.to_path_buf(), partition)
}

/// Global defined & undefined symbols from an ELF64 LE object (`.o` or `.ko`).
#[derive(Debug, Default)]
pub struct ObjSymbols {
    pub defined: Vec<String>,
    pub undefs: Vec<String>,
}

/// Pure-Rust ELF64 LE symbol table extractor for `.o` / `.ko` link-precheck.
pub fn parse_obj_symbols_bytes(data: &[u8]) -> Result<ObjSymbols, String> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err("not an ELF binary (possibly LLVM bitcode)".into());
    }
    if data[4] != 2 || data[5] != 1 {
        return Err("not ELF64 little-endian".into());
    }
    let e_shoff = read_u64_le(data, 40).ok_or("truncated ehdr")? as usize;
    let e_shentsize = read_u16_le(data, 58).ok_or("truncated ehdr")? as usize;
    let e_shnum = read_u16_le(data, 60).ok_or("truncated ehdr")? as usize;
    if e_shentsize < 64 || e_shnum == 0 {
        return Err("invalid section headers".into());
    }
    let mut shdrs = Vec::with_capacity(e_shnum);
    for idx in 0..e_shnum {
        let base = e_shoff.checked_add(idx * e_shentsize).ok_or("shoff overflow")?;
        if base + 64 > data.len() {
            return Err("truncated section header".into());
        }
        shdrs.push((
            read_u32_le(data, base + 4).unwrap(),
            read_u64_le(data, base + 24).unwrap() as usize,
            read_u64_le(data, base + 32).unwrap() as usize,
            read_u32_le(data, base + 40).unwrap() as usize,
            read_u64_le(data, base + 56).unwrap() as usize,
        ));
    }

    const SHT_SYMTAB: u32 = 2;
    const STB_GLOBAL: u8 = 1;
    const STB_WEAK: u8 = 2;
    let mut out = ObjSymbols::default();

    for &(sh_type, sh_offset, sh_size, sh_link, sh_entsize) in &shdrs {
        if sh_type != SHT_SYMTAB || sh_entsize < 24 || sh_link >= shdrs.len() {
            continue;
        }
        let Some(sbytes) = data.get(sh_offset..sh_offset.saturating_add(sh_size)) else { continue };
        let (_, str_off, str_sz, _, _) = shdrs[sh_link];
        let Some(strtab) = data.get(str_off..str_off.saturating_add(str_sz)) else { continue };
        let count = sh_size / sh_entsize;
        for i in 1..count {
            let off = i * sh_entsize;
            if off + 24 > sbytes.len() {
                break;
            }
            let st_name = read_u32_le(sbytes, off).unwrap() as usize;
            let st_info = sbytes[off + 4];
            let st_shndx = read_u16_le(sbytes, off + 6).unwrap();
            let bind = st_info >> 4;
            let sym = read_cstr(strtab, st_name);
            if sym.is_empty() {
                continue;
            }
            if st_shndx == 0 {
                // Only hard STB_GLOBAL undefs fail MODPOST; weak undefs are optional
                if bind == STB_GLOBAL {
                    out.undefs.push(sym.to_string());
                }
            } else if bind == STB_GLOBAL || bind == STB_WEAK {
                out.defined.push(sym.to_string());
            }
        }
    }
    Ok(out)
}

pub fn parse_obj_symbols(path: &Path) -> Result<ObjSymbols, String> {
    let data = fs::read(path).map_err(|e| format!("read error: {e}"))?;
    parse_obj_symbols_bytes(&data)
}

/// Load all global defined symbols from every `.ko` under a techpack build dir
/// (covers unmodified sibling `.c` files in multi-object modules even under Full-LTO!).
pub fn load_techpack_ko_symbols(dir: &Path) -> HashSet<String> {
    let mut syms = HashSet::new();
    fn walk(d: &Path, syms: &mut HashSet<String>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                walk(&p, syms);
            } else if p.extension().is_some_and(|e| e == "ko") {
                if let Ok(os) = parse_obj_symbols(&p) {
                    syms.extend(os.defined);
                }
            }
        }
    }
    if dir.is_dir() {
        walk(dir, &mut syms);
    }
    syms
}

/// Load every symbol listed in `KERNEL_OBJ/System.map` (for in-tree built-in `.o` link checks).
pub fn load_vmlinux_system_map(ctx: &Ctx) -> HashSet<String> {
    let mut syms = HashSet::new();
    let sm = ctx.kernel_obj.join("System.map");
    let Ok(txt) = fs::read_to_string(sm) else { return syms };
    for ln in txt.lines() {
        let mut it = ln.split_whitespace();
        let _addr = it.next();
        let _kind = it.next();
        if let Some(name) = it.next() {
            syms.insert(name.to_string());
        }
    }
    syms
}

fn collect_symvers_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_symvers_recursive(&p, out);
        } else if ent.file_name() == "Module.symvers" {
            out.push(p);
        }
    }
}

/// Load `Module.symvers` from KERNEL_OBJ (vmlinux + in-tree) and all out-of-tree module dirs.
/// Returns (vmlinux_exports, all_symvers_crc_map).
pub fn load_symvers(ctx: &Ctx) -> (HashSet<String>, HashMap<String, u64>) {
    let mut vmlinux_syms = HashSet::new();
    let mut crc_map = HashMap::new();

    let mut files = Vec::new();
    let main_sv = ctx.kernel_obj.join("Module.symvers");
    if main_sv.is_file() {
        files.push(main_sv);
    }
    let ext_obj = ctx.product_out.join("obj/sm8735-modules");
    if ext_obj.is_dir() {
        collect_symvers_recursive(&ext_obj, &mut files);
    }

    for f in files {
        let Ok(txt) = fs::read_to_string(&f) else { continue };
        for ln in txt.lines() {
            let p: Vec<&str> = ln.split('\t').collect();
            if p.len() >= 3 {
                let crc_str = p[0].trim().trim_start_matches("0x").trim_start_matches("0X");
                let crc = u64::from_str_radix(crc_str, 16).unwrap_or(0);
                let sym = p[1].trim().to_string();
                let owner = p[2].trim();
                if owner == "vmlinux" {
                    vmlinux_syms.insert(sym.clone());
                }
                if crc != 0 || !crc_map.contains_key(&sym) {
                    crc_map.insert(sym, crc);
                }
            }
        }
    }
    (vmlinux_syms, crc_map)
}

pub struct ElfAuditResult {
    pub ok: bool,
    pub total_kos: usize,
    pub vermagic_errs: Vec<String>,
    pub missing_deps: Vec<String>,
    pub partition_order_errs: Vec<String>,
    pub unresolved_syms: Vec<String>,
    pub crc_mismatches: Vec<String>,
    pub ko_names: BTreeSet<String>,
    pub all_basenames: Vec<String>,
}

fn partition_rank(part: &str) -> u8 {
    match part {
        "vendor_ramdisk" => 0,
        "system_dlkm" => 1,
        "vendor_dlkm" => 2,
        _ => 3,
    }
}

/// Full ELF64 binary verification across staged kernel modules:
/// vermagic, depends= closure, partition boot-order, SHN_UNDEF symbol resolution, and __versions CRC!
pub fn audit_staged_modules(ctx: &Ctx, uts: &str, kos: &[(String, PathBuf)]) -> ElfAuditResult {
    let parsed: Vec<Result<KoInfo, (String, String, String)>> = par_map(kos, ctx.threads, |(part, p)| {
        parse_ko_file(p, part).map_err(|e| {
            let fname = p.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            (part.clone(), fname, e)
        })
    });

    let mut infos = Vec::new();
    let mut vermagic_errs = Vec::new();
    let mut ko_names = BTreeSet::new();
    let mut all_basenames = Vec::new();

    for res in parsed {
        match res {
            Ok(info) => {
                let fname = info.path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                ko_names.insert(format!("{}/{}", info.partition, fname));
                all_basenames.push(fname);
                infos.push(info);
            }
            Err((part, fname, err)) => {
                vermagic_errs.push(format!("{part}/{fname}: ELF parse failed ({err})"));
            }
        }
    }

    // Build maps of module -> earliest partition rank, and symbol -> earliest provider rank
    let (vmlinux_syms, crc_map) = load_symvers(ctx);
    let mut mod_rank: HashMap<String, u8> = HashMap::new();
    let mut sym_rank: HashMap<String, u8> = HashMap::new();
    for s in &vmlinux_syms {
        sym_rank.insert(s.clone(), 0);
    }
    for info in &infos {
        let r = partition_rank(&info.partition);
        mod_rank
            .entry(info.mod_name.clone())
            .and_modify(|e| *e = (*e).min(r))
            .or_insert(r);
        for exp in &info.exports {
            sym_rank
                .entry(exp.clone())
                .and_modify(|e| *e = (*e).min(r))
                .or_insert(r);
        }
    }
    // Also accept any symbol present in Module.symvers even if owner wasn't "vmlinux"
    // (at rank 2 as fallback if not exported by a staged .ko)
    let all_known_syms: HashSet<&String> = crc_map.keys().collect();

    let mut missing_deps = Vec::new();
    let mut partition_order_errs = Vec::new();
    let mut unresolved_syms = Vec::new();
    let mut crc_mismatches = Vec::new();

    for info in &infos {
        let fname = info.path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let my_rank = partition_rank(&info.partition);

        // 1. vermagic
        match &info.vermagic {
            Some(v) if !uts.is_empty() && v.starts_with(uts) => {}
            Some(v) => vermagic_errs.push(format!("{}/{}: `{}`", info.partition, fname, truncate_str(v, 60))),
            None => vermagic_errs.push(format!("{}/{}: missing vermagic", info.partition, fname)),
        }

        // 2. depends= closure & partition ordering
        for dep in &info.depends {
            match mod_rank.get(dep) {
                None => {
                    // Could be built-in into vmlinux (normal in some Kconfig setups); only flag if
                    // we also see unresolved symbols or if it's not a built-in module.
                    // Check modules.builtin to avoid false positives!
                    let builtin = ctx.kernel_obj.join("modules.builtin");
                    let is_builtin = fs::read_to_string(&builtin)
                        .map(|txt| txt.contains(&format!("/{dep}.ko")) || txt.contains(&format!("/{}.ko", dep.replace('_', "-"))))
                        .unwrap_or(false);
                    if !is_builtin {
                        missing_deps.push(format!("{}/{}: depends on missing module `{dep}`", info.partition, fname));
                    }
                }
                Some(&dep_r) if dep_r > my_rank => {
                    partition_order_errs.push(format!(
                        "{}/{}: early-boot module depends on later-partition module `{dep}`!",
                        info.partition, fname
                    ));
                }
                _ => {}
            }
        }

        // 3. SHN_UNDEF symbol resolution (only check if Module.symvers loaded!)
        if !vmlinux_syms.is_empty() {
            let mut missing_for_ko = Vec::new();
            let mut late_for_ko = Vec::new();
            for sym in &info.undefs {
                // Skip compiler/linker internal symbols like _mcount, __fentry__, __stack_chk_fail, etc. if absent
                if sym.starts_with("__cfi_") || sym.starts_with("__ubsan_") || sym.starts_with("__llvm_") {
                    continue;
                }
                match sym_rank.get(sym) {
                    Some(&prov_r) => {
                        if prov_r > my_rank {
                            late_for_ko.push(sym.clone());
                        }
                    }
                    None => {
                        if !all_known_syms.contains(sym) {
                            missing_for_ko.push(sym.clone());
                        }
                    }
                }
            }
            if !missing_for_ko.is_empty() {
                unresolved_syms.push(format!(
                    "{}/{}: {} unresolved symbol(s): {}",
                    info.partition,
                    fname,
                    missing_for_ko.len(),
                    missing_for_ko.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
            if !late_for_ko.is_empty() {
                partition_order_errs.push(format!(
                    "{}/{}: calls later-partition symbol(s): {}",
                    info.partition,
                    fname,
                    late_for_ko.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
        }

        // 4. __versions CRC check (when CONFIG_MODVERSIONS emits __versions section)
        if !info.versions.is_empty() && !crc_map.is_empty() {
            let mut bad_crc = Vec::new();
            for (crc, sym) in &info.versions {
                if sym == "module_layout" {
                    continue;
                }
                if let Some(&expected) = crc_map.get(sym) {
                    if expected != 0 && *crc != expected {
                        bad_crc.push(format!("{sym} (ko=0x{crc:08x} != symvers=0x{expected:08x})"));
                    }
                }
            }
            if !bad_crc.is_empty() {
                crc_mismatches.push(format!(
                    "{}/{}: {} CRC mismatch(es): {}",
                    info.partition,
                    fname,
                    bad_crc.len(),
                    bad_crc.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }

    let ok = vermagic_errs.is_empty()
        && missing_deps.is_empty()
        && partition_order_errs.is_empty()
        && unresolved_syms.is_empty()
        && crc_mismatches.is_empty()
        && !infos.is_empty();

    ElfAuditResult {
        ok,
        total_kos: infos.len(),
        vermagic_errs,
        missing_deps,
        partition_order_errs,
        unresolved_syms,
        crc_mismatches,
        ko_names,
        all_basenames,
    }
}

/// Scan device/ and vendor/ trees for any prebuilt closed-source `.ko` blobs!
pub fn find_prebuilt_kos(ws_root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for rel in ["src/device/xiaomi", "src/vendor/xiaomi"] {
        let dir = ws_root.join(rel);
        if dir.is_dir() {
            collect_kos_rec(&dir, &mut found);
        }
    }
    found.sort();
    found
}

fn collect_kos_rec(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_kos_rec(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("ko") {
            out.push(p);
        }
    }
}

/// Also check `modules.load*` consistency inside a staged partition directory.
/// Normalizes `.ko` suffix and `-`/`_` differences (Android `modules.load` uses bare names).
pub fn check_modules_load_lists(part_dir: &Path, part_name: &str, staged_basenames: &HashSet<String>) -> Vec<String> {
    let mut errs = Vec::new();
    let norm_staged: HashSet<String> = staged_basenames
        .iter()
        .map(|s| s.trim_end_matches(".ko").replace('-', "_"))
        .collect();
    let Ok(rd) = fs::read_dir(part_dir) else { return errs };
    for ent in rd.flatten() {
        let p = ent.path();
        let name = ent.file_name().to_string_lossy().into_owned();
        if name.starts_with("modules.load") && p.is_file() {
            if let Ok(txt) = fs::read_to_string(&p) {
                for ln in txt.lines() {
                    let t = ln.trim();
                    if t.is_empty() || t.starts_with('#') {
                        continue;
                    }
                    let base = Path::new(t)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| t.to_string());
                    let norm = base.trim_end_matches(".ko").replace('-', "_");
                    if !norm_staged.contains(&norm) {
                        errs.push(format!("{part_name}/{name}: lists missing `{base}`"));
                    }
                }
            }
        }
    }
    errs
}

// Keep unused-import warning away if BTreeMap is used in tests
#[allow(dead_code)]
fn _keep_btreemap(_: BTreeMap<String, String>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_elf64_ko() -> Vec<u8> {
        // Minimal valid ELF64 LE object with sections:
        // [0] NULL, [1] .shstrtab, [2] .modinfo, [3] __ksymtab_strings, [4] __versions, [5] .strtab, [6] .symtab
        let shstrtab = b"\0.shstrtab\0.modinfo\0__ksymtab_strings\0__versions\0.strtab\0.symtab\0";
        let modinfo = b"vermagic=6.6.162-Drago SMP preempt\0name=test_drv\0depends=dep_a,dep-b\0";
        let ksymtab_str = b"my_exported_fn\0";
        let mut versions = vec![0u8; 64];
        versions[0..8].copy_from_slice(&0x12345678u64.to_le_bytes());
        versions[8..8 + 9].copy_from_slice(b"printk_fn");
        let strtab = b"\0printk_fn\0local_sym\0";
        // 3 Elf64_Sym entries (24B each): [0] null, [1] STB_GLOBAL SHN_UNDEF printk_fn, [2] STB_LOCAL SHN_UNDEF local_sym
        let mut symtab = vec![0u8; 24 * 3];
        // sym 1: st_name=1, st_info=(1<<4)=0x10 (STB_GLOBAL), st_shndx=0
        symtab[24..28].copy_from_slice(&1u32.to_le_bytes());
        symtab[28] = 0x10;
        // sym 2: st_name=11, st_info=0x00 (STB_LOCAL), st_shndx=0
        symtab[48..52].copy_from_slice(&11u32.to_le_bytes());
        symtab[52] = 0x00;

        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB

        let mut push_sec = |data: &[u8]| -> (usize, usize) {
            let off = buf.len();
            buf.extend_from_slice(data);
            (off, data.len())
        };
        let s1 = push_sec(shstrtab);
        let s2 = push_sec(modinfo);
        let s3 = push_sec(ksymtab_str);
        let s4 = push_sec(&versions);
        let s5 = push_sec(strtab);
        let s6 = push_sec(&symtab);

        let shoff = buf.len();
        buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        buf[60..62].copy_from_slice(&7u16.to_le_bytes());
        buf[62..64].copy_from_slice(&1u16.to_le_bytes());

        let mut push_shdr = |name_off: u32, sh_type: u32, off: usize, sz: usize, link: u32, entsize: u64| {
            let mut sh = [0u8; 64];
            sh[0..4].copy_from_slice(&name_off.to_le_bytes());
            sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
            sh[24..32].copy_from_slice(&(off as u64).to_le_bytes());
            sh[32..40].copy_from_slice(&(sz as u64).to_le_bytes());
            sh[40..44].copy_from_slice(&link.to_le_bytes());
            sh[56..64].copy_from_slice(&entsize.to_le_bytes());
            buf.extend_from_slice(&sh);
        };
        push_shdr(0, 0, 0, 0, 0, 0);
        push_shdr(1, 3, s1.0, s1.1, 0, 0);   // .shstrtab
        push_shdr(11, 1, s2.0, s2.1, 0, 0);  // .modinfo
        push_shdr(20, 1, s3.0, s3.1, 0, 0);  // __ksymtab_strings
        push_shdr(38, 1, s4.0, s4.1, 0, 0);  // __versions
        push_shdr(49, 3, s5.0, s5.1, 0, 0);  // .strtab
        push_shdr(57, 2, s6.0, s6.1, 5, 24); // .symtab -> link=5 (.strtab)
        buf
    }

    #[test]
    fn test_elf64_ko_parser() {
        let bytes = build_synthetic_elf64_ko();
        let info = parse_ko_bytes(&bytes, PathBuf::from("test-drv.ko"), "vendor_dlkm").unwrap();
        assert_eq!(info.mod_name, "test_drv");
        assert_eq!(info.vermagic.as_deref(), Some("6.6.162-Drago SMP preempt"));
        assert_eq!(info.depends, vec!["dep_a", "dep_b"]);
        assert_eq!(info.exports, vec!["my_exported_fn"]);
        assert_eq!(info.undefs, vec!["printk_fn"]);
        assert_eq!(info.versions, vec![(0x12345678, "printk_fn".to_string())]);
    }
}
