//! Pure-Rust Qualcomm Minidump (`Raw_Dmp!` v2 / `/dev/block/by-name/rawdump`) forensic crash decoder.
//!
//! Supports both live ADB extraction (reading ONLY small diagnostic sections via targeted `dd`,
//! typically ~10 MiB total instead of pulling the full 300 MiB partition) and offline rawdump files.
//!
//! Decodes:
//!   1. `Raw_Dmp!` v2 header + 64-byte section TOC (`0x58`, stride `0x40`)
//!   2. `md_HYP_DIAG.BIN` (Gunyah EL2 hypervisor log) + automatic ARM SMMUv2/QSMMUV500 register
//!      bitfield decoder (`FSR`, `FSYNR0`, `FSYNR1`, `CBFRSYNRA`, `CBAR`, `TCR`/`VTCR`)
//!   3. `md_RST_STAT.BIN` + `md_XBL_LOG.BIN` + `md_RM_Log3.BIN`
//!   4. `md_PMON_HIS.BIN` (Qualcomm PMIC PON `PLOG` history via `pmic-pon-log.c` tables)
//!   5. `md_KLOGBUF.BIN` + `md_LOG_DESC.BIN` + `md_LOG_INFO.BIN` (Linux 6.12 `printk_ringbuffer`)
//!   6. `md_KPMSG.BIN` (Android binary `pmsg` logcat ringbuffer, wall-clock sorted)
//!   7. `md_KELF_HDR.BIN` + `md_KDATABSS.BIN` + `md_KWDOGDATA.BIN` + `md_KMODULES.BIN` + `md_dump_vms4.BIN`
//!      (auto-KASLR slide, `panic_cpu`/`oops_in_progress`/`system_state`, watchdog margins, vCPU symbolization)
//!   8. `md_KGSL_EVENTLO.BIN` (Adreno KGSL `0xabbaabba` event ring + in-flight unretired GPU contexts)

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::device;
use crate::util::*;

// ====================================================== 1. Raw_Dmp! v2 Container & TOC

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawDumpHeader {
    pub version: u32,
    pub valid: u32,
    pub dump_size: u64,
    pub total_size: u64,
    pub sec_count: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawDumpSection {
    pub name: String,
    pub valid: u32,
    pub version: u32,
    pub sec_type: u32,
    pub offset: u64,
    pub size: u64,
    pub vaddr: u64,
}

#[derive(Debug, Clone)]
pub struct RawDumpToc {
    pub header: RawDumpHeader,
    pub sections: BTreeMap<String, RawDumpSection>,
}

fn le_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le_i32(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

fn decode_base64_loose(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut vals = [0u8; 4];
    let mut n = 0usize;
    let mut pad = 0usize;
    for &b in input {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                0
            }
            _ => continue,
        };
        vals[n] = v;
        n += 1;
        if n == 4 {
            let triple = ((vals[0] as u32) << 18)
                | ((vals[1] as u32) << 12)
                | ((vals[2] as u32) << 6)
                | (vals[3] as u32);
            out.push(((triple >> 16) & 0xff) as u8);
            if pad < 2 {
                out.push(((triple >> 8) & 0xff) as u8);
            }
            if pad < 1 {
                out.push((triple & 0xff) as u8);
            }
            n = 0;
            pad = 0;
        }
    }
    out
}

/// Parse Qualcomm `Raw_Dmp!` v2 header + 64-byte section entries from the initial header buffer (e.g. 16 KiB).
pub fn parse_rawdump_toc(buf: &[u8]) -> Result<RawDumpToc, String> {
    if buf.len() < 0x98 {
        return Err(format!("rawdump header too small ({} bytes)", buf.len()));
    }
    if &buf[0..8] != b"Raw_Dmp!" {
        let preview = String::from_utf8_lossy(&buf[0..8]);
        return Err(format!("invalid rawdump magic `{preview}` (expected `Raw_Dmp!`)"));
    }
    let version = le_u32(buf, 8);
    let valid = le_u32(buf, 12);
    let dump_size = le_u64(buf, 36);
    let total_size = le_u64(buf, 44);
    let sec_count = le_u32(buf, 52);

    if sec_count == 0 || sec_count > 1024 {
        return Err(format!("implausible rawdump section count: {sec_count}"));
    }

    // Standard SM8735/Pakala v2 (0x2000) TOC starts at 0x58, stride 0x40.
    // Fallback probe around 0x50..0x80 if a slightly different bootloader header size is encountered.
    let mut table_off = 0x58usize;
    if !(table_off + 0x40 <= buf.len() && le_u32(buf, table_off) == 1 && le_u32(buf, table_off + 4) == 0x1000) {
        for cand in (0x40..=0x80).step_by(4) {
            if cand + 0x40 <= buf.len()
                && le_u32(buf, cand) == 1
                && le_u32(buf, cand + 4) == 0x1000
                && le_u32(buf, cand + 8) <= 8
            {
                table_off = cand;
                break;
            }
        }
    }

    let mut sections = BTreeMap::new();
    for i in 0..(sec_count as usize) {
        let o = table_off + i * 0x40;
        if o + 0x40 > buf.len() {
            break;
        }
        let svalid = le_u32(buf, o);
        let sver = le_u32(buf, o + 4);
        let stype = le_u32(buf, o + 8);
        let soff = le_u64(buf, o + 12);
        let ssz = le_u64(buf, o + 20);
        let sva = le_u64(buf, o + 28);
        let name_raw = &buf[o + 0x2c..o + 0x40];
        let end = name_raw.iter().position(|&c| c == 0).unwrap_or(name_raw.len());
        let name = String::from_utf8_lossy(&name_raw[..end]).trim().to_string();
        if name.is_empty() || svalid == 0 {
            continue;
        }
        sections.insert(
            name.clone(),
            RawDumpSection {
                name,
                valid: svalid,
                version: sver,
                sec_type: stype,
                offset: soff,
                size: ssz,
                vaddr: sva,
            },
        );
    }

    Ok(RawDumpToc {
        header: RawDumpHeader {
            version,
            valid,
            dump_size,
            total_size,
            sec_count,
        },
        sections,
    })
}

// ====================================================== 2. Data Source (Live ADB or Local File)

enum DumpSource {
    Adb { serial: String, device_path: String },
    File(PathBuf),
}

impl DumpSource {
    fn read_range(&self, offset: u64, size: u64) -> Result<Vec<u8>, String> {
        if size == 0 {
            return Ok(Vec::new());
        }
        match self {
            DumpSource::File(path) => {
                let mut f = fs::File::open(path)
                    .map_err(|e| format!("open `{}` failed: {e}", path.display()))?;
                f.seek(SeekFrom::Start(offset))
                    .map_err(|e| format!("seek to 0x{offset:x} failed: {e}"))?;
                let mut buf = vec![0u8; size as usize];
                f.read_exact(&mut buf)
                    .map_err(|e| format!("read {size} bytes @0x{offset:x} failed: {e}"))?;
                Ok(buf)
            }
            DumpSource::Adb { serial, device_path } => {
                // 1. Direct `adb exec-out dd` (when adbd is root): zero PTY, 100% binary-clean, full USB speed.
                let direct_cmd = format!(
                    "dd if={device_path} iflag=skip_bytes,count_bytes skip={offset} count={size} bs=65536 2>/dev/null"
                );
                if let Ok(out) = Command::new("adb")
                    .args(["-s", serial, "exec-out", &direct_cmd])
                    .output()
                {
                    if out.status.success() && out.stdout.len() == size as usize {
                        return Ok(out.stdout);
                    }
                }
                // 2. Fallback via `su -c "... | base64"` so PTY \n->\r\n translation NEVER corrupts binary data.
                let b64_cmd = format!(
                    "su -c \"dd if={device_path} iflag=skip_bytes,count_bytes skip={offset} count={size} bs=65536 2>/dev/null | base64\""
                );
                let out2 = Command::new("adb")
                    .args(["-s", serial, "exec-out", &b64_cmd])
                    .output()
                    .map_err(|e| format!("adb exec-out su base64 failed: {e}"))?;
                let decoded = decode_base64_loose(&out2.stdout);
                if decoded.len() == size as usize {
                    return Ok(decoded);
                }
                if !decoded.is_empty() && offset == 0 && decoded.len() >= 0x98 {
                    return Ok(decoded);
                }
                Err(format!(
                    "dd read failed @0x{offset:x}+{size} (got {} bytes): {}",
                    decoded.len(),
                    String::from_utf8_lossy(&out2.stderr).trim()
                ))
            }
        }
    }

    fn read_section(&self, toc: &RawDumpToc, name: &str, max_bytes: Option<u64>) -> Result<Vec<u8>, String> {
        let sec = toc
            .sections
            .get(name)
            .ok_or_else(|| format!("section `{name}` not present"))?;
        let n = match max_bytes {
            Some(m) => sec.size.min(m),
            None => sec.size,
        };
        self.read_range(sec.offset, n)
    }
}

// ====================================================== 3. ARM SMMUv2 / QSMMUV500 Fault Decoder

#[derive(Debug, Clone)]
pub struct SmmuFaultDecoded {
    pub smmu_base: u64,
    pub smmu_name: &'static str,
    pub cb: Option<u32>,
    pub fsr: Option<u32>,
    pub fsr_flags: Vec<&'static str>,
    pub fsr_format: Option<&'static str>,
    pub far: Option<u64>,
    pub ipafar: Option<u64>,
    pub fsynr0: Option<u32>,
    pub fsynr0_desc: String,
    pub cbar: Option<u32>,
    pub cbar_desc: String,
    pub tcr: Option<u32>,
    pub tcr_desc: String,
    pub sid: Option<u32>,
    pub ttbr0: Option<u64>,
}

fn parse_hex_field(line: &str, key: &str) -> Option<u64> {
    let idx = line.find(key)?;
    let rest = line[idx + key.len()..].trim_start();
    let hex_part = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))
        .unwrap_or(rest)
        .trim_start();
    let digits: String = hex_part
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        u64::from_str_radix(&digits, 16).ok()
    }
}

fn parse_dec_field(line: &str, key: &str) -> Option<u32> {
    let idx = line.find(key)?;
    let rest = line[idx + key.len()..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok()
}

pub fn decode_smmu_base_name(base: u64) -> &'static str {
    match base {
        0x03da_0000 => "kgsl-smmu (Adreno GPU)",
        0x1500_0000 => "apps-smmu (APPS/Display/Video/Camera/UFS/PCIe)",
        0x050a_0000 | 0x059a_0000 => "kgsl-smmu (legacy Adreno GPU)",
        _ => "unknown-smmu",
    }
}

pub fn decode_smmu_fault_line(line: &str) -> Option<SmmuFaultDecoded> {
    if !line.contains("SMMU_ERR_FATAL") && !line.contains("FSR=") {
        return None;
    }
    let smmu_base = parse_hex_field(line, "SMMU:>>").unwrap_or(0);
    let cb = parse_dec_field(line, "CB:");
    let fsr_u64 = parse_hex_field(line, "FSR=");
    let fsr = fsr_u64.map(|v| v as u32);
    let far = parse_hex_field(line, "FAR=");
    let ipafar = parse_hex_field(line, "IPAFAR=");
    let fsynr0 = parse_hex_field(line, "FSYNR0=").map(|v| v as u32);
    // Note: Gunyah EL2 prints 32-bit registers as %llx with uninitialized upper 32 bits; mask low 32!
    let cbar = parse_hex_field(line, "CBAR=").map(|v| (v & 0xffff_ffff) as u32);
    let tcr = parse_hex_field(line, "TCR=").map(|v| (v & 0xffff_ffff) as u32);
    let sid = parse_hex_field(line, "CBFRSYNRA=").map(|v| (v & 0xffff) as u32);
    let ttbr0 = parse_hex_field(line, "TTBR0=");

    let mut fsr_flags = Vec::new();
    let mut fsr_format = None;
    if let Some(f) = fsr {
        if (f & (1 << 31)) != 0 { fsr_flags.push("MULTI"); }
        if (f & (1 << 30)) != 0 { fsr_flags.push("SS(Stalled)"); }
        if (f & (1 << 8)) != 0 { fsr_flags.push("UUT(UnsupportedUpstreamTxn)"); }
        if (f & (1 << 7)) != 0 { fsr_flags.push("ASF(AddressSizeFault)"); }
        if (f & (1 << 6)) != 0 { fsr_flags.push("TLBLKF"); }
        if (f & (1 << 5)) != 0 { fsr_flags.push("TLBMCF"); }
        if (f & (1 << 4)) != 0 { fsr_flags.push("EF(ExternalFault)"); }
        if (f & (1 << 3)) != 0 { fsr_flags.push("PF(PermissionFault)"); }
        if (f & (1 << 2)) != 0 { fsr_flags.push("AFF(AccessFlagFault)"); }
        if (f & (1 << 1)) != 0 { fsr_flags.push("TF(TranslationFault)"); }
        fsr_format = Some(match (f >> 9) & 0x3 {
            0 => "AArch32-S",
            1 => "AArch32-L",
            2 => "AArch64",
            _ => "Reserved",
        });
    }

    let fsynr0_desc = if let Some(s) = fsynr0 {
        let plvl = s & 0x3;
        let s2 = (s & (1 << 2)) != 0;
        let wnr = (s & (1 << 4)) != 0;
        let pnu = (s & (1 << 5)) != 0;
        let ind = (s & (1 << 6)) != 0;
        let nsattr = (s & (1 << 8)) != 0;
        let ptwf = (s & (1 << 10)) != 0;
        let afr = (s & (1 << 11)) != 0;
        let s1cb = (s >> 16) & 0xff;
        let mut parts = vec![
            if wnr { "WRITE" } else { "READ" }.to_string(),
            format!("PLVL={plvl}"),
        ];
        if s2 { parts.push("S2".to_string()); }
        if ptwf { parts.push("PTWF(S1WalkFault)".to_string()); }
        if pnu { parts.push("PNU(Priv)".to_string()); }
        if ind { parts.push("IND(Instr)".to_string()); }
        if nsattr { parts.push("NSATTR".to_string()); }
        if afr { parts.push("AFR".to_string()); }
        let cb_hint = if smmu_base == 0x03da_0000 {
            match s1cb {
                0 => " (gfx3d_user)",
                1 => " (gfx3d_lpac)",
                2 => " (gfx3d_secure)",
                _ => "",
            }
        } else {
            ""
        };
        parts.push(format!("S1CBNDX={s1cb}{cb_hint}"));
        parts.join(" | ")
    } else {
        String::new()
    };

    let cbar_desc = if let Some(c) = cbar {
        let vmid = c & 0xff;
        let typ = (c >> 16) & 0x3;
        let typ_s = match typ {
            0 => "Stage-2",
            1 => "Stage-1 (S2 bypass)",
            2 => "Stage-1 (S2 fault)",
            _ => "Nested S1+S2",
        };
        let vm_hint = match vmid {
            3 => " (HLOS Android)",
            _ => "",
        };
        format!("{typ_s}, VMID={vmid}{vm_hint}")
    } else {
        String::new()
    };

    let tcr_desc = if let Some(t) = tcr {
        let is_s2 = cbar.map(|c| ((c >> 16) & 0x3) == 0).unwrap_or(false);
        let t0sz = t & 0x3f;
        let ias = 64u32.saturating_sub(t0sz);
        let tg0 = match (t >> 14) & 0x3 {
            0 => "4K",
            1 => "64K",
            2 => "16K",
            _ => "?",
        };
        if is_s2 {
            let sl0 = (t >> 6) & 0x3;
            let start_lvl = match sl0 {
                0 => "L2",
                1 => "L1",
                2 => "L0",
                _ => "?",
            };
            let ps = match (t >> 16) & 0x7 {
                0 => "32b",
                1 => "36b",
                2 => "40b",
                3 => "42b",
                4 => "44b",
                5 => "48b",
                _ => "?",
            };
            format!("IPA={ias}b (T0SZ={t0sz}), PA={ps}, granule={tg0}, start={start_lvl}")
        } else {
            format!("VA={ias}b (T0SZ={t0sz}), granule={tg0}")
        }
    } else {
        String::new()
    };

    Some(SmmuFaultDecoded {
        smmu_base,
        smmu_name: decode_smmu_base_name(smmu_base),
        cb,
        fsr,
        fsr_flags,
        fsr_format,
        far,
        ipafar,
        fsynr0,
        fsynr0_desc,
        cbar,
        cbar_desc,
        tcr,
        tcr_desc,
        sid,
        ttbr0,
    })
}

// ====================================================== 4. PMIC PON History (`md_PMON_HIS.BIN`)

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PmicPonEntry {
    pub state: u8,
    pub event: u8,
    pub data1: u8,
    pub data0: u8,
    pub summary: String,
    pub is_fault: bool,
    pub is_important: bool,
}

fn pmic_state_name(s: u8) -> &'static str {
    match s {
        0 => "FAULT",
        1 => "PON",
        2 => "POFF",
        3 => "ON",
        4 => "RESET",
        5 => "OFF",
        6 => "FAULT",
        7 => "WARM_RESET",
        _ => "UNKNOWN",
    }
}

fn pmic_pon_trigger_label(code: u16) -> Option<&'static str> {
    match code {
        0x0084 => Some("PS_HOLD"),
        0x0085 => Some("HARD_RESET"),
        0x0086 => Some("RESIN_N"),
        0x0087 => Some("KPDPWR_N"),
        0x0202 | 0x18A0 | 0x2763 | 0x31C2 | 0x71C2 | 0x8732 => Some("USB_CHARGER"),
        0x0621 => Some("RTC_ALARM"),
        0x0640 => Some("SMPL"),
        0x18C0 => Some("PMIC_SID1_GPIO5"),
        0x18F0 => Some("PON_PBS_CBLPWR1_RSN"),
        0x1910 => Some("PON_PBS_CBLPWR2_RSN"),
        0x81C2 => Some("PON_PBS_SYS_OK_RSN_PORT2"),
        _ => None,
    }
}

fn pmic_reset_trigger_label(code: u16) -> Option<&'static str> {
    match code {
        0x0080 => Some("KPDPWR_N_S2"),
        0x0081 => Some("RESIN_N_S2"),
        0x0082 => Some("KPDPWR_N_AND_RESIN_N_S2"),
        0x0083 => Some("PMIC_WATCHDOG_S2"),
        0x0084 => Some("PS_HOLD"),
        0x0085 => Some("SW_RESET"),
        0x0086 => Some("RESIN_N_DEBOUNCE"),
        0x0087 => Some("KPDPWR_N_DEBOUNCE"),
        0x01A4 => Some("PON_PBS_LANDO_OCP_RSN"),
        0x21E3 => Some("PMIC_SID2_BCL_ALARM"),
        0x31F5 => Some("PMIC_SID3_BCL_ALARM"),
        0x11D0 => Some("PMIC_SID1_OCP"),
        0x21D0 => Some("PMIC_SID2_OCP"),
        0x41D0 => Some("PMIC_SID4_OCP"),
        0x51D0 => Some("PMIC_SID5_OCP"),
        _ => None,
    }
}

fn decode_bitmask(val: u8, labels: &[&str; 8]) -> String {
    let mut out = Vec::new();
    for (bit, lbl) in labels.iter().enumerate() {
        if (val & (1 << bit)) != 0 {
            out.push(*lbl);
        }
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join("|")
    }
}

pub fn parse_pmic_pon_history(buf: &[u8]) -> Vec<PmicPonEntry> {
    const FAULT1: [&str; 8] = [
        "GP_FAULT0", "GP_FAULT1", "GP_FAULT2", "GP_FAULT3",
        "MBG_FAULT", "OVLO", "UVLO", "AVDD_RB",
    ];
    const FAULT2: [&str; 8] = [
        "UNK0", "UNK1", "PMIC_RB", "FAULT_N",
        "FAULT_WATCHDOG", "PBS_NACK", "RESTART_PON", "OVERTEMP_STAGE3",
    ];
    const FAULT3: [&str; 8] = [
        "GP_FAULT4", "GP_FAULT5", "GP_FAULT6", "GP_FAULT7",
        "GP_FAULT8", "GP_FAULT9", "GP_FAULT10", "GP_FAULT11",
    ];
    const FAULT4: [&str; 8] = [
        "V1P2_SYS_OK", "PVDD_OK", "CBOOST_OK", "RAW_UVLO_LV_RB",
        "RAW_UVLO_RB", "RAW_OVLO_RB", "RAW_OVLO_LV_RB", "UNK7",
    ];

    let start = if buf.len() >= 8 && &buf[0..4] == b"PLOG" {
        8
    } else {
        0
    };
    let mut out = Vec::new();
    let mut o = start;
    while o + 4 <= buf.len() {
        let state = buf[o];
        let event = buf[o + 1];
        let data1 = buf[o + 2];
        let data0 = buf[o + 3];
        o += 4;
        if state == 0 && event == 0 && data1 == 0 && data0 == 0 {
            continue;
        }
        let code = ((data1 as u16) << 8) | (data0 as u16);
        let st_s = pmic_state_name(state);
        let mut is_fault = state == 0 || state == 6;
        let mut is_important = false;
        let ev_desc = match event {
            0x01 => {
                is_important = true;
                let lbl = pmic_pon_trigger_label(code).unwrap_or("OTHER");
                format!("PON_TRIGGER={lbl}(0x{code:04x})")
            }
            0x06 => {
                is_important = true;
                let lbl = pmic_reset_trigger_label(code).unwrap_or("OTHER");
                format!("RESET_TRIGGER={lbl}(0x{code:04x})")
            }
            0x07 => {
                is_important = true;
                let rtype = match code {
                    0x01 => "WARM_RESET",
                    0x04 => "SHUTDOWN",
                    0x07 => "HARD_RESET",
                    _ => "OTHER",
                };
                format!("RESET_TYPE={rtype}(0x{code:04x})")
            }
            0x08 => format!("WARM_RESET_COUNT={code}"),
            0x09 => {
                is_fault = true;
                is_important = true;
                format!(
                    "FAULT_REASON1=[{}] REASON2=[{}]",
                    decode_bitmask(data0, &FAULT1),
                    decode_bitmask(data1, &FAULT2)
                )
            }
            0x0A => {
                is_fault = true;
                is_important = true;
                format!(
                    "FAULT_REASON3=[{}] REASON4=[{}]",
                    decode_bitmask(data0, &FAULT3),
                    decode_bitmask(data1, &FAULT4)
                )
            }
            0x0C => {
                is_important = true;
                format!("FUNDAMENTAL_RESET(0x{code:04x})")
            }
            0x0E => "PON_SUCCESS".to_string(),
            0x0F => format!("WAITING_ON_PSHOLD(0x{code:04x})"),
            0x10..=0x8E => {
                is_fault = true;
                is_important = true;
                let bus = (event as usize - 0x10 + 1) / 32;
                let sid = (event as usize - 0x10 + 1) % 32;
                format!("SECONDARY_PMIC_FAULT(bus={bus},sid={sid},data=0x{code:04x})")
            }
            _ => format!("EV(0x{event:02x})=0x{code:04x}"),
        };
        out.push(PmicPonEntry {
            state,
            event,
            data1,
            data0,
            summary: format!("{st_s:<10} {ev_desc}"),
            is_fault,
            is_important,
        });
    }
    out
}

// ====================================================== 5. Linux 6.12 `printk_ringbuffer`

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PrbRecord {
    pub seq: u64,
    pub ts_nsec: u64,
    pub level: u8,
    pub facility: u8,
    pub caller_id: u32,
    pub text: String,
}

impl PrbRecord {
    pub fn format_line(&self) -> String {
        let secs = self.ts_nsec / 1_000_000_000;
        let usecs = (self.ts_nsec % 1_000_000_000) / 1_000;
        format!("<{}>[{secs:5}.{usecs:06}] {}", self.level, self.text)
    }
}

/// Reconstruct Linux 6.12 `printk_ringbuffer` records from `md_KLOGBUF.BIN`, `md_LOG_DESC.BIN`, `md_LOG_INFO.BIN`.
/// Layout (arm64 Linux 6.12):
///   - `prb_desc`: 24 bytes = `(state_var: u64, begin: u64, next: u64)`
///   - `printk_info`: 88 bytes = `(seq: u64, ts_nsec: u64, text_len: u16, facility: u8, flags_level: u8, caller_id: u32, dev_info: [u8; 64])`
///   - `text_data_ring`: power-of-2 size; each data block starts with `id: u64` (8 bytes) followed by text bytes!
pub fn decode_printk_ringbuffer(klog: &[u8], log_desc: &[u8], log_info: &[u8]) -> Vec<PrbRecord> {
    if klog.is_empty() || !klog.len().is_power_of_two() || log_desc.len() < 24 || log_info.len() < 88 {
        return Vec::new();
    }
    let data_mask = (klog.len() as u64) - 1;
    let count = (log_desc.len() / 24).min(log_info.len() / 88);
    let mut recs = Vec::with_capacity(count.min(8192));

    for i in 0..count {
        let doff = i * 24;
        let ioff = i * 88;
        let state_var = le_u64(log_desc, doff);
        let state = (state_var >> 62) & 0x3;
        // 1 = desc_committed, 2 = desc_finalized
        if state != 1 && state != 2 {
            continue;
        }
        let desc_id = state_var & ((1u64 << 62) - 1);
        let begin = le_u64(log_desc, doff + 8);
        let next = le_u64(log_desc, doff + 16);

        let seq = le_u64(log_info, ioff);
        let ts_nsec = le_u64(log_info, ioff + 8);
        let text_len = le_u16(log_info, ioff + 16) as usize;
        let facility = log_info[ioff + 18];
        let flg_lvl = log_info[ioff + 19];
        let level = (flg_lvl >> 5) & 0x7;
        let caller_id = le_u32(log_info, ioff + 20);

        // Dataless or invalid lpos (bit 0 set => FAILED_LPOS / EMPTY_LINE_LPOS)
        if (begin & 1) != 0 || (next & 1) != 0 || text_len == 0 || text_len > 4096 {
            continue;
        }
        let begin_idx = (begin & data_mask) as usize;
        let next_idx = (next & data_mask) as usize;
        // Handle wrapped data block: if block wrapped to offset 0, actual block starts at 0!
        let blk_start = if begin_idx > next_idx && next_idx != 0 {
            0usize
        } else {
            begin_idx
        };
        if blk_start + 8 > klog.len() {
            continue;
        }
        let stored_id = le_u64(klog, blk_start);
        if stored_id != desc_id {
            continue;
        }
        let text_start = blk_start + 8;
        let text_end = (text_start + text_len).min(klog.len());
        let raw_text = &klog[text_start..text_end];
        let text = String::from_utf8_lossy(raw_text)
            .trim_end_matches(['\r', '\n', '\0'])
            .to_string();
        recs.push(PrbRecord {
            seq,
            ts_nsec,
            level,
            facility,
            caller_id,
            text,
        });
    }

    recs.sort_by_key(|r| r.seq);
    recs
}

// ====================================================== 6. Android `pmsg` Binary Logcat (`md_KPMSG.BIN`)

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PmsgRecord {
    pub sec: u32,
    pub nsec: u32,
    pub log_id: u8,
    pub prio: u8,
    pub pid: u16,
    pub tid: u16,
    pub tag: String,
    pub msg: String,
}

impl PmsgRecord {
    pub fn prio_char(&self) -> char {
        match self.prio {
            2 => 'V',
            3 => 'D',
            4 => 'I',
            5 => 'W',
            6 => 'E',
            7 => 'F',
            _ => '?',
        }
    }

    pub fn format_line(&self) -> String {
        // UTC HH:MM:SS.mmm from unix sec
        let sod = (self.sec % 86400) as u32;
        let hh = sod / 3600;
        let mm = (sod % 3600) / 60;
        let ss = sod % 60;
        let ms = self.nsec / 1_000_000;
        format!(
            "{hh:02}:{mm:02}:{ss:02}.{ms:03} {:5}/{:5} {} {}: {}",
            self.pid,
            self.tid,
            self.prio_char(),
            self.tag,
            self.msg
        )
    }
}

pub fn decode_kpmsg(buf: &[u8]) -> Vec<PmsgRecord> {
    let mut recs = Vec::new();
    let mut i = 0usize;
    let n = buf.len();
    while i + 18 <= n {
        if buf[i] == 0x6c {
            let plen = le_u16(buf, i + 1) as usize;
            let _uid = le_u16(buf, i + 3);
            let pid = le_u16(buf, i + 5);
            if (18..=4096).contains(&plen) && i + plen <= n {
                let log_id = buf[i + 7];
                let tid = le_u16(buf, i + 8);
                let sec = le_u32(buf, i + 10);
                let nsec = le_u32(buf, i + 14);
                // Sanity-check timestamp (2020..2038) & valid Android log buffer id (0..=8)
                if log_id <= 8 && (1_577_836_800..=2_147_483_647).contains(&sec) && nsec < 1_000_000_000 {
                    let body = &buf[i + 18..i + plen];
                    if body.len() >= 2 && log_id != 2 {
                        // Text log buffers (main=0, radio=1, system=3, crash=4, stats=5, security=6, kernel=7)
                        let prio = body[0];
                        if (2..=7).contains(&prio) {
                            let rest = &body[1..];
                            let nul = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                            let tag = String::from_utf8_lossy(&rest[..nul]).to_string();
                            let msg_bytes = if nul < rest.len() { &rest[nul + 1..] } else { &[] };
                            let msg = String::from_utf8_lossy(msg_bytes)
                                .trim_end_matches(['\0', '\n', '\r'])
                                .replace('\n', " | ");
                            if !tag.is_empty() && tag.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                                recs.push(PmsgRecord {
                                    sec,
                                    nsec,
                                    log_id,
                                    prio,
                                    pid,
                                    tid,
                                    tag,
                                    msg,
                                });
                            }
                        }
                    }
                    i += plen;
                    continue;
                }
            }
        }
        i += 1;
    }
    recs.sort_by_key(|r| (r.sec, r.nsec));
    recs
}

// ====================================================== 7. Adreno KGSL Eventlog (`md_KGSL_EVENTLO.BIN`)

#[derive(Debug, Clone)]
pub struct KgslEvent {
    pub time_ns: u64,
    pub pid: i32,
    pub event_id: u16,
    pub name: &'static str,
    pub ctx_id: Option<u32>,
    pub ts: Option<u32>,
    pub detail: String,
}

pub fn decode_kgsl_eventlog(buf: &[u8]) -> (Vec<KgslEvent>, BTreeMap<u32, (u32, u32, i32)>) {
    const MAGIC: u32 = 0xabba_abba;
    let mut events = Vec::new();
    let mut off = 0usize;
    while off + 24 <= buf.len() {
        let m = le_u32(buf, off);
        if m != MAGIC {
            off += 4;
            continue;
        }
        let pid = le_i32(buf, off + 4);
        let time_ns = le_u64(buf, off + 8);
        let ev_raw = le_u32(buf, off + 16);
        let sz = le_u32(buf, off + 20) as usize;
        let ev_id = (ev_raw & 0xffff) as u16;
        if sz > buf.len().saturating_sub(off + 24) {
            break;
        }
        let payload = &buf[off + 24..off + 24 + sz];
        off += 24 + sz;
        if ev_id == 1 || time_ns == 0 {
            if sz == 0 && ev_id == 0 {
                break;
            }
            continue;
        }
        let (name, ctx_id, ts, detail) = match ev_id {
            2 if payload.len() >= 16 => {
                let cid = le_u32(payload, 0);
                let ts = le_u32(payload, 4);
                let typ = le_u32(payload, 8);
                let age = le_u32(payload, 12);
                ("FIRE", Some(cid), Some(ts), format!("ctx={cid} ts={ts} type={typ} age={age}"))
            }
            3 if payload.len() >= 24 => {
                let cid = le_u32(payload, 0);
                let ts = le_u32(payload, 4);
                let prio = le_u32(payload, 8);
                let flags = le_u64(payload, 16);
                ("CMDBATCH_SUBMIT", Some(cid), Some(ts), format!("ctx={cid} ts={ts} prio={prio} flags=0x{flags:x}"))
            }
            4 if payload.len() >= 40 => {
                let cid = le_u32(payload, 0);
                let ts = le_u32(payload, 4);
                let prio = le_u32(payload, 8);
                let flags = le_u64(payload, 16);
                let start = le_u64(payload, 24);
                let retire = le_u64(payload, 32);
                (
                    "CMDBATCH_RETIRE",
                    Some(cid),
                    Some(ts),
                    format!("ctx={cid} ts={ts} prio={prio} flags=0x{flags:x} dur={}us", retire.saturating_sub(start) / 19),
                )
            }
            5 | 6 if payload.len() >= 8 => {
                let cid = le_u32(payload, 0);
                let fn_raw = &payload[4..];
                let end = fn_raw.iter().position(|&b| b == 0).unwrap_or(fn_raw.len());
                let fname = String::from_utf8_lossy(&fn_raw[..end]);
                (
                    if ev_id == 5 { "SYNCPOINT_FENCE" } else { "SYNCPOINT_EXPIRE" },
                    Some(cid),
                    None,
                    format!("ctx={cid} fence={fname}"),
                )
            }
            7 | 8 if payload.len() >= 16 => {
                let id = le_u32(payload, 0);
                let seq = le_u64(payload, 8);
                (
                    if ev_id == 7 { "TIMELINE_ALLOC" } else { "TIMELINE_RELEASE" },
                    Some(id),
                    None,
                    format!("id={id} seq={seq}"),
                )
            }
            _ => ("UNKNOWN", None, None, format!("ev={ev_id} sz={sz}")),
        };
        events.push(KgslEvent {
            time_ns,
            pid,
            event_id: ev_id,
            name,
            ctx_id,
            ts,
            detail,
        });
    }
    events.sort_by_key(|e| e.time_ns);

    // Track per-context (max_submitted_ts, max_retired_ts, submit_pid) to spot in-flight GPU jobs at crash!
    let mut ctx_state: BTreeMap<u32, (u32, u32, i32)> = BTreeMap::new();
    for ev in &events {
        if let (Some(cid), Some(ts)) = (ev.ctx_id, ev.ts) {
            let entry = ctx_state.entry(cid).or_insert((0, 0, ev.pid));
            if ev.event_id == 3 {
                if ts > entry.0 {
                    entry.0 = ts;
                    entry.2 = ev.pid;
                }
            } else if ev.event_id == 4 && ts > entry.1 {
                entry.1 = ts;
            }
        }
    }
    (events, ctx_state)
}

// ====================================================== 8. Watchdog, KASLR, Kernel State & vCPU Symbolizer

fn extract_ascii_runs(buf: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in buf {
        if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    for ln in s.lines() {
                        let t = ln.trim();
                        if t.len() >= min_len.min(6) {
                            out.push(t.to_string());
                        }
                    }
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = String::from_utf8(cur) {
            for ln in s.lines() {
                let t = ln.trim();
                if t.len() >= min_len.min(6) {
                    out.push(t.to_string());
                }
            }
        }
    }
    out
}

fn find_llvm_tool(ctx: &Ctx, tool: &str) -> Option<PathBuf> {
    let clang_dir = ctx.ws_root.join("src/prebuilts/clang/host/linux-x86");
    if let Ok(rd) = fs::read_dir(&clang_dir) {
        let mut cands: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path().join("bin").join(tool))
            .filter(|p| p.is_file())
            .collect();
        cands.sort();
        if let Some(p) = cands.pop() {
            return Some(p);
        }
    }
    let (rc, out, _) = run_cmd("which", &[tool], &ctx.ws_root, None);
    if rc == 0 {
        let p = PathBuf::from(out.trim());
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn find_matching_vmlinux(ctx: &Ctx, banner: Option<&str>, explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(b) = banner {
        // Parse `Linux version <uts> (...)`
        if let Some(rest) = b.split("Linux version ").nth(1) {
            if let Some(uts) = rest.split_whitespace().next() {
                let exact = ctx
                    .product_out
                    .join("obj/PACKAGING/kernel_modules_intermediates/lib/modules")
                    .join(uts)
                    .join("build/vmlinux");
                if exact.is_file() {
                    return Some(exact);
                }
            }
        }
    }
    let fallback = ctx.kernel_obj.join("vmlinux");
    if fallback.is_file() {
        return Some(fallback);
    }
    None
}

fn lookup_vmlinux_syms(ctx: &Ctx, vmlinux: &Path, wanted: &[&str]) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let nm = find_llvm_tool(ctx, "llvm-nm").unwrap_or_else(|| PathBuf::from("nm"));
    let nm_s = nm.to_string_lossy().into_owned();
    let vml_s = vmlinux.to_string_lossy().into_owned();
    let (rc, out, _) = run_cmd(&nm_s, &["-n", &vml_s], &ctx.ws_root, None);
    if rc != 0 {
        return map;
    }
    let want_set: BTreeSet<&str> = wanted.iter().copied().collect();
    for ln in out.lines() {
        let mut it = ln.split_whitespace();
        let Some(addr_s) = it.next() else { continue };
        let Some(_kind) = it.next() else { continue };
        let Some(name) = it.next() else { continue };
        if want_set.contains(name) {
            if let Ok(a) = u64::from_str_radix(addr_s, 16) {
                map.insert(name.to_string(), a);
            }
        }
    }
    map
}

fn symbolize_addrs(ctx: &Ctx, vmlinux: &Path, unslid: &[u64]) -> HashMap<u64, String> {
    let mut out_map = HashMap::new();
    if unslid.is_empty() {
        return out_map;
    }
    let Some(sym) = find_llvm_tool(ctx, "llvm-symbolizer") else {
        return out_map;
    };
    let sym_s = sym.to_string_lossy().into_owned();
    let vml_s = vmlinux.to_string_lossy().into_owned();
    let mut args = vec![
        "-e".to_string(),
        vml_s,
        "--no-inlines".to_string(),
        "-f".to_string(),
        "-s".to_string(),
    ];
    for &a in unslid {
        args.push(format!("0x{a:x}"));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (rc, out, _) = run_cmd(&sym_s, &arg_refs, &ctx.ws_root, None);
    if rc != 0 {
        return out_map;
    }
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    for (idx, &a) in unslid.iter().enumerate() {
        let fn_name = lines.get(idx * 2).copied().unwrap_or("?");
        let loc = lines.get(idx * 2 + 1).copied().unwrap_or("?");
        let desc = if loc == "??:0:0" || loc == "??:0" {
            fn_name.to_string()
        } else {
            format!("{fn_name} ({loc})")
        };
        out_map.insert(a, desc);
    }
    out_map
}

/// Extract runtime `_sdata` VA from `md_KELF_HDR.BIN` (PT_LOAD index 1 in QCOM minidump ELF header).
fn parse_kelf_sdata_va(kelf: &[u8]) -> Option<u64> {
    if kelf.len() < 64 || &kelf[0..4] != b"\x7fELF" || kelf[4] != 2 {
        return None;
    }
    let phoff = le_u64(kelf, 32) as usize;
    let phentsize = le_u16(kelf, 54) as usize;
    let phnum = le_u16(kelf, 56) as usize;
    if phentsize < 56 || phnum < 2 || phoff + 2 * phentsize > kelf.len() {
        return None;
    }
    let po = phoff + phentsize; // PT[1] = KDATABSS (_sdata)
    let p_type = le_u32(kelf, po);
    if p_type != 1 {
        return None;
    }
    Some(le_u64(kelf, po + 16))
}

fn decode_rst_stat(code: u32) -> &'static str {
    match code {
        0x0 => "COLD/NORMAL(0x0)",
        0x1 => "APPS_WDOG/SBL(0x1)",
        0x2 => "RPM/AOP_ERR(0x2)",
        0x3 => "TZ_SECURE_WDOG_BITE(0x3)",
        _ => "OTHER",
    }
}

// ====================================================== 9. Public Commands & Fast `crash-log` Summary Probe

#[derive(Debug, Clone, Default)]
pub struct RawDumpOpts {
    pub serial: Option<String>,
    pub file: Option<String>,
    pub save_dir: Option<String>,
    pub vmlinux: Option<String>,
    pub tail: usize,
    pub full: bool,
    pub list_sections: bool,
}

/// Fast `<1s` summary probe embedded into `kawal crash-log`: checks rawdump TOC, `md_HYP_DIAG.BIN`,
/// `md_RST_STAT.BIN`, and `md_PMON_HIS.BIN` without pulling multi-megabyte ringbuffers.
pub fn probe_rawdump_summary_for_crash_log(ctx: &Ctx, serial: &str) -> bool {
    let src = DumpSource::Adb {
        serial: serial.to_string(),
        device_path: "/dev/block/by-name/rawdump".to_string(),
    };
    let hdr_buf = match src.read_range(0, 16384) {
        Ok(b) if b.len() >= 0x98 => b,
        _ => {
            println!("  (no readable /dev/block/by-name/rawdump or permission denied)");
            return false;
        }
    };
    let toc = match parse_rawdump_toc(&hdr_buf) {
        Ok(t) => t,
        Err(e) => {
            println!("  clean/empty: {e}");
            return false;
        }
    };
    println!(
        "  header   : Raw_Dmp! v0x{:x} valid={} sections={} size={:.1} MiB",
        toc.header.version,
        toc.header.valid,
        toc.sections.len(),
        toc.header.dump_size as f64 / (1024.0 * 1024.0)
    );

    let mut found_fatal = false;
    if let Ok(rst) = src.read_section(&toc, "md_RST_STAT.BIN", Some(4))
        .or_else(|_| src.read_section(&toc, "MD_RST_STAT.BIN", Some(4)))
    {
        if rst.len() >= 4 {
            let code = le_u32(&rst, 0);
            println!("  rst_stat : 0x{code:08x} [{}]", decode_rst_stat(code));
            if code != 0 {
                found_fatal = true;
            }
        }
    }

    if let Ok(hyp) = src.read_section(&toc, "md_HYP_DIAG.BIN", None) {
        let lines = extract_ascii_runs(&hyp, 8);
        let mut smmu_hits = 0usize;
        for ln in &lines {
            if ln.contains("FATAL") || ln.contains("SMMU_ERR") || ln.contains("Abort:") || ln.contains("WDOG_TRIGGER") {
                found_fatal = true;
                println!("  [HYP!] {}", truncate_str(ln, 120));
                if let Some(d) = decode_smmu_fault_line(ln) {
                    smmu_hits += 1;
                    print_smmu_decoded("         ", &d);
                }
            }
        }
        if smmu_hits == 0 && !found_fatal {
            println!("  hyp_diag : {} lines (no FATAL/SMMU_ERR)", lines.len());
        }
    }

    if let Ok(pmon) = src.read_section(&toc, "md_PMON_HIS.BIN", None) {
        let entries = parse_pmic_pon_history(&pmon);
        let faults: Vec<&PmicPonEntry> = entries.iter().filter(|e| e.is_fault).collect();
        let imp: Vec<&PmicPonEntry> = entries.iter().filter(|e| e.is_important).collect();
        if faults.is_empty() {
            let last_rst = imp.iter().rev().take(3).map(|e| e.summary.as_str()).collect::<Vec<_>>().join(" | ");
            println!("  pmic_pon : 0 HW/thermal/UVLO faults; latest: {last_rst}");
        } else {
            found_fatal = true;
            println!("  pmic_pon : {} FAULT entries:", faults.len());
            for f in faults.iter().take(4) {
                println!("     [PMIC!] {}", f.summary);
            }
        }
    }

    println!("  hint     : run `kawal rawdump -s {serial} --save lab/device-backups/rawdump-latest` for full dmesg + pmsg + KGSL + vCPU decode");
    let _ = ctx;
    found_fatal
}

fn print_smmu_decoded(indent: &str, d: &SmmuFaultDecoded) {
    println!(
        "{indent}SMMU    : 0x{:08x} [{}] CB={}",
        d.smmu_base,
        d.smmu_name,
        d.cb.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
    );
    if let Some(fsr) = d.fsr {
        println!(
            "{indent}FSR     : 0x{fsr:08x} [Format={} | {}]",
            d.fsr_format.unwrap_or("?"),
            d.fsr_flags.join(" | ")
        );
    }
    if d.far.is_some() || d.ipafar.is_some() {
        println!(
            "{indent}ADDR    : FAR(VA)=0x{:012x}  IPAFAR=0x{:012x}  SID=0x{:04x}",
            d.far.unwrap_or(0),
            d.ipafar.unwrap_or(0),
            d.sid.unwrap_or(0)
        );
    }
    if !d.fsynr0_desc.is_empty() {
        println!("{indent}FSYNR0  : 0x{:08x} [{}]", d.fsynr0.unwrap_or(0), d.fsynr0_desc);
    }
    if !d.cbar_desc.is_empty() || !d.tcr_desc.is_empty() {
        println!(
            "{indent}STAGE   : CBAR=0x{:x} ({}) | TCR=0x{:08x} ({}) | TTBR0=0x{:x}",
            d.cbar.unwrap_or(0),
            d.cbar_desc,
            d.tcr.unwrap_or(0),
            d.tcr_desc,
            d.ttbr0.unwrap_or(0)
        );
    }
}

pub fn cmd_rawdump(ctx: &Ctx, opts: &RawDumpOpts) -> i32 {
    println!("========================================================================");
    println!("kawal rawdump: Qualcomm Minidump / HYP / SMMU / dmesg / pmsg / KGSL decoder");
    println!("========================================================================");

    let src = if let Some(ref fpath) = opts.file {
        println!("  source   : file {fpath}");
        DumpSource::File(PathBuf::from(fpath))
    } else {
        let dev = match device::select_adb_device(ctx, opts.serial.as_deref()) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("!! {e}");
                return 1;
            }
        };
        println!("  source   : adb {} (/dev/block/by-name/rawdump)", dev.serial);
        DumpSource::Adb {
            serial: dev.serial,
            device_path: "/dev/block/by-name/rawdump".to_string(),
        }
    };

    let hdr_buf = match src.read_range(0, 16384) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("!! failed to read rawdump header: {e}");
            return 1;
        }
    };
    let toc = match parse_rawdump_toc(&hdr_buf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    println!(
        "  header   : Raw_Dmp! v0x{:x} valid={} sections={} dump_size={:.1} MiB",
        toc.header.version,
        toc.header.valid,
        toc.sections.len(),
        toc.header.dump_size as f64 / (1024.0 * 1024.0)
    );

    if opts.list_sections {
        println!("\n[TOC] {} sections:", toc.sections.len());
        for s in toc.sections.values() {
            println!(
                "  {:<22} off=0x{:08x} size={:10} (0x{:08x}) va=0x{:016x}",
                s.name, s.offset, s.size, s.size, s.vaddr
            );
        }
    }

    let save_dir = opts.save_dir.as_ref().map(PathBuf::from);
    if let Some(ref sd) = save_dir {
        if let Err(e) = fs::create_dir_all(sd) {
            eprintln!("!! could not create save dir `{}`: {e}", sd.display());
            return 1;
        }
    }
    let mut summary_lines: Vec<String> = Vec::new();
    let tail_n = if opts.tail == 0 { 25 } else { opts.tail };

    // ---------------- [1/6] Gunyah EL2 Hypervisor + SMMU + RST_STAT + XBL ----------------
    println!("\n[1/6] Gunyah EL2 Hypervisor & Hardware Reset Status (md_HYP_DIAG / md_RST_STAT / md_XBL_LOG):");
    if let Ok(rst) = src.read_section(&toc, "md_RST_STAT.BIN", Some(4))
        .or_else(|_| src.read_section(&toc, "MD_RST_STAT.BIN", Some(4)))
    {
        if rst.len() >= 4 {
            let code = le_u32(&rst, 0);
            let s = format!("  rst_stat : 0x{code:08x} [{}]", decode_rst_stat(code));
            println!("{s}");
            summary_lines.push(s);
        }
    }
    if let Ok(hyp) = src.read_section(&toc, "md_HYP_DIAG.BIN", None) {
        let lines = extract_ascii_runs(&hyp, 8);
        if let Some(ref sd) = save_dir {
            let _ = fs::write(sd.join("hyp_diag.txt"), lines.join("\n") + "\n");
        }
        let mut fatals = Vec::new();
        for ln in &lines {
            if ln.contains("SMMU_ERR")
                || ln.contains("FATAL")
                || ln.contains("Abort:")
                || ln.contains("WDOG_TRIGGER")
                || ln.contains("PANIC")
                || ln.contains("Exception")
            {
                fatals.push(ln.clone());
            }
        }
        if fatals.is_empty() {
            println!("  hyp_diag : {} lines (no FATAL/SMMU_ERR hits)", lines.len());
            for ln in lines.iter().rev().take(4).rev() {
                println!("    {ln}");
            }
        } else {
            println!("  hyp_diag : {} FATAL/ERROR line(s) (of {} total):", fatals.len(), lines.len());
            for ln in &fatals {
                println!("    [!] {ln}");
                summary_lines.push(format!("[HYP!] {ln}"));
                if let Some(d) = decode_smmu_fault_line(ln) {
                    print_smmu_decoded("        ", &d);
                }
            }
        }
    } else {
        println!("  hyp_diag : (not present)");
    }
    if let Ok(xbl) = src.read_section(&toc, "md_XBL_LOG.BIN", None) {
        let lines = extract_ascii_runs(&xbl, 8);
        for ln in &lines {
            if ln.contains("TCSR") || ln.contains("dload") || ln.contains("DLOAD") || ln.contains("reset") || ln.contains("Reset") {
                println!("  xbl_log  : {}", truncate_str(ln, 115));
            }
        }
    }

    // ---------------- [2/6] PMIC PON / Reset History ----------------
    println!("\n[2/6] PMIC PON / Power & Thermal Fault History (md_PMON_HIS.BIN):");
    if let Ok(pmon) = src.read_section(&toc, "md_PMON_HIS.BIN", None) {
        let entries = parse_pmic_pon_history(&pmon);
        let faults: Vec<&PmicPonEntry> = entries.iter().filter(|e| e.is_fault).collect();
        let imp: Vec<&PmicPonEntry> = entries.iter().filter(|e| e.is_important).collect();
        println!(
            "  entries  : {} total | {} important | {} HW/PMIC faults",
            entries.len(),
            imp.len(),
            faults.len()
        );
        if faults.is_empty() {
            println!("  verdict  : CLEAN (0 PMIC UVLO/OVLO/overtemp/watchdog faults)");
        } else {
            for f in &faults {
                println!("  [PMIC!] {}", f.summary);
            }
        }
        let show_entries: Vec<&PmicPonEntry> = if opts.full {
            entries.iter().collect()
        } else {
            imp.iter().copied().skip(imp.len().saturating_sub(10)).collect()
        };
        for e in show_entries {
            println!("    {}", e.summary);
        }
    } else {
        println!("  (md_PMON_HIS.BIN not present)");
    }

    // ---------------- [3/6] Linux 6.12 printk_ringbuffer (dmesg) ----------------
    println!("\n[3/6] Kernel Log Ringbuffer (md_KLOGBUF + md_LOG_DESC + md_LOG_INFO):");
    let mut kernel_banner: Option<String> = None;
    let mut last_klog_ns: u64 = 0;
    if let (Ok(klog), Ok(ldesc), Ok(linfo)) = (
        src.read_section(&toc, "md_KLOGBUF.BIN", None),
        src.read_section(&toc, "md_LOG_DESC.BIN", None),
        src.read_section(&toc, "md_LOG_INFO.BIN", None),
    ) {
        let recs = decode_printk_ringbuffer(&klog, &ldesc, &linfo);
        if let Some(last) = recs.last() {
            last_klog_ns = last.ts_nsec;
        }
        if let Some(ref sd) = save_dir {
            let mut full_dmesg = String::with_capacity(recs.len() * 80);
            for r in &recs {
                full_dmesg.push_str(&r.format_line());
                full_dmesg.push('\n');
            }
            let _ = fs::write(sd.join("dmesg.log"), &full_dmesg);
        }
        let mut boot_idx = None;
        let mut pureason = None;
        let mut crit_hits = Vec::new();
        for r in &recs {
            if kernel_banner.is_none() && r.text.starts_with("Linux version ") {
                kernel_banner = Some(r.text.clone());
            }
            if boot_idx.is_none() {
                if let Some(p) = r.text.find("mtdoops.boot_index=") {
                    boot_idx = r.text[p + 19..].split_whitespace().next().map(str::to_string);
                }
            }
            if pureason.is_none() {
                if let Some(p) = r.text.find("bootinfo.pureason=") {
                    pureason = r.text[p + 18..].split_whitespace().next().map(str::to_string);
                }
            }
            let t = r.text.as_str();
            if t.contains("Kernel panic")
                || t.contains("BUG:")
                || t.contains("Oops:")
                || t.contains("Internal error:")
                || t.contains("Unable to handle kernel")
                || t.contains("WARNING: CPU:")
                || t.contains("Call trace:")
                || t.contains("RBBM: GPC")
                || t.contains("GPU PAGE FAULT")
                || t.contains("Unhandled context fault")
                || t.contains("Out of memory:")
            {
                crit_hits.push(r.format_line());
            }
        }
        println!(
            "  records  : {} decoded | last_ts={:.3}s | boot_index={} pureason={}",
            recs.len(),
            last_klog_ns as f64 / 1e9,
            boot_idx.as_deref().unwrap_or("?"),
            pureason.as_deref().unwrap_or("?")
        );
        if let Some(ref b) = kernel_banner {
            println!("  banner   : {}", truncate_str(b, 110));
        }
        if crit_hits.is_empty() {
            println!("  panic    : NONE (0 kernel panic/BUG/Oops/GPU fault lines in dmesg)");
        } else {
            println!("  panic/err: {} critical line(s):", crit_hits.len());
            for c in crit_hits.iter().take(if opts.full { 80 } else { 15 }) {
                println!("    [!] {}", truncate_str(c, 120));
            }
        }
        println!("  tail (last {} of {}):", tail_n.min(recs.len()), recs.len());
        let start = recs.len().saturating_sub(tail_n);
        for r in &recs[start..] {
            println!("    {}", truncate_str(&r.format_line(), 120));
        }
    } else {
        println!("  (dmesg ringbuffer sections not present)");
    }

    // ---------------- [4/6] Kernel State, KASLR, Watchdog & vCPU Contexts ----------------
    println!("\n[4/6] Kernel State, KASLR, Watchdog & vCPU Contexts (md_KELF_HDR / md_KDATABSS / md_KWDOGDATA / md_dump_vms4):");
    let vmlinux = find_matching_vmlinux(ctx, kernel_banner.as_deref(), opts.vmlinux.as_deref());
    let mut kaslr_slide: Option<u64> = None;
    let mut sdata_runtime_va: Option<u64> = None;

    if let Ok(kelf) = src.read_section(&toc, "md_KELF_HDR.BIN", None) {
        sdata_runtime_va = parse_kelf_sdata_va(&kelf);
    }

    if let (Some(vml), Some(sdata_va)) = (&vmlinux, sdata_runtime_va) {
        let syms = lookup_vmlinux_syms(
            ctx,
            vml,
            &["_sdata", "panic_cpu", "oops_in_progress", "system_state", "tainted_mask"],
        );
        if let Some(&sdata_static) = syms.get("_sdata") {
            let slide = sdata_va.wrapping_sub(sdata_static);
            kaslr_slide = Some(slide);
            println!("  vmlinux  : {}", vml.display());
            println!("  KASLR    : _sdata=0x{sdata_va:016x} (slide=0x{slide:x})");
            if let Ok(kbss) = src.read_section(&toc, "md_KDATABSS.BIN", None) {
                let read_sym_i32 = |name: &str| -> Option<i32> {
                    let a = *syms.get(name)?;
                    let off = a.checked_sub(sdata_static)? as usize;
                    if off + 4 <= kbss.len() {
                        Some(le_i32(&kbss, off))
                    } else {
                        None
                    }
                };
                let read_sym_u64 = |name: &str| -> Option<u64> {
                    let a = *syms.get(name)?;
                    let off = a.checked_sub(sdata_static)? as usize;
                    if off + 8 <= kbss.len() {
                        Some(le_u64(&kbss, off))
                    } else {
                        None
                    }
                };
                let panic_cpu = read_sym_i32("panic_cpu");
                let oops = read_sym_i32("oops_in_progress");
                let sys_st = read_sym_i32("system_state");
                let taint = read_sym_u64("tainted_mask");
                let st_name = match sys_st {
                    Some(0) => "BOOTING",
                    Some(1) => "SCHEDULING",
                    Some(2) => "FREEING_INITMEM",
                    Some(3) => "RUNNING",
                    Some(4) => "HALT",
                    Some(5) => "POWER_OFF",
                    Some(6) => "RESTART",
                    Some(7) => "SUSPEND",
                    _ => "?",
                };
                println!(
                    "  kstate   : panic_cpu={} oops_in_progress={} system_state={}({}) tainted=0x{:x}",
                    panic_cpu.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                    oops.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                    sys_st.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                    st_name,
                    taint.unwrap_or(0)
                );
            }
        }
    } else {
        println!(
            "  vmlinux  : {} (sdata_va={})",
            vmlinux.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "not found (pass --vmlinux)".into()),
            sdata_runtime_va.map(|v| format!("0x{v:016x}")).unwrap_or_else(|| "?".into())
        );
    }

    if let Ok(wd) = src.read_section(&toc, "md_KWDOGDATA.BIN", Some(128)) {
        if wd.len() >= 0x30 {
            let bark_ms = le_u32(&wd, 0x18);
            let bite_ms = le_u32(&wd, 0x1c);
            let last_pet_ns = le_u64(&wd, 0x28);
            println!(
                "  watchdog : bark={}ms bite={}ms last_pet={:.3}s (klog_tail={:.3}s)",
                bark_ms,
                bite_ms,
                last_pet_ns as f64 / 1e9,
                last_klog_ns as f64 / 1e9
            );
        }
    }

    // Parse module base map from md_KMODULES.BIN + symbolize md_dump_vms4.BIN
    let mut mod_bases: Vec<(u64, String)> = Vec::new();
    if let Ok(kmod) = src.read_section(&toc, "md_KMODULES.BIN", None) {
        let txt = String::from_utf8_lossy(&kmod);
        for ln in txt.lines() {
            if let Some(rest) = ln.strip_prefix("name: ") {
                let mut parts = rest.split(", base: ");
                if let (Some(name), Some(after)) = (parts.next(), parts.next()) {
                    if let Some(hex_s) = after.split(',').next() {
                        if let Ok(base) = u64::from_str_radix(hex_s.trim(), 16) {
                            mod_bases.push((base, name.trim().to_string()));
                        }
                    }
                }
            }
        }
        mod_bases.sort_by_key(|(b, _)| *b);
    }

    if let Ok(vms) = src.read_section(&toc, "md_dump_vms4.BIN", None) {
        let needle = b"2HDBvm_3_vcpu_";
        let mut offsets = Vec::new();
        for pos in 0..vms.len().saturating_sub(needle.len()) {
            if &vms[pos..pos + needle.len()] == needle {
                offsets.push(pos);
            }
        }
        if !offsets.is_empty() {
            let mut per_vcpu: Vec<(String, Vec<u64>)> = Vec::new();
            let mut kern_unslid: BTreeSet<u64> = BTreeSet::new();
            let ktext_lo = sdata_runtime_va.map(|s| s.saturating_sub(0x0400_0000)).unwrap_or(0xffff_ffec_2c00_0000);
            let ktext_hi = sdata_runtime_va.map(|s| s.saturating_add(0x0200_0000)).unwrap_or(0xffff_ffec_3200_0000);
            let mod_lo = ktext_lo.saturating_sub(0x0600_0000);

            for (idx, &start) in offsets.iter().enumerate() {
                let end = offsets.get(idx + 1).copied().unwrap_or(vms.len());
                let name_slice = &vms[start..(start + 24).min(end)];
                let nul = name_slice.iter().position(|&b| b == 0).unwrap_or(name_slice.len());
                let vname = String::from_utf8_lossy(&name_slice[..nul]).to_string();
                let a_start = (start + 7) & !7;
                let mut addrs = Vec::new();
                let mut o = a_start;
                while o + 8 <= end {
                    let v = le_u64(&vms, o);
                    if v >= mod_lo && v <= ktext_hi {
                        addrs.push(v);
                        if v >= ktext_lo {
                            if let Some(sl) = kaslr_slide {
                                kern_unslid.insert(v.wrapping_sub(sl));
                            }
                        }
                    }
                    o += 8;
                }
                per_vcpu.push((vname, addrs));
            }

            let sym_map = match (&vmlinux, kaslr_slide) {
                (Some(vml), Some(_)) => {
                    let list: Vec<u64> = kern_unslid.into_iter().collect();
                    symbolize_addrs(ctx, vml, &list)
                }
                _ => HashMap::new(),
            };

            println!("  vCPUs    : {} captured in md_dump_vms4.BIN:", per_vcpu.len());
            for (vname, addrs) in &per_vcpu {
                let mut labels: Vec<String> = Vec::new();
                for &v in addrs {
                    let lbl = if let Some(sl) = kaslr_slide {
                        let u = v.wrapping_sub(sl);
                        if let Some(s) = sym_map.get(&u) {
                            s.clone()
                        } else if let Some(m) = mod_bases.iter().rev().find(|(b, _)| *b <= v && v - *b < 0x100_0000) {
                            format!("[{}+0x{:x}]", m.1, v - m.0)
                        } else {
                            continue;
                        }
                    } else {
                        format!("0x{v:016x}")
                    };
                    if !labels.contains(&lbl) && !lbl.starts_with("vectors") && !lbl.starts_with("ld-temp") {
                        labels.push(lbl);
                    }
                }
                let state = if labels.is_empty() {
                    "EL0 userspace (no kernel frames)".to_string()
                } else if labels.iter().any(|l| l.contains("cpu_do_idle") || l.contains("psci_enter_idle")) {
                    format!("IDLE ({})", labels.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
                } else {
                    labels.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
                };
                println!("    {vname:<18} -> {state}");
            }
        }
    }

    // ---------------- [5/6] Android `pmsg` Logcat (`md_KPMSG.BIN`) ----------------
    println!("\n[5/6] Android PMSG Logcat Ringbuffer (md_KPMSG.BIN):");
    if let Ok(kpmsg) = src.read_section(&toc, "md_KPMSG.BIN", None) {
        let recs = decode_kpmsg(&kpmsg);
        if let Some(ref sd) = save_dir {
            let mut full_pmsg = String::with_capacity(recs.len() * 96);
            for r in &recs {
                full_pmsg.push_str(&r.format_line());
                full_pmsg.push('\n');
            }
            let _ = fs::write(sd.join("pmsg.log"), &full_pmsg);
        }
        let filtered: Vec<&PmsgRecord> = recs
            .iter()
            .filter(|r| {
                opts.full
                    || (!r.tag.starts_with("QTI-Thermal")
                        && !r.tag.contains("Health")
                        && !r.tag.starts_with("Wifi")
                        && !r.tag.starts_with("wpa_supplicant"))
            })
            .collect();
        println!("  records  : {} total ({} after noise filter)", recs.len(), filtered.len());
        let interesting: Vec<&PmsgRecord> = filtered
            .iter()
            .copied()
            .filter(|r| {
                r.prio >= 6
                    || r.tag.contains("framefx")
                    || r.tag.contains("DEBUG")
                    || r.tag.contains("ActivityTaskManager")
                    || r.msg.contains("Fatal")
                    || r.msg.contains("luwes")
                    || r.msg.contains("SGSR")
                    || r.msg.contains("SIGSEGV")
                    || r.msg.contains("VK_ERROR")
            })
            .collect();
        if !interesting.is_empty() {
            let take_n = if opts.full { 40 } else { 15 };
            let st = interesting.len().saturating_sub(take_n);
            println!("  key hits (last {} of {}):", interesting.len() - st, interesting.len());
            for r in &interesting[st..] {
                println!("    {}", truncate_str(&r.format_line(), 120));
            }
        }
        let st = filtered.len().saturating_sub(12);
        println!("  tail (last {}):", filtered.len() - st);
        for r in &filtered[st..] {
            println!("    {}", truncate_str(&r.format_line(), 120));
        }
    } else {
        println!("  (md_KPMSG.BIN not present)");
    }

    // ---------------- [6/6] Adreno KGSL Eventlog (`md_KGSL_EVENTLO.BIN`) ----------------
    println!("\n[6/6] Adreno KGSL GPU Eventlog (md_KGSL_EVENTLO.BIN):");
    if let Ok(kgsl) = src.read_section(&toc, "md_KGSL_EVENTLO.BIN", None) {
        let (events, ctx_state) = decode_kgsl_eventlog(&kgsl);
        if let Some(ref sd) = save_dir {
            let mut txt = String::with_capacity(events.len() * 72);
            for e in &events {
                txt.push_str(&format!(
                    "[{:10.6}] pid={:5} {:<16} {}\n",
                    e.time_ns as f64 / 1e9,
                    e.pid,
                    e.name,
                    e.detail
                ));
            }
            let _ = fs::write(sd.join("kgsl_eventlog.txt"), &txt);
        }
        let inflight: Vec<(u32, u32, u32, i32)> = ctx_state
            .iter()
            .filter(|(_, (sub, ret, _))| *sub > *ret)
            .map(|(&cid, &(sub, ret, pid))| (cid, sub, ret, pid))
            .collect();
        println!(
            "  events   : {} decoded | last_ts={:.6}s | in-flight GPU contexts={}",
            events.len(),
            events.last().map(|e| e.time_ns as f64 / 1e9).unwrap_or(0.0),
            inflight.len()
        );
        for (cid, sub, ret, pid) in &inflight {
            println!("  [IN-FLIGHT] ctx={cid} pid={pid} submitted_ts={sub} retired_ts={ret} (pending={})", sub - ret);
        }
        let show = if opts.full { 35 } else { 12 };
        let st = events.len().saturating_sub(show);
        for e in &events[st..] {
            println!(
                "    [{:10.6}] pid={:5} {:<16} {}",
                e.time_ns as f64 / 1e9,
                e.pid,
                e.name,
                e.detail
            );
        }
    } else {
        println!("  (md_KGSL_EVENTLO.BIN not present)");
    }

    if let Some(ref sd) = save_dir {
        let _ = fs::write(sd.join("summary.txt"), summary_lines.join("\n") + "\n");
        println!("\nSaved decoded logs to: {}", sd.display());
    }
    0
}

// ====================================================== Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rawdump_toc_v2() {
        let mut buf = vec![0u8; 512];
        buf[0..8].copy_from_slice(b"Raw_Dmp!");
        buf[8..12].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[12..16].copy_from_slice(&1u32.to_le_bytes());
        buf[36..44].copy_from_slice(&0x9540664u64.to_le_bytes());
        buf[44..52].copy_from_slice(&0x12c00000u64.to_le_bytes());
        buf[52..56].copy_from_slice(&2u32.to_le_bytes());

        // Entry 0 at 0x58
        let o0 = 0x58;
        buf[o0..o0 + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[o0 + 4..o0 + 8].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[o0 + 8..o0 + 12].copy_from_slice(&3u32.to_le_bytes());
        buf[o0 + 12..o0 + 20].copy_from_slice(&0x024e2d18u64.to_le_bytes());
        buf[o0 + 20..o0 + 28].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[o0 + 28..o0 + 36].copy_from_slice(&0x80289000u64.to_le_bytes());
        buf[o0 + 0x2c..o0 + 0x2c + 15].copy_from_slice(b"md_HYP_DIAG.BIN");

        // Entry 1 at 0x98
        let o1 = 0x98;
        buf[o1..o1 + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[o1 + 4..o1 + 8].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[o1 + 8..o1 + 12].copy_from_slice(&3u32.to_le_bytes());
        buf[o1 + 12..o1 + 20].copy_from_slice(&0x094f8e1cu64.to_le_bytes());
        buf[o1 + 20..o1 + 28].copy_from_slice(&264u64.to_le_bytes());
        buf[o1 + 0x2c..o1 + 0x2c + 15].copy_from_slice(b"md_PMON_HIS.BIN");

        let toc = parse_rawdump_toc(&buf).unwrap();
        assert_eq!(toc.header.version, 0x2000);
        assert_eq!(toc.header.sec_count, 2);
        let hyp = toc.sections.get("md_HYP_DIAG.BIN").unwrap();
        assert_eq!(hyp.offset, 0x024e2d18);
        assert_eq!(hyp.size, 0x2000);
        assert!(toc.sections.contains_key("md_PMON_HIS.BIN"));
    }

    #[test]
    fn test_decode_smmu_fault_line_sm8735() {
        let ln = "0 768.889479 SMMU_ERR_FATAL SMMU:>> 0x03da0000 CB: 24 Fault: FSR=0x40000480, FAR=0x      402651c000, IPAFAR=0x       a515cd000, FSYNR0=0x00000016, FSYNR1=0xffffe01b00000004, CBFRSYNRA=0x10c0020000000000, CR0=0x00e00406,  NSCR0=0xffffffec00000000, CBAR=0xffffffec00000003, CBA2R=0xffffffec00000001, SCTLR=0x00cf00e1, TCR=0x0001355c, TTBR0=0x8b9f00000, TTBR1=0x00000000";
        let d = decode_smmu_fault_line(ln).unwrap();
        assert_eq!(d.smmu_base, 0x03da_0000);
        assert_eq!(d.smmu_name, "kgsl-smmu (Adreno GPU)");
        assert_eq!(d.cb, Some(24));
        assert_eq!(d.fsr, Some(0x4000_0480));
        assert_eq!(d.fsr_format, Some("AArch64"));
        assert!(d.fsr_flags.contains(&"SS(Stalled)"));
        assert!(d.fsr_flags.contains(&"ASF(AddressSizeFault)"));
        assert_eq!(d.far, Some(0x40_2651_c000));
        assert_eq!(d.ipafar, Some(0xa_515c_d000));
        assert!(d.fsynr0_desc.contains("WRITE"));
        assert!(d.fsynr0_desc.contains("PLVL=2"));
        assert!(d.fsynr0_desc.contains("S2"));
        assert!(d.fsynr0_desc.contains("gfx3d_user"));
        assert!(d.cbar_desc.contains("Stage-2"));
        assert!(d.cbar_desc.contains("VMID=3"));
        assert!(d.tcr_desc.contains("IPA=36b"));
        assert!(d.tcr_desc.contains("PA=36b"));
        assert_eq!(d.sid, Some(0));
    }

    #[test]
    fn test_parse_pmic_pon_history() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PLOG");
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&[0x04, 0x07, 0x00, 0x07]); // RESET HARD_RESET
        buf.extend_from_slice(&[0x04, 0x06, 0x00, 0x84]); // RESET PS_HOLD
        buf.extend_from_slice(&[0x05, 0x01, 0x71, 0xC2]); // OFF USB_CHARGER
        buf.extend_from_slice(&[0x00, 0x09, 0x80, 0x40]); // FAULT UVLO + OVERTEMP_STAGE3
        let entries = parse_pmic_pon_history(&buf);
        assert_eq!(entries.len(), 4);
        assert!(!entries[0].is_fault && entries[0].summary.contains("HARD_RESET"));
        assert!(!entries[1].is_fault && entries[1].summary.contains("PS_HOLD"));
        assert!(!entries[2].is_fault && entries[2].summary.contains("USB_CHARGER"));
        assert!(entries[3].is_fault && entries[3].summary.contains("UVLO") && entries[3].summary.contains("OVERTEMP_STAGE3"));
    }

    #[test]
    fn test_decode_printk_ringbuffer() {
        let mut klog = vec![0u8; 4096];
        let mut ldesc = vec![0u8; 24 * 2];
        let mut linfo = vec![0u8; 88 * 2];

        // Record 0: seq=10, ts=1.5s, id=42, text="hello kernel"
        let id0 = 42u64;
        let sv0 = (2u64 << 62) | id0; // desc_finalized
        ldesc[0..8].copy_from_slice(&sv0.to_le_bytes());
        ldesc[8..16].copy_from_slice(&0u64.to_le_bytes());
        ldesc[16..24].copy_from_slice(&32u64.to_le_bytes());

        linfo[0..8].copy_from_slice(&10u64.to_le_bytes());
        linfo[8..16].copy_from_slice(&1_500_000_000u64.to_le_bytes());
        linfo[16..18].copy_from_slice(&12u16.to_le_bytes());
        linfo[19] = 6 << 5; // level=6

        klog[0..8].copy_from_slice(&id0.to_le_bytes());
        klog[8..20].copy_from_slice(b"hello kernel");

        let recs = decode_printk_ringbuffer(&klog, &ldesc, &linfo);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].seq, 10);
        assert_eq!(recs[0].level, 6);
        assert_eq!(recs[0].text, "hello kernel");
        assert!(recs[0].format_line().contains("[    1.500000] hello kernel"));
    }

    #[test]
    fn test_decode_kpmsg_and_kgsl_eventlog() {
        // Build 1 pmsg record
        let body = b"\x04framefx\x00luwes: SGSR 2\x00";
        let plen = (18 + body.len()) as u16;
        let mut pbuf = Vec::new();
        pbuf.push(0x6c);
        pbuf.extend_from_slice(&plen.to_le_bytes());
        pbuf.extend_from_slice(&10194u16.to_le_bytes());
        pbuf.extend_from_slice(&12040u16.to_le_bytes());
        pbuf.push(0u8); // main
        pbuf.extend_from_slice(&12296u16.to_le_bytes());
        pbuf.extend_from_slice(&1_795_511_143u32.to_le_bytes());
        pbuf.extend_from_slice(&245_000_000u32.to_le_bytes());
        pbuf.extend_from_slice(body);

        let precs = decode_kpmsg(&pbuf);
        assert_eq!(precs.len(), 1);
        assert_eq!(precs[0].tag, "framefx");
        assert_eq!(precs[0].msg, "luwes: SGSR 2");

        // Build 2 KGSL events (submit ts=10, retire ts=9 -> 1 in-flight!)
        let mut kbuf = Vec::new();
        kbuf.extend_from_slice(&0xabba_abbau32.to_le_bytes());
        kbuf.extend_from_slice(&12296i32.to_le_bytes());
        kbuf.extend_from_slice(&763_000_000_000u64.to_le_bytes());
        kbuf.extend_from_slice(&3u32.to_le_bytes()); // CMDBATCH_SUBMIT
        kbuf.extend_from_slice(&24u32.to_le_bytes());
        kbuf.extend_from_slice(&28u32.to_le_bytes()); // ctx=28
        kbuf.extend_from_slice(&10u32.to_le_bytes()); // ts=10
        kbuf.extend_from_slice(&8u32.to_le_bytes());  // prio
        kbuf.extend_from_slice(&0u32.to_le_bytes());
        kbuf.extend_from_slice(&8u64.to_le_bytes());  // flags

        let (evs, ctxs) = decode_kgsl_eventlog(&kbuf);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].name, "CMDBATCH_SUBMIT");
        assert_eq!(ctxs.get(&28), Some(&(10, 0, 12296)));
    }
}
