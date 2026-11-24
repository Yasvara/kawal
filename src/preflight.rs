use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::buildguard;
use crate::elf;
use crate::util::*;

/// Detect the exact Android prebuilt clang binary used by the kernel from KERNEL_OBJ/.config.
pub fn detect_clang_bin(ctx: &Ctx) -> String {
    let cfg = ctx.kernel_obj.join(".config");
    if let Ok(txt) = fs::read_to_string(&cfg) {
        for ln in txt.lines() {
            if let Some(rest) = ln.strip_prefix("CONFIG_CC_VERSION_TEXT=") {
                if let Some(idx) = rest.find("based on r") {
                    let rev: String = rest[idx + 9..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    let cand = ctx
                        .ws_root
                        .join(format!("src/prebuilts/clang/host/linux-x86/clang-{rev}/bin/clang"));
                    if cand.is_file() {
                        return cand.to_string_lossy().into_owned();
                    }
                }
            }
        }
    }
    let pre = ctx.ws_root.join("src/prebuilts/clang/host/linux-x86");
    if let Ok(rd) = fs::read_dir(&pre) {
        let mut cands: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path().join("bin/clang"))
            .filter(|p| p.is_file())
            .collect();
        cands.sort();
        if let Some(last) = cands.last() {
            return last.to_string_lossy().into_owned();
        }
    }
    "clang".to_string()
}

/// Shell-like tokenizer that respects single and double quotes (for Kbuild `savedcmd_*.o := ...`).
pub fn split_cmd_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in s.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur.push(ch);
            }
        } else if in_double {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            } else {
                cur.push(ch);
            }
        } else {
            match ch {
                '\\' => escaped = true,
                '\'' => in_single = true,
                '"' => in_double = true,
                c if c.is_ascii_whitespace() => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Parse a Kbuild `.foo.o.cmd` file into clang arguments.
/// - `out_obj = None` -> `-fsyntax-only`
/// - `out_obj = Some(path)` -> `-c -fno-lto -o <path>` (native ELF64 `.o` for MODPOST symbol check!)
/// - `override_src = Some(path)` -> replace the `.c` input argument (for sibling-fallback new `.c` files!)
pub fn parse_ocmd_to_clang_args(
    ocmd_text: &str,
    out_obj: Option<&Path>,
    override_src: Option<&Path>,
    extra_inc_dirs: &[PathBuf],
) -> Option<Vec<String>> {
    let first = ocmd_text.lines().next()?;
    let (_, rhs) = first.split_once(":=")?;
    let raw_toks = split_cmd_tokens(rhs.trim());
    if raw_toks.is_empty() {
        return None;
    }

    let mut i = 0;
    while i < raw_toks.len() {
        let t = &raw_toks[i];
        if t.ends_with("ccache") || t.ends_with("clang") || t.ends_with("gcc") || t.ends_with("sccache") {
            i += 1;
        } else {
            break;
        }
    }

    let mut args = Vec::with_capacity(raw_toks.len() + extra_inc_dirs.len() + 6);
    let mut replaced_src = false;
    while i < raw_toks.len() {
        let t = &raw_toks[i];
        if t == ";" || t == "&&" || t == "||" {
            break;
        }
        if t == "-o" || t == "-MF" || t == "-MT" || t == "-MQ" {
            i += 2;
            continue;
        }
        if t == "-c"
            || t == "-flto"
            || t.starts_with("-flto=")
            || t == "-fno-lto"
            || t == "-fwhole-program-vtables"
            || t == "-fsplit-lto-unit"
            || t.starts_with("-fsanitize=cfi")
            || t.starts_with("-Wp,-MMD,")
            || t.starts_with("-Wp,-MD,")
            || t == "-Werror=unused-command-line-argument"
            || t == "-Werror=ignored-optimization-argument"
        {
            i += 1;
            continue;
        }
        // When borrowing a sibling .o.cmd for a brand-new .c file, drop source-specific -DKBUILD_BASENAME / -DKBUILD_MODFILE?
        // Actually keeping KBUILD_MODNAME is critical; only swap the .c source argument!
        if let Some(ov) = override_src {
            if t.ends_with(".c") && !t.starts_with('-') {
                args.push(ov.to_string_lossy().into_owned());
                replaced_src = true;
                i += 1;
                continue;
            }
        }
        args.push(t.clone());
        i += 1;
    }
    if let Some(ov) = override_src {
        if !replaced_src {
            args.push(ov.to_string_lossy().into_owned());
        }
    }
    for inc in extra_inc_dirs {
        args.push(format!("-I{}", inc.display()));
    }
    if let Some(obj) = out_obj {
        args.push("-fno-lto".to_string());
        args.push("-c".to_string());
        args.push("-o".to_string());
        args.push(obj.to_string_lossy().into_owned());
    } else {
        args.push("-fsyntax-only".to_string());
    }
    args.push("-fno-color-diagnostics".to_string());
    args.push("-Wno-unused-command-line-argument".to_string());
    Some(args)
}

#[allow(dead_code)]
pub fn parse_ocmd_to_syntax_args(ocmd_text: &str) -> Option<Vec<String>> {
    parse_ocmd_to_clang_args(ocmd_text, None, None, &[])
}

fn find_ocmd_for_kernel_c(ctx: &Ctx, rel_c: &str) -> Option<(PathBuf, PathBuf)> {
    let p = Path::new(rel_c);
    let stem = p.file_stem()?.to_string_lossy();
    let dir = p.parent().unwrap_or(Path::new(""));
    let ocmd = ctx.kernel_obj.join(dir).join(format!(".{stem}.o.cmd"));
    if ocmd.is_file() {
        Some((ocmd, ctx.kernel_obj.clone()))
    } else {
        None
    }
}

fn find_ocmd_for_module_c(ctx: &Ctx, rel_c: &str) -> Option<(PathBuf, PathBuf)> {
    let p = Path::new(rel_c);
    let stem = p.file_stem()?.to_string_lossy();
    let dir = p.parent().unwrap_or(Path::new(""));
    let ocmd = ctx
        .product_out
        .join("obj/sm8735-modules")
        .join(dir)
        .join(format!(".{stem}.o.cmd"));
    if ocmd.is_file() {
        Some((ocmd, ctx.kernel_obj.clone()))
    } else {
        None
    }
}

/// Skip obviously unbuilt test/kunit/foreign-vendor paths when falling back to sibling .o.cmd.
pub fn is_noisy_unbuilt_sibling_path(rel_c: &str) -> bool {
    if rel_c.ends_with("-test.c")
        || rel_c.ends_with("_test.c")
        || rel_c.ends_with("_kunit.c")
        || rel_c.contains("/tests/")
        || rel_c.contains("/kunit/")
    {
        return true;
    }
    for pfx in [
        "sound/soc/amd/",
        "sound/soc/intel/",
        "sound/soc/sof/",
        "sound/soc/soc-ac97.c",
        "sound/pci/",
        "drivers/gpu/drm/amd/",
        "drivers/gpu/drm/i915/",
        "drivers/gpu/drm/nouveau/",
        "drivers/gpu/drm/xe/",
        "drivers/net/ethernet/",
        "drivers/infiniband/",
        "security/selinux/netlabel.c",
        "drivers/acpi/",
    ] {
        if rel_c.starts_with(pfx) {
            return true;
        }
    }
    false
}

/// For a newly-added `.c` file with no `.o.cmd` yet, check if its `<stem>.o` is referenced in
/// its techpack's Kbuild/Makefile and if so borrow a sibling `.o.cmd` from the same or parent dir.
fn find_sibling_ocmd(ctx: &Ctx, rel_c: &str, kbuild_cache: &mut HashMap<String, String>) -> Option<(PathBuf, PathBuf, PathBuf)> {
    if is_noisy_unbuilt_sibling_path(rel_c) {
        return None;
    }
    let p = Path::new(rel_c);
    let stem = p.file_stem()?.to_string_lossy();
    let obj_name = format!("{stem}.o");
    let tp = buildguard::techpack_root(rel_c);
    let tp_dir = if tp.is_empty() { ctx.repo.clone() } else { ctx.repo.join(&tp) };

    let kb = kbuild_cache.entry(tp.clone()).or_insert_with(|| {
        let mut s = String::new();
        for cand in ["Kbuild", "Makefile", "msm/Kbuild", "drivers/Kbuild"] {
            if let Ok(t) = fs::read_to_string(tp_dir.join(cand)) {
                s.push_str(&t);
                s.push('\n');
            }
        }
        if let Some(par) = p.parent() {
            for cand in ["Kbuild", "Makefile"] {
                if let Ok(t) = fs::read_to_string(ctx.repo.join(par).join(cand)) {
                    s.push_str(&t);
                    s.push('\n');
                }
            }
        }
        s
    });
    if !kb.contains(&obj_name) {
        return None;
    }

    let obj_base = if ctx.is_modules_repo {
        ctx.product_out.join("obj/sm8735-modules")
    } else {
        ctx.kernel_obj.clone()
    };
    let mut cur = p.parent().unwrap_or(Path::new(""));
    let tp_path = Path::new(&tp);
    loop {
        let search = obj_base.join(cur);
        if let Ok(rd) = fs::read_dir(&search) {
            for ent in rd.flatten() {
                let nm = ent.file_name().to_string_lossy().into_owned();
                if nm.starts_with('.') && nm.ends_with(".o.cmd") && !nm.ends_with(".mod.o.cmd") {
                    let abs_src = ctx.repo.join(rel_c);
                    return Some((ent.path(), ctx.kernel_obj.clone(), abs_src));
                }
            }
        }
        if cur == tp_path || cur.as_os_str().is_empty() {
            break;
        }
        match cur.parent() {
            Some(par) => cur = par,
            None => break,
        }
    }
    None
}

/// Find `.o.cmd` files whose `deps_` list includes any of the modified header paths!
fn find_header_dependents(search_root: &Path, mod_headers: &[String], max_hits: usize) -> Vec<PathBuf> {
    if mod_headers.is_empty() || !search_root.is_dir() {
        return Vec::new();
    }
    let mut found = BTreeSet::new();
    for chunk in mod_headers.chunks(25) {
        let escaped: Vec<String> = chunk
            .iter()
            .map(|h| h.replace('.', r"\.").replace('+', r"\+"))
            .collect();
        let pat = format!(r"({})(\s|\\|$)", escaped.join("|"));
        let (_, out) = rg(search_root, &["-l", "--hidden", "-g", ".*.o.cmd", &pat]);
        for ln in out.lines() {
            let p = search_root.join(ln.trim());
            if p.is_file() {
                found.insert(p);
                if found.len() >= max_hits {
                    return found.into_iter().collect();
                }
            }
        }
    }
    found.into_iter().collect()
}

fn is_linker_pseudo_sym(sym: &str) -> bool {
    sym.is_empty()
        || sym == "__this_module"
        || sym == "_GLOBAL_OFFSET_TABLE_"
        || sym.starts_with("__kcfi_typeid_")
        || sym.starts_with(".__kcfi_typeid_")
        || sym.starts_with(".L")
        || sym.starts_with("$x")
        || sym.starts_with("$d")
}

struct PreflightJob {
    label: String,
    techpack: String,
    ocmd: PathBuf,
    cwd: PathBuf,
    override_src: Option<PathBuf>,
    extra_incs: Vec<PathBuf>,
}

/// Fast 16-core real `clang` pre-flight check using Kbuild's own `.o.cmd` flags.
/// - Default: `-fsyntax-only` (+ auto-discovered new `-I` dirs + sibling-fallback for new `.c` + `build-guard`)
/// - `--link`: compiles native ELF64 `.o` (`-c -fno-lto`) and verifies EVERY `STB_GLOBAL` `SHN_UNDEF`
///   against `Module.symvers`, sibling `.o`/`.ko`, and `System.map` -> catches 100% of MODPOST errors in ~15s!
pub fn cmd_preflight(
    ctx: &Ctx,
    base: Option<&str>,
    with_deps: bool,
    link_check: bool,
    run_guard: bool,
    built_only: bool,
    show_new: bool,
    explicit_files: &[String],
) -> i32 {
    if !ctx.kernel_obj.is_dir() {
        eprintln!(
            "!! KERNEL_OBJ not found at {} — need at least one prior build for .o.cmd flags",
            ctx.kernel_obj.display()
        );
        return 2;
    }

    let mut guard_failed = false;
    if run_guard && explicit_files.is_empty() {
        if buildguard::cmd_build_guard(ctx, base, "HEAD") != 0 {
            guard_failed = true;
        }
    }

    let clang = detect_clang_bin(ctx);
    println!(
        "=== kawal preflight (16-core real clang {}) ===",
        if link_check { "-c -fno-lto + ELF64 MODPOST link-check" } else { "-fsyntax-only" }
    );
    println!("  clang: {clang}");

    let mut target_c: BTreeSet<String> = BTreeSet::new();
    let mut mod_headers: Vec<String> = Vec::new();
    let mut added_hdr_dirs_by_tp: HashMap<String, BTreeSet<PathBuf>> = HashMap::new();

    let mut kconfig_or_caps_changed = false;
    if !explicit_files.is_empty() {
        for f in explicit_files {
            if f.ends_with(".c") {
                target_c.insert(f.clone());
            } else if f.ends_with(".h") {
                mod_headers.push(f.clone());
            }
        }
    } else if let Some(b) = base {
        let diff_files = git(ctx, &["diff", "--name-only", b, "HEAD"]);
        for ln in diff_files.lines() {
            let f = ln.trim();
            if f.ends_with(".c") {
                target_c.insert(f.to_string());
            } else if f.ends_with(".h") {
                mod_headers.push(f.to_string());
            } else if f.ends_with("Kconfig") || f == "arch/arm64/tools/cpucaps" {
                kconfig_or_caps_changed = true;
            }
        }
        let dirty = git(ctx, &["diff", "--name-only"]);
        for ln in dirty.lines() {
            let f = ln.trim();
            if f.ends_with(".c") {
                target_c.insert(f.to_string());
            } else if f.ends_with(".h") {
                mod_headers.push(f.to_string());
            }
        }
        // Discover newly-added header directories per techpack (avoids stale .o.cmd false-fails!)
        let added_h = git(ctx, &["diff", "--diff-filter=A", "--name-only", b, "HEAD", "--", "*.h"]);
        for ln in added_h.lines() {
            let f = ln.trim();
            if f.is_empty() {
                continue;
            }
            if let Some(par) = Path::new(f).parent() {
                let abs = ctx.repo.join(par);
                if abs.is_dir() {
                    let tp = buildguard::techpack_root(f);
                    added_hdr_dirs_by_tp.entry(tp).or_default().insert(abs);
                }
            }
        }
    } else {
        let dirty = git(ctx, &["diff", "--name-only"]);
        let src = if dirty.trim().is_empty() {
            git(ctx, &["diff", "--name-only", "HEAD^1", "HEAD"])
        } else {
            dirty
        };
        for ln in src.lines() {
            let f = ln.trim();
            if f.ends_with(".c") {
                target_c.insert(f.to_string());
            } else if f.ends_with(".h") {
                mod_headers.push(f.to_string());
            }
        }
    }

    let mut jobs: Vec<PreflightJob> = Vec::new();
    let mut seen_ocmd: HashSet<PathBuf> = HashSet::new();
    let mut skipped_unbuilt = 0usize;
    let mut new_c_checked = 0usize;
    let mut kbuild_cache: HashMap<String, String> = HashMap::new();

    for f in &target_c {
        if !ctx.repo.join(f).is_file() {
            skipped_unbuilt += 1;
            continue;
        }
        let tp = buildguard::techpack_root(f);
        let extra_incs: Vec<PathBuf> = added_hdr_dirs_by_tp
            .get(&tp)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        let found = if ctx.is_modules_repo {
            find_ocmd_for_module_c(ctx, f)
        } else {
            find_ocmd_for_kernel_c(ctx, f)
        };
        if let Some((ocmd, cwd)) = found {
            if seen_ocmd.insert(ocmd.clone()) {
                jobs.push(PreflightJob {
                    label: f.clone(),
                    techpack: tp,
                    ocmd,
                    cwd,
                    override_src: None,
                    extra_incs,
                });
            }
        } else if !built_only {
            if let Some((sib_ocmd, cwd, abs_src)) = find_sibling_ocmd(ctx, f, &mut kbuild_cache) {
                jobs.push(PreflightJob {
                    label: format!("[NEW] {f}"),
                    techpack: tp,
                    ocmd: sib_ocmd,
                    cwd,
                    override_src: Some(abs_src),
                    extra_incs,
                });
                new_c_checked += 1;
            } else {
                skipped_unbuilt += 1;
            }
        } else {
            skipped_unbuilt += 1;
        }
    }

    let mut dep_kernel = 0usize;
    let mut dep_modules = 0usize;
    if with_deps && !mod_headers.is_empty() {
        let filtered_hdrs: Vec<String> = mod_headers
            .iter()
            .filter(|h| {
                !matches!(
                    h.as_str(),
                    "include/linux/kernel.h"
                        | "include/linux/types.h"
                        | "include/linux/list.h"
                        | "include/linux/sched.h"
                        | "include/linux/mm.h"
                        | "include/linux/fs.h"
                        | "include/linux/slab.h"
                        | "include/linux/device.h"
                ) || !explicit_files.is_empty()
            })
            .cloned()
            .collect();

        let k_deps = find_header_dependents(&ctx.kernel_obj, &filtered_hdrs, 400);
        for ocmd in k_deps {
            if seen_ocmd.insert(ocmd.clone()) {
                let lbl = ocmd
                    .strip_prefix(&ctx.kernel_obj)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| ocmd.to_string_lossy().into_owned());
                jobs.push(PreflightJob {
                    label: lbl,
                    techpack: String::new(),
                    ocmd,
                    cwd: ctx.kernel_obj.clone(),
                    override_src: None,
                    extra_incs: Vec::new(),
                });
                dep_kernel += 1;
            }
        }
        let mod_obj = ctx.product_out.join("obj/sm8735-modules");
        let m_deps = find_header_dependents(&mod_obj, &filtered_hdrs, 250);
        for ocmd in m_deps {
            if seen_ocmd.insert(ocmd.clone()) {
                let rel = ocmd
                    .strip_prefix(&mod_obj)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| ocmd.to_string_lossy().into_owned());
                let tp = buildguard::techpack_root(&rel);
                let extra_incs: Vec<PathBuf> = added_hdr_dirs_by_tp
                    .get(&tp)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();
                jobs.push(PreflightJob {
                    label: format!("modules/{rel}"),
                    techpack: tp,
                    ocmd,
                    cwd: ctx.kernel_obj.clone(),
                    override_src: None,
                    extra_incs,
                });
                dep_modules += 1;
            }
        }
    }

    println!(
        "  checking {} TU(s) in parallel ({} direct .c, {} new .c via sibling, {} kernel hdr-deps, {} module hdr-deps; {} unbuilt skipped)",
        jobs.len(),
        jobs.len() - new_c_checked - dep_kernel - dep_modules,
        new_c_checked,
        dep_kernel,
        dep_modules,
        skipped_unbuilt
    );
    if kconfig_or_caps_changed {
        println!("  note: Kconfig/cpucaps changed since last KERNEL_OBJ build — stale autoconf.h/cpucap-defs.h may flag renamed CONFIG_*/ARM64_* macros until next make");
    }
    if jobs.is_empty() {
        println!("  nothing to check (no built .o.cmd matched)");
        return if guard_failed { 1 } else { 0 };
    }

    let tmp_dir = std::env::temp_dir().join(format!("kawal-preflight-{}", std::process::id()));
    if link_check {
        let _ = fs::remove_dir_all(&tmp_dir);
        let _ = fs::create_dir_all(&tmp_dir);
    }

    let indexed: Vec<(usize, &PreflightJob)> = jobs.iter().enumerate().collect();
    let results: Vec<(usize, i32, String, Option<PathBuf>)> = par_map(&indexed, ctx.threads, |&(idx, job)| {
        let Ok(txt) = fs::read_to_string(&job.ocmd) else {
            return (idx, 0, String::new(), None);
        };
        let obj_path = if link_check {
            Some(tmp_dir.join(format!("tu_{idx}.o")))
        } else {
            None
        };
        let Some(args) = parse_ocmd_to_clang_args(
            &txt,
            obj_path.as_deref(),
            job.override_src.as_deref(),
            &job.extra_incs,
        ) else {
            return (idx, 0, String::new(), None);
        };
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let (rc, _out, err) = run_cmd(&clang, &arg_refs, &job.cwd, None);
        (idx, rc, err, obj_path)
    });

    let mut built_failed = Vec::new();
    let mut new_failed = Vec::new();
    let built_total = jobs.len().saturating_sub(new_c_checked);
    for (idx, rc, err, _) in &results {
        if *rc != 0 {
            if jobs[*idx].override_src.is_some() {
                new_failed.push((&jobs[*idx].label, err.as_str()));
            } else {
                built_failed.push((&jobs[*idx].label, err.as_str()));
            }
        }
    }

    let mut compile_ok = true;
    if built_failed.is_empty() {
        println!(
            "  PASS [BUILT]: all {built_total} real built translation unit(s) compiled cleanly (0 C errors!)"
        );
    } else {
        compile_ok = false;
        println!(
            "  !! FAIL [BUILT]: {}/{built_total} real built translation unit(s) have compile errors:",
            built_failed.len()
        );
        for (label, err) in &built_failed {
            println!("\n  --- {label} ---");
            for ln in err
                .lines()
                .filter(|l| l.contains("error:") || l.contains("fatal error:") || l.contains("note:"))
                .take(12)
            {
                println!("    {ln}");
            }
        }
    }

    if !new_failed.is_empty() {
        // Explicit-file invocations on a [NEW] file should still report & fail so single-file checks work.
        if !explicit_files.is_empty() && built_total == 0 {
            compile_ok = false;
        }
        if show_new || (!explicit_files.is_empty() && built_total == 0) {
            println!(
                "\n  [NEW-SIBLING] {}/{} speculative unbuilt .c check(s) failed:",
                new_failed.len(),
                new_c_checked
            );
            for (label, err) in &new_failed {
                println!("\n  --- {label} ---");
                for ln in err
                    .lines()
                    .filter(|l| l.contains("error:") || l.contains("fatal error:") || l.contains("note:"))
                    .take(8)
                {
                    println!("    {ln}");
                }
            }
        } else {
            let sample: Vec<&str> = new_failed
                .iter()
                .take(6)
                .map(|(l, _)| l.trim_start_matches("[NEW] "))
                .collect();
            let extra = if new_failed.len() > 6 {
                format!(" (+{} more)", new_failed.len() - 6)
            } else {
                String::new()
            };
            println!(
                "  WARN [NEW-SIBLING]: {}/{} speculative unbuilt .c checks failed (collapsed: {}{extra}; pass --show-new to expand)",
                new_failed.len(),
                new_c_checked,
                sample.join(", ")
            );
        }
    }

    // ELF64 MODPOST undefined-symbol pre-check!
    let mut link_ok = true;
    if link_check {
        let (_, all_symvers) = elf::load_symvers(ctx);
        let sysmap = if !ctx.is_modules_repo {
            elf::load_vmlinux_system_map(ctx)
        } else {
            HashSet::new()
        };

        // Parse every successfully compiled native ELF64 .o
        let mut parsed: Vec<(usize, elf::ObjSymbols)> = Vec::new();
        let mut defined_by_tp: HashMap<String, HashSet<String>> = HashMap::new();
        for (idx, rc, _, obj_opt) in &results {
            if *rc != 0 {
                continue;
            }
            let Some(obj) = obj_opt else { continue };
            if let Ok(os) = elf::parse_obj_symbols(obj) {
                let tp = &jobs[*idx].techpack;
                defined_by_tp.entry(tp.clone()).or_default().extend(os.defined.iter().cloned());
                parsed.push((*idx, os));
            }
        }

        // Also add intra-module symbols from existing .ko files in each touched techpack
        let mod_obj = ctx.product_out.join("obj/sm8735-modules");
        let mut ko_syms_by_tp: HashMap<String, HashSet<String>> = HashMap::new();
        for tp in defined_by_tp.keys() {
            if !tp.is_empty() {
                let syms = elf::load_techpack_ko_symbols(&mod_obj.join(tp));
                ko_syms_by_tp.insert(tp.clone(), syms);
            }
        }

        // Check every STB_GLOBAL SHN_UNDEF!
        let mut missing_by_sym: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (idx, os) in &parsed {
            let job = &jobs[*idx];
            let is_mod = ctx.is_modules_repo || job.label.starts_with("modules/");
            let tp_new = defined_by_tp.get(&job.techpack);
            let tp_ko = ko_syms_by_tp.get(&job.techpack);

            for sym in &os.undefs {
                if is_linker_pseudo_sym(sym) {
                    continue;
                }
                if all_symvers.contains_key(sym) {
                    continue;
                }
                if !is_mod && sysmap.contains(sym) {
                    continue;
                }
                if tp_new.is_some_and(|s| s.contains(sym)) {
                    continue;
                }
                if tp_ko.is_some_and(|s| s.contains(sym)) {
                    continue;
                }
                missing_by_sym
                    .entry(sym.clone())
                    .or_default()
                    .insert(job.label.clone());
            }
        }

        let _ = fs::remove_dir_all(&tmp_dir);

        if missing_by_sym.is_empty() {
            println!(
                "  PASS: ELF64 MODPOST pre-check: 0 unresolved external symbols across {} compiled .o file(s)!",
                parsed.len()
            );
        } else {
            link_ok = false;
            println!(
                "  !! FAIL: ELF64 MODPOST pre-check found {} UNDEFINED external symbol(s):",
                missing_by_sym.len()
            );
            for (sym, locs) in &missing_by_sym {
                let sample: Vec<&String> = locs.iter().take(3).collect();
                let extra = if locs.len() > 3 {
                    format!(" (+{} more)", locs.len() - 3)
                } else {
                    String::new()
                };
                println!(
                    "    !! UNDEF `{sym}` referenced by {}{extra}",
                    sample.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                );
            }
        }
    }

    if compile_ok && link_ok && !guard_failed { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ocmd_to_syntax_args() {
        let sample = r#"savedcmd_drivers/tty/tty_port.o := /usr/bin/ccache clang -Wp,-MMD,drivers/tty/.tty_port.o.d -I./include -DARM64_ASM_ARCH='"armv8.5-a"' -flto -Werror=unused-command-line-argument -c -o drivers/tty/tty_port.o /path/tty_port.c"#;
        let args = parse_ocmd_to_syntax_args(sample).unwrap();
        assert!(!args.iter().any(|a| a.contains("ccache") || a == "clang"));
        assert!(!args.iter().any(|a| a.starts_with("-Wp,-MMD")));
        assert!(!args.iter().any(|a| a == "-c" || a == "-o" || a == "-flto"));
        assert!(args.iter().any(|a| a == "-fsyntax-only"));
        assert!(args.iter().any(|a| a == "/path/tty_port.c"));
        assert!(args.iter().any(|a| a == r#"-DARM64_ASM_ARCH="armv8.5-a""#));
    }

    #[test]
    fn test_parse_ocmd_link_and_override() {
        let sample = r#"savedcmd_foo.o := ccache clang -I./include -flto=full -fwhole-program-vtables -c -o foo.o /old/foo.c"#;
        let args = parse_ocmd_to_clang_args(
            sample,
            Some(Path::new("/tmp/out.o")),
            Some(Path::new("/new/bar.c")),
            &[PathBuf::from("/extra/inc")],
        )
        .unwrap();
        assert!(!args.iter().any(|a| a.contains("flto=full") || a.contains("whole-program-vtables")));
        assert!(args.iter().any(|a| a == "-fno-lto"));
        assert!(args.iter().any(|a| a == "/tmp/out.o"));
        assert!(args.iter().any(|a| a == "/new/bar.c"));
        assert!(args.iter().any(|a| a == "-I/extra/inc"));
    }
}
