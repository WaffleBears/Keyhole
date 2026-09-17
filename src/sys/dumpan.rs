use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct Kv {
    pub key: String,
    pub value: String,
    pub tone: i32,
}

#[derive(Clone, Debug, Default)]
pub struct Section {
    pub title: String,
    pub hint: String,
    pub rows: Vec<Kv>,
}

#[derive(Clone, Debug, Default)]
pub struct DumpReport {
    pub title: String,
    pub kind: String,
    pub verdict: String,
    pub verdict_tone: i32,
    pub sections: Vec<Section>,
}

fn kv(key: &str, value: impl Into<String>) -> Kv {
    Kv { key: key.into(), value: value.into(), tone: 0 }
}

fn kvt(key: &str, value: impl Into<String>, tone: i32) -> Kv {
    Kv { key: key.into(), value: value.into(), tone }
}

impl DumpReport {
    pub fn text(&self) -> String {
        let mut s = format!("{}\n{}\n\n{}\n", self.title, self.kind, self.verdict);
        for sec in &self.sections {
            s.push_str(&format!("\n== {}", sec.title));
            if !sec.hint.is_empty() {
                s.push_str(&format!("  ({})", sec.hint));
            }
            s.push('\n');
            for r in &sec.rows {
                if r.key.is_empty() { s.push_str(&format!("  {}\n", r.value)) } else { s.push_str(&format!("  {:<24} {}\n", r.key, r.value)) }
            }
        }
        s
    }
}

pub fn exception_name(code: u32) -> &'static str {
    match code {
        0xC0000005 => "ACCESS_VIOLATION",
        0xC0000006 => "IN_PAGE_ERROR",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000025 => "NONCONTINUABLE_EXCEPTION",
        0xC000008C => "ARRAY_BOUNDS_EXCEEDED",
        0xC000008E => "FLOAT_DIVIDE_BY_ZERO",
        0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC0000095 => "INTEGER_OVERFLOW",
        0xC0000096 => "PRIVILEGED_INSTRUCTION",
        0xC00000FD => "STACK_OVERFLOW",
        0xC0000135 => "DLL_NOT_FOUND",
        0xC0000138 => "ORDINAL_NOT_FOUND",
        0xC0000139 => "ENTRYPOINT_NOT_FOUND",
        0xC0000142 => "DLL_INIT_FAILED",
        0xC0000194 => "POSSIBLE_DEADLOCK",
        0xC0000374 => "HEAP_CORRUPTION",
        0xC0000409 => "STACK_BUFFER_OVERRUN (fail fast)",
        0xC0000417 => "INVALID_CRUNTIME_PARAMETER",
        0xC0000420 => "ASSERTION_FAILURE",
        0x80000003 => "BREAKPOINT",
        0x80000004 => "SINGLE_STEP",
        0xE0434352 => ".NET exception (CLR)",
        0xE06D7363 => "C++ exception (MSVC)",
        0x40000015 => "FATAL_APP_EXIT",
        _ => "",
    }
}

pub fn bugcheck_advice(code: u32) -> (&'static str, [&'static str; 4]) {
    match code {
        0x0A => ("A driver touched pageable or invalid memory at an IRQL that is too high. Almost always a driver bug.", ["Memory referenced", "IRQL at the time", "0 read, 1 write, 8 execute", "Address of the instruction"]),
        0x1A => ("The memory manager found corrupt structures: bad RAM, a driver overwriting memory, or a firmware issue.", ["Subtype", "", "", ""]),
        0x1E => ("A kernel mode exception was not handled.", ["Exception code", "Address where it happened", "Parameter 0", "Parameter 1"]),
        0x24 => ("NTFS raised an exception: disk corruption, a failing disk, or a filter driver.", ["Source file and line", "Exception record", "Context record", ""]),
        0x3B => ("An exception happened while executing a system service routine, usually inside a driver.", ["Exception code", "Address of the instruction", "Context record", ""]),
        0x50 => ("Invalid memory was referenced: a faulty driver, bad RAM or a corrupt page file.", ["Memory referenced", "0 read, 1 write, 2 execute", "Address of the instruction", "Reserved"]),
        0x7E => ("A system thread raised an exception nobody handled, usually in a driver.", ["Exception code", "Address where it happened", "Exception record", "Context record"]),
        0x7F => ("A trap the kernel could not handle: often a kernel stack overflow (EXCEPTION_DOUBLE_FAULT, 8) or bad hardware.", ["Trap number", "", "", ""]),
        0x9F => ("A driver did not complete a power request in time (sleep, resume or shutdown hung).", ["Reason", "Device object or timeout", "Thread or device", "Blocked IRP"]),
        0xA5 => ("The ACPI firmware is not compliant. A BIOS update is the usual fix.", ["ACPI code", "", "", ""]),
        0xC2 => ("A driver corrupted the kernel pool (freed twice, wrong tag, or wrote past an allocation).", ["Subtype", "Pool address", "", ""]),
        0xC4 => ("Driver Verifier caught a driver breaking a rule.", ["Verifier code", "", "", ""]),
        0xD1 => ("A driver touched pageable memory at DISPATCH_LEVEL or higher.", ["Memory referenced", "IRQL", "0 read, 1 write, 8 execute", "Address of the instruction"]),
        0xEF => ("A critical system process (csrss, wininit, svchost with RPC, and so on) died.", ["Process object", "", "", ""]),
        0xF4 => ("A process or thread crucial to the system ended unexpectedly, often because the disk holding the page file dropped out.", ["Object type", "Object", "Exit status or name", ""]),
        0x101 => ("A processor stopped responding to interrupts. Usually hardware, firmware or a driver spinning with interrupts off.", ["Timeout ticks", "Processor number", "PRCB address", ""]),
        0x109 => ("PatchGuard: kernel code or critical structures were modified. Rootkit, or a driver hooking the kernel.", ["Reserved", "Reserved", "Failure type", "Corruption type"]),
        0x116 => ("The display driver failed to reset the GPU in time.", ["Context", "Address in the driver", "Error code", "Internal"]),
        0x124 => ("A fatal hardware error was reported by the CPU or chipset (machine check). Check CPU, board, RAM and firmware.", ["Source", "WHEA error record", "Bank high bits", "Bank low bits"]),
        0x133 => ("A DPC or ISR ran too long. A driver monopolised a processor.", ["0 single DPC, 1 cumulative", "Timeout", "", ""]),
        0x139 => ("The kernel detected a corrupted list, stack cookie or other integrity check failure (fail fast).", ["Failure type", "Trap frame", "Exception record", ""]),
        0x13A => ("Kernel heap corruption detected.", ["Failure type", "Heap address", "Address involved", ""]),
        0x154 => ("A store or memory compression component failed unexpectedly.", ["", "", "", ""]),
        0x1CA => ("A synthetic watchdog fired: a hypervisor or virtual machine issue.", ["", "", "", ""]),
        0x1E0 => ("An invalid kernel stack pointer or overrun was detected.", ["", "", "", ""]),
        _ => ("", ["", "", "", ""]),
    }
}

fn faulting_param(code: u32) -> Option<usize> {
    match code {
        0x0A | 0xD1 => Some(3),
        0x1E | 0x7E | 0x3B => Some(1),
        0x50 => Some(2),
        0x116 => Some(1),
        _ => None,
    }
}

struct PeExports {
    names: Vec<(u32, String)>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn rva_to_offset(b: &[u8], sections: &[(u32, u32, u32)], rva: u32) -> Option<usize> {
    for &(va, size, raw) in sections {
        if rva >= va && (rva as u64) < va as u64 + size.max(1) as u64 {
            let off = (rva - va) as usize + raw as usize;
            return if off < b.len() { Some(off) } else { None };
        }
    }
    if (rva as usize) < b.len() { Some(rva as usize) } else { None }
}

pub fn pe_exports(bytes: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    if bytes.get(0..2) != Some(b"MZ") {
        return out;
    }
    let Some(pe) = u32_at(bytes, 0x3C).map(|v| v as usize) else { return out };
    if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
        return out;
    }
    let Some(section_count) = u16_at(bytes, pe + 6) else { return out };
    let Some(opt_size) = u16_at(bytes, pe + 20) else { return out };
    let opt = pe + 24;
    let Some(magic) = u16_at(bytes, opt) else { return out };
    let dir = if magic == 0x20B { opt + 112 } else { opt + 96 };
    let Some(export_rva) = u32_at(bytes, dir) else { return out };
    let Some(export_size) = u32_at(bytes, dir + 4) else { return out };
    if export_rva == 0 {
        return out;
    }
    let mut sections = Vec::new();
    let sec = opt + opt_size as usize;
    for i in 0..section_count as usize {
        let s = sec + i * 40;
        if let (Some(va), Some(size), Some(raw), Some(raw_size)) = (u32_at(bytes, s + 12), u32_at(bytes, s + 8), u32_at(bytes, s + 20), u32_at(bytes, s + 16)) {
            sections.push((va, size.max(raw_size), raw));
        }
    }
    let Some(ed) = rva_to_offset(bytes, &sections, export_rva) else { return out };
    let (Some(n_funcs), Some(n_names), Some(funcs), Some(names), Some(ords)) = (u32_at(bytes, ed + 20), u32_at(bytes, ed + 24), u32_at(bytes, ed + 28), u32_at(bytes, ed + 32), u32_at(bytes, ed + 36)) else { return out };
    let (Some(funcs_off), Some(names_off), Some(ords_off)) = (rva_to_offset(bytes, &sections, funcs), rva_to_offset(bytes, &sections, names), rva_to_offset(bytes, &sections, ords)) else { return out };
    for i in 0..n_names.min(200_000) as usize {
        let (Some(name_rva), Some(ord)) = (u32_at(bytes, names_off + i * 4), u16_at(bytes, ords_off + i * 2)) else { break };
        if ord as u32 >= n_funcs {
            continue;
        }
        let Some(func_rva) = u32_at(bytes, funcs_off + ord as usize * 4) else { continue };
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue;
        }
        let Some(name_off) = rva_to_offset(bytes, &sections, name_rva) else { continue };
        let end = bytes[name_off..].iter().position(|&c| c == 0).map(|p| name_off + p).unwrap_or(bytes.len());
        if let Ok(name) = std::str::from_utf8(&bytes[name_off..end]) {
            out.push((func_rva, name.to_string()));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn nearest_export(exports: &[(u32, String)], rva: u32) -> Option<(String, u32)> {
    let idx = exports.partition_point(|(r, _)| *r <= rva);
    if idx == 0 {
        return None;
    }
    let (base, name) = &exports[idx - 1];
    let delta = rva - base;
    if delta > 0x10000 { None } else { Some((name.clone(), delta)) }
}

pub struct Symbolizer {
    cache: HashMap<String, Option<PeExports>>,
}

impl Default for Symbolizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Symbolizer {
    pub fn new() -> Self {
        Symbolizer { cache: HashMap::new() }
    }

    fn driver_store() -> &'static HashMap<String, PathBuf> {
        static INDEX: std::sync::OnceLock<HashMap<String, PathBuf>> = std::sync::OnceLock::new();
        INDEX.get_or_init(|| {
            let mut map = HashMap::new();
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let repo =Path::new(&root).join("System32").join("DriverStore").join("FileRepository");
            let Ok(packages) = std::fs::read_dir(&repo) else { return map };
            for pkg in packages.flatten() {
                let Ok(files) = std::fs::read_dir(pkg.path()) else { continue };
                for f in files.flatten() {
                    let p = f.path();
                    if p.is_dir() {
                        if let Ok(inner) = std::fs::read_dir(&p) {
                            for g in inner.flatten() {
                                let q = g.path();
                                if q.extension().map(|e| e.eq_ignore_ascii_case("sys") || e.eq_ignore_ascii_case("dll")).unwrap_or(false) {
                                    map.entry(g.file_name().to_string_lossy().to_lowercase()).or_insert(q);
                                }
                            }
                        }
                        continue;
                    }
                    if p.extension().map(|e| e.eq_ignore_ascii_case("sys") || e.eq_ignore_ascii_case("dll")).unwrap_or(false) {
                        map.entry(f.file_name().to_string_lossy().to_lowercase()).or_insert(p);
                    }
                }
            }
            map
        })
    }

    fn candidates(path: &str) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let p = super::actions::expand_env(path);
        let p = p.replace("\\SystemRoot\\", &format!("{}\\", std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))).replace("\\??\\", "");
        out.push(PathBuf::from(&p));
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        if let Some(name) = Path::new(&p).file_name() {
            out.push(Path::new(&root).join("System32").join(name));
            out.push(Path::new(&root).join("System32").join("drivers").join(name));
            out.push(Path::new(&root).join(name));
            if let Some(p) = Self::driver_store().get(&name.to_string_lossy().to_lowercase()) {
                out.push(p.clone());
            }
        }
        out
    }

    fn exports_for(&mut self, module_path: &str) -> &Option<PeExports> {
        let key = module_path.to_lowercase();
        if !self.cache.contains_key(&key) {
            let mut found = None;
            for c in Self::candidates(module_path) {
                if let Ok(bytes) = std::fs::read(&c) {
                    let names = pe_exports(&bytes);
                    if !names.is_empty() {
                        found = Some(PeExports { names });
                        break;
                    }
                }
            }
            self.cache.insert(key.clone(), found);
        }
        &self.cache[&key]
    }

    pub fn symbol(&mut self, module_name: &str, module_path: &str, offset: u64) -> String {
        let short = module_name.rsplit(['\\', '/']).next().unwrap_or(module_name);
        let stem = short.rsplit_once('.').map(|(s, _)| s).unwrap_or(short);
        let stem = if stem.eq_ignore_ascii_case("ntoskrnl") { "nt" } else { stem };
        if let Some(exp) = self.exports_for(module_path)
            && offset <= u32::MAX as u64
                && let Some((name, delta)) = nearest_export(&exp.names, offset as u32) {
                    return if delta == 0 { format!("{}!{}", stem, name) } else { format!("{}!{}+0x{:x}", stem, name, delta) };
                }
        format!("{}+0x{:x}", stem, offset)
    }
}

fn is_windows_module(name: &str, company: &str) -> bool {
    let n = name.to_lowercase();
    if company.to_lowercase().contains("microsoft") {
        return true;
    }
    let core = ["ntoskrnl.exe", "nt", "hal.dll", "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "win32u.dll", "gdi32.dll", "gdi32full.dll", "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "combase.dll", "rpcrt4.dll", "sechost.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "shcore.dll", "clr.dll", "coreclr.dll", "mscoree.dll", "ntfs.sys", "fltmgr.sys", "storport.sys", "ndis.sys", "tcpip.sys", "netio.sys", "wdf01000.sys", "ci.dll", "clfs.sys", "volmgr.sys", "partmgr.sys", "classpnp.sys", "disk.sys", "acpi.sys", "pci.sys", "intelppm.sys", "dxgkrnl.sys", "dxgmms2.sys", "win32k.sys", "win32kbase.sys", "win32kfull.sys", "cng.sys", "ksecdd.sys", "mup.sys", "rdbss.sys", "mrxsmb.sys", "srv2.sys", "afd.sys", "http.sys", "volsnap.sys", "fvevol.sys", "wof.sys", "iorate.sys", "mountmgr.sys", "cdrom.sys", "usbxhci.sys", "usbport.sys", "usbhub3.sys", "hidclass.sys", "kbdclass.sys", "mouclass.sys", "ndisuio.sys", "wfplwfs.sys", "fwpkclnt.sys", "vmbus.sys", "vmbkmcl.sys", "storvsc.sys", "netvsc.sys", "hyperkbd.sys"];
    core.contains(&n.as_str()) || n.starts_with("api-ms-win") || n.starts_with("ext-ms-")
}

fn company_of(path: &str) -> String {
    for c in Symbolizer::candidates(path) {
        if c.is_file() {
            return super::version::read(&c.display().to_string()).company;
        }
    }
    String::new()
}

struct BlockOn;

impl BlockOn {
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}

const KERNEL_PREFIX: u64 = 64 << 20;

pub fn looks_like_dump(path: &str) -> bool {
    let p = path.trim().trim_matches('"').to_ascii_lowercase();
    p.ends_with(".dmp") || p.ends_with(".mdmp") || p.ends_with(".hdmp")
}

pub fn analyze(path: &Path) -> Result<DumpReport, String> {
    use std::io::Read;
    let size = std::fs::metadata(path).map(|m| m.len()).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    let mut file = std::fs::File::open(path).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    let mut head = [0u8; 32];
    let n = file.read(&mut head).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    if n < 32 {
        return Err("the file is too small to be a dump".into());
    }
    if &head[..8] == b"PAGEDU64" || &head[..8] == b"PAGEDUMP" {
        let mut bytes = Vec::with_capacity(size.min(KERNEL_PREFIX) as usize);
        bytes.extend_from_slice(&head[..n]);
        file.take(KERNEL_PREFIX - n as u64).read_to_end(&mut bytes).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
        return analyze_kernel(path, &bytes, size);
    }
    if &head[..4] == b"MDMP" {
        drop(file);
        return analyze_user(path);
    }
    Err("not a Windows dump file (no MDMP or PAGEDU64 signature)".into())
}

fn size_text(n: u64) -> String {
    if n >= 1 << 30 { format!("{:.1} GB", n as f64 / (1u64 << 30) as f64) } else if n >= 1 << 20 { format!("{:.1} MB", n as f64 / (1u64 << 20) as f64) } else { format!("{} KB", n / 1024) }
}

struct KernelDriver {
    name: String,
    path: String,
    base: u64,
    size: u64,
}

fn dump_string(b: &[u8], off: usize) -> String {
    let Some(len) = u32_at(b, off) else { return String::new() };
    let len = len.min(512) as usize;
    let mut w = Vec::with_capacity(len);
    for i in 0..len {
        match u16_at(b, off + 4 + i * 2) {
            Some(c) => w.push(c),
            None => break,
        }
    }
    String::from_utf16_lossy(&w)
}

fn analyze_kernel(path: &Path, b: &[u8], file_size: u64) -> Result<DumpReport, String> {
    let is64 = &b[..8] == b"PAGEDU64";
    let mut report = DumpReport { title: path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), kind: String::new(), ..Default::default() };
    let header = super::crashes::parse_kernel_header(b).ok_or("the kernel dump header could not be read")?;
    let (code, params) = (header.code, header.params);
    let build = u32_at(b, 0x0C).unwrap_or(0);
    let machine = u32_at(b, if is64 { 0x30 } else { 0x20 }).unwrap_or(0);
    let cpus = u32_at(b, if is64 { 0x34 } else { 0x24 }).unwrap_or(0);
    let dump_type = if is64 { u32_at(b, 0xF98).unwrap_or(0) } else { u32_at(b, 0xF88).unwrap_or(0) };
    let systime = if is64 { u64_at(b, 0xFA8).unwrap_or(0) } else { 0 };
    let uptime = if is64 { u64_at(b, 0x1030).unwrap_or(0) } else { 0 };
    report.kind = match dump_type {
        1 => "Kernel dump: complete memory".into(),
        2 => "Kernel dump: kernel memory".into(),
        4 | 5 => "Kernel minidump (triage)".into(),
        6 => "Kernel dump: automatic".into(),
        7 => "Kernel dump: active memory".into(),
        _ => format!("Kernel dump (type {})", dump_type),
    };
    let (advice, param_names) = bugcheck_advice(code);
    let name = super::crashes::bugcheck_name(code).unwrap_or("");
    let mut summary = Section { title: "Summary".into(), hint: String::new(), rows: Vec::new() };
    summary.rows.push(kv("File", path.display().to_string()));
    summary.rows.push(kv("Size", size_text(file_size)));
    if systime > 0 {
        summary.rows.push(kv("Written", super::local_time_text(super::filetime_to_unix_ms(systime as i64))));
    }
    if uptime > 0 {
        summary.rows.push(kv("Uptime at crash", format!("{} h {} min", uptime / 36_000_000_000, (uptime / 600_000_000) % 60)));
    }
    summary.rows.push(kv("Windows build", if build > 0 { build.to_string() } else { "unknown".into() }));
    summary.rows.push(kv("Architecture", match machine { 0x8664 => "x64".into(), 0x14C => "x86".into(), 0xAA64 => "ARM64".into(), other => format!("{:#x}", other) }));
    summary.rows.push(kv("Processors", cpus.to_string()));
    report.sections.push(summary);
    let mut bug = Section { title: "Bug check".into(), hint: "what Windows itself reported".into(), rows: Vec::new() };
    bug.rows.push(kvt("Code", if name.is_empty() { format!("0x{:08X}", code) } else { format!("0x{:08X}  {}", code, name) }, 4));
    if !advice.is_empty() {
        bug.rows.push(kv("Meaning", advice));
    }
    let mut drivers: Vec<KernelDriver> = Vec::new();
    let mut unloaded: Vec<(String, u64, u64)> = Vec::new();
    let mut stack_words: Vec<u64> = Vec::new();
    let mut rip = 0u64;
    let mut exception_code = 0u32;
    let mut exception_addr = 0u64;
    if is64 && b.len() > 0x2000 + 0x60 {
        let t = 0x2000;
        let context_off = u32_at(b, t + 0x0C).unwrap_or(0) as usize;
        let exception_off = u32_at(b, t + 0x10).unwrap_or(0) as usize;
        let unloaded_off = u32_at(b, t + 0x18).unwrap_or(0) as usize;
        let stack_off = u32_at(b, t + 0x28).unwrap_or(0) as usize;
        let stack_size = u32_at(b, t + 0x2C).unwrap_or(0) as usize;
        let list_off = u32_at(b, t + 0x30).unwrap_or(0) as usize;
        let count = u32_at(b, t + 0x34).unwrap_or(0) as usize;
        let pool_off = u32_at(b, t + 0x38).unwrap_or(0) as usize;
        if context_off > 0 {
            rip = u64_at(b, context_off + 0xF8).unwrap_or(0);
        }
        if exception_off > 0 {
            exception_code = u32_at(b, exception_off).unwrap_or(0);
            exception_addr = u64_at(b, exception_off + 16).unwrap_or(0);
        }
        if count > 0 && pool_off > list_off && list_off > 0 {
            let entry = (pool_off - list_off) / count;
            if (0x50..=0x400).contains(&entry) {
                for i in 0..count.min(2000) {
                    let e = list_off + i * entry;
                    let name_off = u32_at(b, e).unwrap_or(0) as usize;
                    let base = u64_at(b, e + 0x38).unwrap_or(0);
                    let size = u64_at(b, e + 0x48).unwrap_or(0) & 0xFFFF_FFFF;
                    if name_off == 0 || base < 0xFFFF_0000_0000_0000 || size == 0 || size > 512 << 20 {
                        continue;
                    }
                    let full = dump_string(b, name_off);
                    if full.is_empty() {
                        continue;
                    }
                    let name = full.rsplit('\\').next().unwrap_or(&full).to_string();
                    drivers.push(KernelDriver { name, path: full, base, size });
                }
            }
        }
        if stack_off > 0 && stack_size > 0 && stack_size < 1 << 20 {
            let mut o = stack_off;
            while o + 8 <= (stack_off + stack_size).min(b.len()) {
                stack_words.push(u64_at(b, o).unwrap_or(0));
                o += 8;
            }
        }
        if unloaded_off > 0 {
            let n = u32_at(b, unloaded_off).unwrap_or(0).min(64) as usize;
            for i in 0..n {
                let e = unloaded_off + 4 + i * 56;
                let mut w = Vec::new();
                for k in 0..12 {
                    match u16_at(b, e + 16 + k * 2) {
                        Some(0) | None => break,
                        Some(c) => w.push(c),
                    }
                }
                let start = u64_at(b, e + 40).unwrap_or(0);
                let end = u64_at(b, e + 48).unwrap_or(0);
                if !w.is_empty() && start > 0 && end > start {
                    unloaded.push((String::from_utf16_lossy(&w), start, end));
                }
            }
        }
    }
    drivers.sort_by_key(|d| d.base);
    let find = |addr: u64| drivers.iter().find(|d| addr >= d.base && addr < d.base + d.size);
    let mut sym = Symbolizer::new();
    let describe = |addr: u64, sym: &mut Symbolizer| -> String {
        match find(addr) {
            Some(d) => format!("0x{:016X}  {}", addr, sym.symbol(&d.name, &d.path, addr - d.base)),
            None => match unloaded.iter().find(|(_, s, e)| addr >= *s && addr < *e) {
                Some((n, s, _)) => format!("0x{:016X}  {} (unloaded)+0x{:x}", addr, n, addr - s),
                None => format!("0x{:016X}", addr),
            },
        }
    };
    for (i, p) in params.iter().enumerate() {
        let label = if param_names[i].is_empty() { format!("Parameter {}", i + 1) } else { format!("Parameter {}: {}", i + 1, param_names[i]) };
        let looks_like_code = *p >= 0xFFFF_8000_0000_0000 && find(*p).is_some();
        bug.rows.push(kv(&label, if looks_like_code { describe(*p, &mut sym) } else { format!("0x{:016X}", p) }));
    }
    if exception_code != 0 {
        let en = exception_name(exception_code);
        bug.rows.push(kv("Exception record", format!("0x{:08X} {} at {}", exception_code, en, describe(exception_addr, &mut sym))));
    }
    if rip != 0 {
        bug.rows.push(kv("Instruction pointer", describe(rip, &mut sym)));
    }
    report.sections.push(bug);
    let fault_addr = faulting_param(code).map(|i| params[i]).filter(|a| *a != 0);
    let mut stack_frames: Vec<u64> = Vec::new();
    for w in &stack_words {
        if (find(*w).is_some() || unloaded.iter().any(|(_, s, e)| *w >= *s && *w < *e))
            && stack_frames.last() != Some(w) {
                stack_frames.push(*w);
            }
    }
    let mut culprit: Option<(String, String)> = None;
    let mut companies: HashMap<String, String> = HashMap::new();
    let mut company_for = |d: &KernelDriver| -> String {
        companies.entry(d.name.to_lowercase()).or_insert_with(|| company_of(&d.path)).clone()
    };
    if let Some(a) = fault_addr {
        if let Some(d) = find(a) {
            let company = company_for(d);
            if !is_windows_module(&d.name, &company) {
                culprit = Some((d.name.clone(), format!("the faulting address {} is inside it", describe(a, &mut sym))));
            }
        } else if let Some((n, _, _)) = unloaded.iter().find(|(_, s, e)| a >= *s && a < *e) {
            culprit = Some((n.clone(), "the faulting address is inside a driver that had already been unloaded (a use after unload bug in that driver)".into()));
        }
    }
    if culprit.is_none() {
        for f in &stack_frames {
            if let Some(d) = find(*f) {
                let company = company_for(d);
                if !is_windows_module(&d.name, &company) {
                    culprit = Some((d.name.clone(), format!("it is the first driver not from Windows on the crashing stack ({})", describe(*f, &mut sym))));
                    break;
                }
            }
        }
    }
    if culprit.is_none()
        && let Some(a) = fault_addr.or(if rip != 0 { Some(rip) } else { None })
            && let Some(d) = find(a) {
                culprit = Some((d.name.clone(), format!("only Windows modules are on the stack. The fault was in {} which usually means bad memory, a firmware issue or a driver that corrupted memory earlier", describe(a, &mut sym))));
            }
    let mut probable = Section { title: "Probably caused by".into(), hint: "the same heuristics WinDbg's !analyze uses without symbols: the faulting address, then the first driver not from Windows on the stack".into(), rows: Vec::new() };
    match &culprit {
        Some((n, why)) => {
            let path = drivers.iter().find(|d| &d.name == n).map(|d| d.path.clone()).unwrap_or_default();
            let company = drivers.iter().find(|d| &d.name == n).map(&mut company_for).unwrap_or_default();
            probable.rows.push(kvt("Module", n.clone(), 4));
            probable.rows.push(kv("Why", why.clone()));
            if !path.is_empty() {
                probable.rows.push(kv("Path", path));
            }
            if !company.is_empty() {
                probable.rows.push(kv("Publisher", company));
            }
            report.verdict = format!("0x{:08X} {}  ·  probably caused by {}", code, name, n);
        }
        None => {
            probable.rows.push(kv("Module", "could not be determined from this dump"));
            report.verdict = format!("0x{:08X} {}", code, name);
        }
    }
    report.verdict_tone = 4;
    report.sections.push(probable);
    let mut stack = Section { title: "Call stack".into(), hint: "return addresses found on the crashing thread's stack, top first. Addresses without a module are omitted".into(), rows: Vec::new() };
    for (i, f) in stack_frames.iter().take(60).enumerate() {
        stack.rows.push(kv(&format!("{:02}", i), describe(*f, &mut sym)));
    }
    if stack.rows.is_empty() {
        stack.rows.push(kv("", "no stack was captured in this dump"));
    }
    report.sections.push(stack);
    let mut on_stack: Vec<(String, usize)> = Vec::new();
    for f in &stack_frames {
        if let Some(d) = find(*f) {
            match on_stack.iter_mut().find(|(n, _)| n == &d.name) {
                Some(e) => e.1 += 1,
                None => on_stack.push((d.name.clone(), 1)),
            }
        }
    }
    let mut third: Section = Section { title: "Drivers not from Windows".into(), hint: "loaded at the time, judged by the publisher in the file's version information on this machine".into(), rows: Vec::new() };
    for d in &drivers {
        let company = company_for(d);
        if !is_windows_module(&d.name, &company) {
            third.rows.push(kv(&d.name, format!("{}{}  ·  0x{:016X} ({})", if company.is_empty() { String::new() } else { format!("{}  ·  ", company) }, d.path, d.base, size_text(d.size))));
        }
    }
    if third.rows.is_empty() {
        third.rows.push(kv("", if drivers.is_empty() { "the driver list could not be read from this dump".to_string() } else { format!("none among the {} loaded drivers", drivers.len()) }));
    }
    report.sections.push(third);
    if !on_stack.is_empty() {
        let mut s = Section { title: "Modules on the stack".into(), hint: "how many stack entries pointed into each module".into(), rows: Vec::new() };
        for (n, c) in on_stack {
            s.rows.push(kv(&n, format!("{} entries", c)));
        }
        report.sections.push(s);
    }
    if !unloaded.is_empty() {
        let mut s = Section { title: "Recently unloaded drivers".into(), hint: "a crash inside one of these ranges points at that driver".into(), rows: Vec::new() };
        for (n, start, end) in &unloaded {
            s.rows.push(kv(n, format!("0x{:016X} to 0x{:016X}", start, end)));
        }
        report.sections.push(s);
    }
    let mut all = Section { title: "Loaded drivers".into(), hint: format!("{} drivers, by load address", drivers.len()), rows: Vec::new() };
    for d in &drivers {
        all.rows.push(kv(&d.name, format!("0x{:016X}  {}  {}", d.base, size_text(d.size), d.path)));
    }
    report.sections.push(all);
    Ok(report)
}

fn analyze_user(path: &Path) -> Result<DumpReport, String> {
    use minidump::{Minidump, Module};
    let dump = Minidump::read_path(path).map_err(|e| format!("minidump could not be parsed: {}", e))?;
    let system = dump.get_stream::<minidump::MinidumpSystemInfo>().ok();
    let modules = dump.get_stream::<minidump::MinidumpModuleList>().map_err(|e| format!("module list: {}", e))?;
    let state = {
        let provider = system.as_ref().map(|si| BlockOn::run(minidump_unwind::debuginfo::DebugInfoSymbolProvider::builder().build(si, &modules)));
        match provider {
            Some(p) => BlockOn::run(minidump_processor::process_minidump(&dump, &p)).map_err(|e| format!("processing failed: {}", e))?,
            None => return Err("the dump has no system information stream".into()),
        }
    };
    let mut report = DumpReport { title: path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), kind: "User-mode minidump".into(), ..Default::default() };
    let mut sym = Symbolizer::new();
    let mut summary = Section { title: "Summary".into(), hint: String::new(), rows: Vec::new() };
    summary.rows.push(kv("File", path.display().to_string()));
    summary.rows.push(kv("Size", size_text(std::fs::metadata(path).map(|m| m.len()).unwrap_or(0))));
    if let Ok(t) = state.time.duration_since(std::time::UNIX_EPOCH) {
        summary.rows.push(kv("Written", super::local_time_text(t.as_millis() as i64)));
    }
    if let Some(pid) = state.process_id {
        summary.rows.push(kv("Process ID", pid.to_string()));
    }
    let main_module = modules.main_module().map(|m| m.code_file().to_string()).unwrap_or_default();
    if !main_module.is_empty() {
        summary.rows.push(kv("Program", main_module.clone()));
    }
    if let Some(v) = state.system_info.format_os_version() {
        summary.rows.push(kv("Windows", v.to_string()));
    }
    summary.rows.push(kv("CPU", format!("{}{}, {} logical processors", state.system_info.cpu, state.system_info.cpu_info.as_ref().map(|c| format!(" ({})", c)).unwrap_or_default(), state.system_info.cpu_count)));
    summary.rows.push(kv("Threads", state.threads.len().to_string()));
    summary.rows.push(kv("Modules", modules.iter().count().to_string()));
    report.sections.push(summary);
    let module_of = |addr: u64| modules.module_at_address(addr);
    let describe = |addr: u64, sym: &mut Symbolizer| -> String {
        match module_of(addr) {
            Some(m) => format!("0x{:016X}  {}", addr, sym.symbol(&m.code_file(), &m.code_file(), addr - m.base_address())),
            None => format!("0x{:016X}", addr),
        }
    };
    let mut crash = Section { title: "Exception".into(), hint: String::new(), rows: Vec::new() };
    let mut crashing_thread: Option<usize> = state.requesting_thread;
    match &state.exception_info {
        Some(e) => {
            let code_text = match e.reason {
                minidump::CrashReason::WindowsGeneral(c) => format!("0x{:08X} {}", (c as u32), exception_name(c as u32)),
                minidump::CrashReason::WindowsAccessViolation(k) => format!("0xC0000005 ACCESS_VIOLATION ({:?})", k),
                minidump::CrashReason::WindowsInPageError(k, s) => format!("0xC0000006 IN_PAGE_ERROR ({:?}, status 0x{:X})", k, s),
                other => format!("{}", other),
            };
            crash.rows.push(kvt("Reason", code_text, 4));
            let top = crashing_thread.and_then(|t| state.threads.get(t)).and_then(|cs| cs.frames.first()).map(|f| f.instruction);
            match top {
                Some(ip) if ip != e.address.0 => {
                    crash.rows.push(kv("Faulting instruction at", describe(ip, &mut sym)));
                    crash.rows.push(kv("Address involved", describe(e.address.0, &mut sym)));
                }
                _ => crash.rows.push(kv("Address", describe(e.address.0, &mut sym))),
            }
            if let Some(adj) = &e.adjusted_address {
                let text = match adj {
                    minidump_processor::AdjustedAddress::NullPointerWithOffset(off) => format!("null pointer plus 0x{:x}: a structure pointer was null and a field of it was used", off.0),
                    minidump_processor::AdjustedAddress::NonCanonical(a) => format!("0x{:016X} is not a canonical address: a corrupted or uninitialised pointer", a.0),
                };
                crash.rows.push(kv("What that means", text));
            }
            if let Some(i) = &e.instruction_str {
                crash.rows.push(kv("Instruction", i.clone()));
            }
            if let Some(m) = &e.memory_access_list {
                let list: Vec<String> = m.iter().map(|a| {
                    let kind = match format!("{:?}", a.access_type).as_str() { "Read" => "read", "Write" => "write", _ => "read and write" };
                    let size = a.size.map(|s| format!("{} bytes ", s)).unwrap_or_default();
                    let mut t = format!("{} {}at 0x{:016X}", kind, size, a.address_info.address);
                    if a.address_info.is_likely_null_pointer_dereference { t.push_str(" (null pointer)") }
                    if a.address_info.is_likely_guard_page { t.push_str(" (guard page: stack overflow or a buffer running off its end)") }
                    t
                }).collect();
                if !list.is_empty() {
                    crash.rows.push(kv("Memory accessed", list.join(", ")));
                }
            }
        }
        None => {
            crash.rows.push(kv("Reason", "no exception in this dump (it was written on request, not because of a crash)"));
            if crashing_thread.is_none() && !state.threads.is_empty() {
                crashing_thread = Some(0);
            }
        }
    }
    if let Some(a) = &state.assertion {
        crash.rows.push(kv("Assertion", a.clone()));
    }
    if let Some(t) = crashing_thread
        && let Some(cs) = state.threads.get(t) {
            crash.rows.push(kv("Thread", format!("{}{}", cs.thread_id, cs.thread_name.as_ref().map(|n| format!(" ({})", n)).unwrap_or_default())));
            if let Some(err) = &cs.last_error_value {
                crash.rows.push(kv("Last error", format!("{}", err)));
            }
        }
    report.sections.push(crash);
    let crashed = state.exception_info.is_some();
    let mut probable = if crashed { Section { title: "Probably caused by".into(), hint: "the first frame on the crashing thread that is not a Windows or runtime module. If every frame is Windows, the module that raised the exception".into(), rows: Vec::new() } } else { Section { title: "Where it was".into(), hint: "the dump was taken on request, so this is simply what the first thread was doing".into(), rows: Vec::new() } };
    let mut culprit: Option<(String, String)> = None;
    let mut stack = Section { title: "Call stack".into(), hint: "crashing thread, top first. The trust column says how the frame was found".into(), rows: Vec::new() };
    if let Some(t) = crashing_thread
        && let Some(cs) = state.threads.get(t) {
            for (i, f) in cs.frames.iter().take(80).enumerate() {
                let text = match &f.module {
                    Some(_) => format!("{}  [{}]", describe(f.instruction, &mut sym), format!("{:?}", f.trust).to_lowercase()),
                    None => format!("0x{:016X}  [{}]", f.instruction, format!("{:?}", f.trust).to_lowercase()),
                };
                stack.rows.push(kv(&format!("{:02}", i), text));
                if culprit.is_none()
                    && let Some(m) = &f.module {
                        let name = Path::new(&m.code_file().to_string()).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                        let company = company_of(&m.code_file());
                        if !is_windows_module(&name, &company) {
                            culprit = Some((name, format!("frame {:02} is inside it: {}", i, describe(f.instruction, &mut sym))));
                        }
                    }
            }
        }
    if culprit.is_none() {
        let top = crashing_thread.and_then(|t| state.threads.get(t)).and_then(|cs| cs.frames.first()).map(|f| f.instruction);
        let ip = top.or(state.exception_info.as_ref().map(|e| e.address.0));
        if let Some(m) = ip.and_then(module_of) {
            let name = Path::new(&m.code_file().to_string()).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            culprit = Some((name, format!("every frame is a Windows or runtime module, so the module holding the faulting instruction is reported: {}", describe(ip.unwrap_or(0), &mut sym))));
        }
    }
    match &culprit {
        Some((n, why)) => {
            probable.rows.push(kvt("Module", n.clone(), if crashed { 4 } else { 0 }));
            probable.rows.push(kv("Why", why.clone()));
            if let Some(m) = modules.iter().find(|m| Path::new(&m.code_file().to_string()).file_name().map(|s| s.to_string_lossy().eq_ignore_ascii_case(n)).unwrap_or(false)) {
                probable.rows.push(kv("Path", m.code_file().to_string()));
                if let Some(v) = m.version() {
                    probable.rows.push(kv("Version", v.to_string()));
                }
                let company = company_of(&m.code_file());
                if !company.is_empty() {
                    probable.rows.push(kv("Publisher", company));
                }
            }
            report.verdict = match &state.exception_info {
                Some(e) => format!("{}  ·  probably caused by {}", match e.reason { minidump::CrashReason::WindowsGeneral(c) => format!("0x{:08X} {}", (c as u32), exception_name(c as u32)), other => format!("{}", other) }, n),
                None => format!("no crash recorded  ·  {}", n),
            };
        }
        None => {
            probable.rows.push(kv("Module", "could not be determined"));
            report.verdict = match &state.exception_info {
                Some(e) => format!("{}  ·  module unknown", match e.reason { minidump::CrashReason::WindowsGeneral(c) => format!("0x{:08X} {}", c as u32, exception_name(c as u32)), other => format!("{}", other) }),
                None => "no crash recorded in this dump".into(),
            };
        }
    }
    report.verdict_tone = if state.exception_info.is_some() { 4 } else { 3 };
    report.sections.push(probable);
    if stack.rows.is_empty() {
        stack.rows.push(kv("", "no stack could be walked"));
    }
    report.sections.push(stack);
    let mut others = Section { title: "Other threads".into(), hint: "top frame of every other thread".into(), rows: Vec::new() };
    for (i, cs) in state.threads.iter().enumerate() {
        if Some(i) == crashing_thread {
            continue;
        }
        let top = cs.frames.first().map(|f| describe(f.instruction, &mut sym)).unwrap_or_else(|| "no frames".into());
        others.rows.push(kv(&format!("{}{}", cs.thread_id, cs.thread_name.as_ref().map(|n| format!(" {}", n)).unwrap_or_default()), top));
    }
    if !others.rows.is_empty() {
        report.sections.push(others);
    }
    let mut third = Section { title: "Modules not from Windows".into(), hint: "judged by the publisher in each file's version information on this machine".into(), rows: Vec::new() };
    let mut all = Section { title: "Loaded modules".into(), hint: format!("{} modules, by load address", modules.iter().count()), rows: Vec::new() };
    for m in modules.by_addr() {
        let file = m.code_file().to_string();
        let name = Path::new(&file).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let company = company_of(&file);
        let ver = m.version().map(|v| v.to_string()).unwrap_or_default();
        if !is_windows_module(&name, &company) {
            third.rows.push(kv(&name, format!("{}{}{}", if company.is_empty() { String::new() } else { format!("{}  ·  ", company) }, if ver.is_empty() { String::new() } else { format!("{}  ·  ", ver) }, file)));
        }
        all.rows.push(kv(&name, format!("0x{:016X}  {}  {}{}", m.base_address(), size_text(m.size()), if ver.is_empty() { String::new() } else { format!("{}  ", ver) }, file)));
    }
    if third.rows.is_empty() {
        third.rows.push(kv("", "none"));
    }
    report.sections.push(third);
    report.sections.push(all);
    Ok(report)
}
