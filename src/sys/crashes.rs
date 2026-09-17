use super::eventlog;
use super::{filetime_to_unix_ms, system_drive, system_root};
use std::path::{Path, PathBuf};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CrashKind {
    BlueScreen,
    AppCrash,
    Hang,
    Shutdown,
    Other,
}

impl CrashKind {
    pub fn label(self) -> &'static str {
        match self {
            CrashKind::BlueScreen => "Blue screen",
            CrashKind::AppCrash => "App crash",
            CrashKind::Hang => "Hang",
            CrashKind::Shutdown => "Shutdown",
            CrashKind::Other => "Other",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            CrashKind::BlueScreen => "bluescreen",
            CrashKind::AppCrash => "crash",
            CrashKind::Hang => "hang",
            CrashKind::Shutdown => "shutdown",
            CrashKind::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CrashRow {
    pub time_ms: i64,
    pub kind: CrashKind,
    pub subject: String,
    pub detail: String,
    pub path: Option<PathBuf>,
    pub size: u64,
    pub log_ref: Option<(String, String, u32)>,
}

#[derive(Default)]
pub struct CrashData {
    pub rows: Vec<CrashRow>,
    pub dump_bytes: u64,
    pub notes: Vec<String>,
}

pub struct ScanRoots {
    pub minidump: PathBuf,
    pub memory_dmp: PathBuf,
    pub wer: Vec<PathBuf>,
    pub crash_dumps: Vec<PathBuf>,
    pub events: bool,
}

impl ScanRoots {
    pub fn system() -> ScanRoots {
        let root = system_root();
        let drive = system_drive();
        let program_data = std::env::var("ProgramData").unwrap_or_else(|_| format!("{}\\ProgramData", drive));
        let mut wer = vec![PathBuf::from(&program_data).join("Microsoft\\Windows\\WER\\ReportArchive"), PathBuf::from(&program_data).join("Microsoft\\Windows\\WER\\ReportQueue")];
        let mut crash_dumps = Vec::new();
        if let Ok(users) = std::fs::read_dir(format!("{}\\Users", drive)) {
            for u in users.flatten() {
                let local = u.path().join("AppData\\Local");
                wer.push(local.join("Microsoft\\Windows\\WER\\ReportArchive"));
                wer.push(local.join("Microsoft\\Windows\\WER\\ReportQueue"));
                crash_dumps.push(local.join("CrashDumps"));
            }
        }
        let ld = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps";
        if let Some(key) = super::reg::open(HKEY_LOCAL_MACHINE, ld) {
            if let Some(folder) = super::reg::string(&key, "DumpFolder") {
                crash_dumps.push(PathBuf::from(super::actions::expand_env(&folder)));
            }
            for sub in super::reg::subkeys(&key) {
                if let Some(k) = super::reg::open(HKEY_LOCAL_MACHINE, &format!("{}\\{}", ld, sub))
                    && let Some(folder) = super::reg::string(&k, "DumpFolder") {
                        crash_dumps.push(PathBuf::from(super::actions::expand_env(&folder)));
                    }
            }
        }
        crash_dumps.sort();
        crash_dumps.dedup();
        ScanRoots { minidump: PathBuf::from(format!("{}\\Minidump", root)), memory_dmp: PathBuf::from(format!("{}\\MEMORY.DMP", root)), wer, crash_dumps, events: true }
    }
}

pub fn bugcheck_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x0A => "IRQL_NOT_LESS_OR_EQUAL",
        0x19 => "BAD_POOL_HEADER",
        0x1A => "MEMORY_MANAGEMENT",
        0x1C => "PFN_REFERENCE_COUNT",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x24 => "NTFS_FILE_SYSTEM",
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x3D => "INTERRUPT_EXCEPTION_NOT_HANDLED",
        0x4E => "PFN_LIST_CORRUPT",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x77 => "KERNEL_STACK_INPAGE_ERROR",
        0x7A => "KERNEL_DATA_INPAGE_ERROR",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x7F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x8E => "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        0x9F => "DRIVER_POWER_STATE_FAILURE",
        0xA0 => "INTERNAL_POWER_ERROR",
        0xBE => "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        0xC2 => "BAD_POOL_CALLER",
        0xC4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0xC5 => "DRIVER_CORRUPTED_EXPOOL",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0xD5 => "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
        0xDE => "POOL_CORRUPTION_IN_FILE_AREA",
        0xE2 => "MANUALLY_INITIATED_CRASH",
        0xE3 => "RESOURCE_NOT_OWNED",
        0xEF => "CRITICAL_PROCESS_DIED",
        0xF4 => "CRITICAL_OBJECT_TERMINATION",
        0xF5 => "FLTMGR_FILE_SYSTEM",
        0xF7 => "DRIVER_OVERRAN_STACK_BUFFER",
        0xFC => "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        0xFE => "BUGCODE_USB_DRIVER",
        0x101 => "CLOCK_WATCHDOG_TIMEOUT",
        0x109 => "CRITICAL_STRUCTURE_CORRUPTION",
        0x113 => "VIDEO_DXGKRNL_FATAL_ERROR",
        0x116 => "VIDEO_TDR_FAILURE",
        0x119 => "VIDEO_SCHEDULER_INTERNAL_ERROR",
        0x124 => "WHEA_UNCORRECTABLE_ERROR",
        0x12B => "FAULTY_HARDWARE_CORRUPTED_PAGE",
        0x133 => "DPC_WATCHDOG_VIOLATION",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x13A => "KERNEL_MODE_HEAP_CORRUPTION",
        0x154 => "UNEXPECTED_STORE_EXCEPTION",
        0x1CA => "SYNTHETIC_WATCHDOG_TIMEOUT",
        0x1E1 => "HYPERVISOR_ERROR",
        _ => return None,
    })
}

pub struct KernelHeader {
    pub code: u32,
    pub params: [u64; 4],
}

pub fn parse_kernel_header(bytes: &[u8]) -> Option<KernelHeader> {
    if bytes.len() < 0x60 {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    if &bytes[..8] == b"PAGEDU64" {
        Some(KernelHeader { code: u32_at(0x38), params: [u64_at(0x40), u64_at(0x48), u64_at(0x50), u64_at(0x58)] })
    } else if &bytes[..8] == b"PAGEDUMP" {
        Some(KernelHeader { code: u32_at(0x28), params: [u32_at(0x2C) as u64, u32_at(0x30) as u64, u32_at(0x34) as u64, u32_at(0x38) as u64] })
    } else {
        None
    }
}

pub fn bugcheck_detail(h: &KernelHeader) -> String {
    let name = bugcheck_name(h.code).map(|n| format!("{}  ", n)).unwrap_or_default();
    format!("{}(0x{:016X}, 0x{:016X}, 0x{:016X}, 0x{:016X})", name, h.params[0], h.params[1], h.params[2], h.params[3])
}

pub fn parse_minidump_exception(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 32 || &bytes[..4] != b"MDMP" {
        return None;
    }
    let u32_at = |o: usize| -> Option<u32> { bytes.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) };
    let count = u32_at(8)? as usize;
    let dir = u32_at(12)? as usize;
    for i in 0..count.min(64) {
        let entry = dir + i * 12;
        let stream_type = u32_at(entry)?;
        let size = u32_at(entry + 4)? as usize;
        let rva = u32_at(entry + 8)? as usize;
        if stream_type == 6 && size >= 12 {
            return u32_at(rva + 8);
        }
    }
    None
}

#[derive(Default, Debug)]
pub struct WerReport {
    pub event_type: String,
    pub time_ms: i64,
    pub app_name: String,
    pub app_path: String,
    pub app_version: String,
    pub module: String,
    pub exception: String,
    pub sig0: String,
    pub dump: Option<String>,
}

pub fn parse_wer(text: &str) -> WerReport {
    let mut r = WerReport::default();
    let mut sig_names: Vec<(usize, String)> = Vec::new();
    let mut sig_values: Vec<(usize, String)> = Vec::new();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "EventType" => r.event_type = v.to_string(),
            "EventTime" => r.time_ms = v.parse::<u64>().map(|ft| filetime_to_unix_ms(ft as i64)).unwrap_or(0),
            "AppName" => r.app_name = v.to_string(),
            "AppPath" => r.app_path = v.to_string(),
            "AppVersion" => r.app_version = v.to_string(),
            _ => {
                if let Some(rest) = k.strip_prefix("Sig[") {
                    if let Some((idx, field)) = rest.split_once("].")
                        && let Ok(i) = idx.parse::<usize>() {
                            if field == "Name" {
                                sig_names.push((i, v.to_string()));
                            } else if field == "Value" {
                                sig_values.push((i, v.to_string()));
                            }
                        }
                } else if k.starts_with("File[") && (k.ends_with("].CabName") || k.ends_with("].Path")) && v.to_lowercase().ends_with(".dmp") && r.dump.is_none() {
                    r.dump = Some(v.to_string());
                }
            }
        }
    }
    for (i, name) in &sig_names {
        let value = sig_values.iter().find(|(j, _)| j == i).map(|(_, v)| v.clone()).unwrap_or_default();
        let n = name.to_lowercase();
        if *i == 0 {
            r.sig0 = value.clone();
        }
        if n.contains("fault module name") || n == "module name" {
            r.module = value.clone();
        } else if n.contains("exception code") {
            r.exception = value.clone();
        } else if n.contains("application name") && r.app_name.is_empty() {
            r.app_name = value.clone();
        }
    }
    if r.module.is_empty()
        && let Some((_, v)) = sig_values.iter().find(|(i, _)| *i == 3) {
            r.module = v.clone();
        }
    if r.exception.is_empty()
        && let Some((_, v)) = sig_values.iter().find(|(i, _)| *i == 6) {
            r.exception = v.clone();
        }
    r
}

fn read_report(path: &Path) -> Option<String> {
    if std::fs::metadata(path).ok()?.len() > 4 << 20 {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return Some(String::from_utf16_lossy(&units));
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn mtime_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn process_from_dump_name(path: &Path) -> (String, Option<u32>) {
    let stem = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let lower = stem.to_ascii_lowercase();
    if let Some(i) = lower.find(".exe.") {
        let name = stem[..i + 4].to_string();
        let pid = stem[i + 5..].trim_end_matches(".dmp").trim_end_matches(".DMP").parse::<u32>().ok();
        return (name, pid);
    }
    (stem.trim_end_matches(".dmp").to_string(), None)
}

pub fn scan(roots: &ScanRoots) -> CrashData {
    let mut data = CrashData::default();
    let mut claimed_dumps: Vec<PathBuf> = Vec::new();
    let mut kernel_times: Vec<i64> = Vec::new();

    let mut kernel_files: Vec<PathBuf> = Vec::new();
    match std::fs::read_dir(&roots.minidump) {
        Ok(rd) => kernel_files.extend(rd.flatten().map(|e| e.path()).filter(|p| p.extension().map(|e| e.eq_ignore_ascii_case("dmp")).unwrap_or(false))),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => data.notes.push(format!("{} not readable: {}", roots.minidump.display(), e)),
        Err(_) => {}
    }
    if roots.memory_dmp.is_file() {
        kernel_files.push(roots.memory_dmp.clone());
    }
    for path in kernel_files {
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        let mut head = vec![0u8; 4096];
        let n = std::fs::File::open(&path).and_then(|mut f| { use std::io::Read; f.read(&mut head) }).unwrap_or(0);
        head.truncate(n);
        let time = mtime_ms(&meta);
        let (subject, detail) = match parse_kernel_header(&head) {
            Some(h) => (format!("Bugcheck 0x{:X}", h.code), bugcheck_detail(&h)),
            None => ("Kernel dump".to_string(), "could not read header".to_string()),
        };
        data.dump_bytes += meta.len();
        kernel_times.push(time);
        data.rows.push(CrashRow { time_ms: time, kind: CrashKind::BlueScreen, subject, detail, path: Some(path), size: meta.len(), log_ref: None });
    }

    for wer_root in &roots.wer {
        let rd = match std::fs::read_dir(wer_root) {
            Ok(rd) => rd,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                data.notes.push(format!("{} not readable: {}", wer_root.display(), e));
                continue;
            }
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let dir = entry.path();
            let report = dir.join("Report.wer");
            let Some(text) = read_report(&report) else { continue };
            let r = parse_wer(&text);
            let et = r.event_type.to_uppercase();
            let kind = if et.starts_with("APPCRASH") || et.starts_with("BEX") || et == "CLR20R3" || et.starts_with("MOAPPCRASH") {
                CrashKind::AppCrash
            } else if et.starts_with("APPHANG") || et.starts_with("MOAPPHANG") {
                CrashKind::Hang
            } else if et.is_empty() {
                continue;
            } else {
                CrashKind::Other
            };
            let time = if r.time_ms > 0 { r.time_ms } else { std::fs::metadata(&report).map(|m| mtime_ms(&m)).unwrap_or(0) };
            let subject = if kind == CrashKind::Other { r.event_type.clone() } else if !r.app_name.is_empty() && r.app_name.to_lowercase().ends_with(".exe") { r.app_name.clone() } else if !r.sig0.is_empty() { r.sig0.clone() } else if !r.app_path.is_empty() { Path::new(&r.app_path).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default() } else { r.app_name.clone() };
            let mut detail = Vec::new();
            if kind == CrashKind::AppCrash {
                if !r.module.is_empty() {
                    detail.push(format!("in {}", r.module));
                }
                if !r.exception.is_empty() {
                    detail.push(format!("exception 0x{}", r.exception.trim_start_matches("0x").to_uppercase()));
                }
            } else if kind == CrashKind::Hang {
                detail.push("stopped responding".to_string());
            }
            if !r.app_version.is_empty() {
                detail.push(format!("version {}", r.app_version));
            }
            if !r.app_name.is_empty() && r.app_name != subject && !r.app_name.to_lowercase().ends_with(".exe") {
                detail.push(r.app_name.clone());
            }
            let mut path = Some(dir.clone());
            let mut size = 0u64;
            if let Some(d) = &r.dump {
                let dump_path = dir.join(Path::new(d).file_name().unwrap_or_default());
                if let Ok(m) = std::fs::metadata(&dump_path) {
                    size = m.len();
                    data.dump_bytes += size;
                    claimed_dumps.push(dump_path.clone());
                    path = Some(dump_path);
                }
            }
            if let Ok(rd2) = std::fs::read_dir(&dir) {
                for f in rd2.flatten() {
                    let p = f.path();
                    if p.extension().map(|e| e.eq_ignore_ascii_case("dmp")).unwrap_or(false) && !claimed_dumps.contains(&p) {
                        if let Ok(m) = std::fs::metadata(&p) {
                            size += m.len();
                            data.dump_bytes += m.len();
                        }
                        claimed_dumps.push(p.clone());
                        if path.as_ref().map(|x| x == &dir).unwrap_or(true) {
                            path = Some(p);
                        }
                    }
                }
            }
            data.rows.push(CrashRow { time_ms: time, kind, subject, detail: detail.join(", "), path, size, log_ref: None });
        }
    }

    for folder in &roots.crash_dumps {
        let rd = match std::fs::read_dir(folder) {
            Ok(rd) => rd,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                data.notes.push(format!("{} not readable: {}", folder.display(), e));
                continue;
            }
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.extension().map(|e| e.eq_ignore_ascii_case("dmp")).unwrap_or(false) || claimed_dumps.contains(&p) {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&p) else { continue };
            let mut head = vec![0u8; 65536];
            let n = std::fs::File::open(&p).and_then(|mut f| { use std::io::Read; f.read(&mut head) }).unwrap_or(0);
            head.truncate(n);
            let (name, pid) = process_from_dump_name(&p);
            let mut detail = Vec::new();
            match parse_minidump_exception(&head) {
                Some(code) => detail.push(format!("exception 0x{:08X}", code)),
                None if head.starts_with(b"MDMP") => {}
                None => detail.push("could not read header".to_string()),
            }
            if let Some(pid) = pid {
                detail.push(format!("pid {}", pid));
            }
            data.dump_bytes += meta.len();
            data.rows.push(CrashRow { time_ms: mtime_ms(&meta), kind: CrashKind::AppCrash, subject: name, detail: detail.join(", "), path: Some(p), size: meta.len(), log_ref: None });
        }
    }

    if roots.events {
        scan_events(&mut data, &kernel_times);
    }

    data.rows.sort_by(|a, b| b.time_ms.cmp(&a.time_ms));
    data
}

fn scan_events(data: &mut CrashData, kernel_times: &[i64]) {
    let ninety_days = 90i64 * 86_400_000;
    let wanted: &[(&str, u32, CrashKind)] = &[
        ("Microsoft-Windows-WER-SystemErrorReporting", 1001, CrashKind::BlueScreen),
        ("Microsoft-Windows-Kernel-Power", 41, CrashKind::Shutdown),
        ("EventLog", 6008, CrashKind::Shutdown),
        ("User32", 1074, CrashKind::Shutdown),
    ];
    let rows = match eventlog::query_ids("System", ninety_days, &wanted.iter().map(|(p, id, _)| (*p, *id)).collect::<Vec<_>>()) {
        Ok(r) => r,
        Err(e) => {
            data.notes.push(format!("System log: {}", e));
            return;
        }
    };
    for r in rows {
        let Some((_, _, kind)) = wanted.iter().find(|(p, id, _)| *p == r.source && *id == r.id) else { continue };
        if *kind == CrashKind::BlueScreen && kernel_times.iter().any(|t| (t - r.time_ms).abs() < 5 * 60_000) {
            continue;
        }
        let (subject, detail) = match (r.source.as_str(), r.id) {
            ("Microsoft-Windows-WER-SystemErrorReporting", 1001) => {
                let msg = r.message.replace('\n', " ");
                let code = msg.split("bugcheck was: ").nth(1).map(|s| s.split_whitespace().next().unwrap_or("").trim_end_matches('.').to_string()).unwrap_or_default();
                let n = u32::from_str_radix(code.trim_start_matches("0x"), 16).ok().and_then(bugcheck_name).map(|s| format!("{}  ", s)).unwrap_or_default();
                let params = msg.split("bugcheck was: ").nth(1).map(|s| s.split('.').next().unwrap_or("").to_string()).unwrap_or_default();
                (if code.is_empty() { "Bugcheck".to_string() } else { format!("Bugcheck {}", code) }, format!("{}{} (dump no longer on disk)", n, params.trim()))
            }
            ("Microsoft-Windows-Kernel-Power", 41) => ("Lost power or hung".to_string(), "The system rebooted without shutting down cleanly first (Kernel-Power 41)".to_string()),
            ("EventLog", 6008) => ("Unexpected shutdown".to_string(), r.first_line.clone()),
            _ => {
                let field = |label: &str| -> String {
                    r.message.split(label).nth(1).map(|s| s.lines().next().unwrap_or("").trim().trim_end_matches('.').to_string()).unwrap_or_default()
                };
                let who = field("on behalf of user ").split(" for ").next().unwrap_or("").trim().to_string();
                let by = field("The process ").split(" (").next().unwrap_or("").trim().to_string();
                let by = by.rsplit('\\').next().unwrap_or("").to_string();
                let reason = { let r1 = field("for the following reason: "); if r1.is_empty() { field("Reason: ") } else { r1 } };
                let action = field("Shutdown Type: ");
                let action = if action.is_empty() { "Restart".to_string() } else { capitalize(&action) };
                (format!("{}{}", action, if who.is_empty() { String::new() } else { format!(" by {}", who) }), [if by.is_empty() { String::new() } else { format!("via {}", by) }, reason].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", "))
            }
        };
        data.rows.push(CrashRow { time_ms: r.time_ms, kind: *kind, subject, detail, path: None, size: 0, log_ref: Some((r.log.clone(), r.source.clone(), r.id)) });
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}
