use crate::nt::*;
use crate::sys::devpath::DeviceMap;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
};

pub const GUARD_TIMEOUT: Duration = Duration::from_millis(50);

#[derive(Clone, Copy)]
pub struct RawHandle {
    pub object: u64,
    pub pid: u32,
    pub value: u64,
    pub access: u32,
    pub type_index: u16,
}

pub const SYNTHETIC_KEY_BIT: u64 = 1 << 63;

pub fn is_synthetic_key(key: u64) -> bool {
    key & (SYNTHETIC_KEY_BIT | (SYNTHETIC_KEY_BIT >> 1)) == SYNTHETIC_KEY_BIT
}

pub fn dedupe_key(h: &RawHandle) -> u64 {
    if h.object != 0 {
        h.object
    } else {
        SYNTHETIC_KEY_BIT | ((h.pid as u64) << 32) | (h.value & 0xFFFF_FFFF)
    }
}

pub struct TypeTable {
    names: HashMap<u16, String>,
}

impl TypeTable {
    pub fn build() -> Self {
        let mut names = HashMap::new();
        let mut cap = 8192usize;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.resize(cap, 0);
            let mut needed = 0u32;
            let status = unsafe {
                NtQueryObject(
                    std::ptr::null_mut(),
                    ObjectTypesInformation,
                    buf.as_mut_ptr() as *mut c_void,
                    cap as u32,
                    &mut needed,
                )
            };
            if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW {
                cap = (needed as usize).max(cap * 2) + 4096;
                continue;
            }
            if !nt_ok(status) {
                return TypeTable { names };
            }
            break;
        }

        unsafe {
            let header = &*(buf.as_ptr() as *const OBJECT_TYPES_INFORMATION);
            let count = header.NumberOfTypes;
            let align = std::mem::size_of::<usize>();
            let mut ptr = buf
                .as_ptr()
                .add(align_up(std::mem::size_of::<OBJECT_TYPES_INFORMATION>(), align));
            for i in 0..count {
                let info = &*(ptr as *const OBJECT_TYPE_INFORMATION);
                let name = info.TypeName.to_string();
                let index = if info.TypeIndex != 0 {
                    info.TypeIndex as u16
                } else {
                    (i + 2) as u16
                };
                if !name.is_empty() {
                    names.insert(index, name);
                }
                let advance = align_up(
                    std::mem::size_of::<OBJECT_TYPE_INFORMATION>()
                        + info.TypeName.MaximumLength as usize,
                    align,
                );
                ptr = ptr.add(advance);
            }
        }
        TypeTable { names }
    }

    pub fn name(&self, index: u16) -> &str {
        self.names.get(&index).map(|s| s.as_str()).unwrap_or("Unknown")
    }

    pub fn index_of(&self, name: &str) -> Option<u16> {
        self.names
            .iter()
            .find(|(_, v)| v.eq_ignore_ascii_case(name))
            .map(|(k, _)| *k)
    }

    pub fn all(&self) -> Vec<String> {
        let mut v: Vec<String> = self.names.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    }
}

fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

pub fn scan_raw() -> Vec<RawHandle> {
    let mut cap: usize = 8 << 20;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.resize(cap, 0);
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buf.as_mut_ptr() as *mut c_void,
                cap as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
            cap = (needed as usize).max(cap * 2) + (1 << 20);
            continue;
        }
        if !nt_ok(status) {
            return Vec::new();
        }
        break;
    }

    unsafe {
        let header = &*(buf.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX);
        let count = header.NumberOfHandles;
        let base = std::ptr::addr_of!(header.Handles) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let e = &*base.add(i);
            out.push(RawHandle {
                object: e.Object as u64,
                pid: e.UniqueProcessId as u32,
                value: e.HandleValue as u64,
                access: e.GrantedAccess,
                type_index: e.ObjectTypeIndex,
            });
        }
        out
    }
}

enum GuardMsg {
    Job(usize),
}

struct Straggler {
    key: u64,
    pid: u32,
    value: u64,
    dup: HANDLE,
    rx: Receiver<Option<String>>,
}

struct Guard {
    tx: Sender<GuardMsg>,
    rx: Receiver<Option<String>>,
    stragglers: Vec<Straggler>,
}

enum Answer {
    Ready(Option<String>),
    Late(Receiver<Option<String>>),
    Failed,
}

fn spawn_worker() -> (Sender<GuardMsg>, Receiver<Option<String>>) {
    let (tx, job_rx) = channel::<GuardMsg>();
    let (res_tx, rx) = channel::<Option<String>>();
    std::thread::Builder::new()
        .name("keyhole-name-guard".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            while let Ok(GuardMsg::Job(h)) = job_rx.recv() {
                let name = query_name_direct(HANDLE(h as *mut c_void));
                if res_tx.send(name).is_err() {
                    break;
                }
            }
        })
        .ok();
    (tx, rx)
}

impl Guard {
    fn new() -> Self {
        let (tx, rx) = spawn_worker();
        Guard {
            tx,
            rx,
            stragglers: Vec::new(),
        }
    }

    fn query(&mut self, h: HANDLE) -> Answer {
        if self.tx.send(GuardMsg::Job(h.0 as usize)).is_err() {
            self.respawn();
            return Answer::Failed;
        }
        match self.rx.recv_timeout(GUARD_TIMEOUT) {
            Ok(v) => Answer::Ready(v),
            Err(_) => Answer::Late(self.respawn()),
        }
    }

    fn respawn(&mut self) -> Receiver<Option<String>> {
        let (tx, rx) = spawn_worker();
        self.tx = tx;
        std::mem::replace(&mut self.rx, rx)
    }

    fn drain(&mut self, out: &mut Partial) {
        let grace_end = Instant::now() + STRAGGLER_GRACE;
        for s in self.stragglers.drain(..) {
            let left = grace_end.saturating_duration_since(Instant::now());
            match s.rx.recv_timeout(left) {
                Ok(v) => {
                    out.names.insert(s.key, v);
                    out.resolved_from.push((s.key, s.pid, s.value));
                    unsafe { let _ = CloseHandle(s.dup); }
                }
                Err(_) => {
                    out.stats.threads_abandoned += 1;
                    out.newly_blocked.push(s.key);
                    out.names.insert(s.key, None);
                    unsafe { let _ = CloseHandle(s.dup); }
                }
            }
        }
    }
}

fn query_name_direct(h: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 2048];
    let mut needed = 0u32;
    let mut status = unsafe {
        NtQueryObject(
            h.0,
            ObjectNameInformation,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut needed,
        )
    };
    if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW {
        buf.resize((needed as usize) + 256, 0);
        status = unsafe {
            NtQueryObject(
                h.0,
                ObjectNameInformation,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut needed,
            )
        };
    }
    if !nt_ok(status) {
        return None;
    }
    let info = unsafe { &*(buf.as_ptr() as *const OBJECT_NAME_INFORMATION) };
    let s = unsafe { info.Name.to_string() };
    if s.is_empty() { None } else { Some(s) }
}

struct CachedName {
    name: Option<String>,
    pid: u32,
    value: u64,
    at: Instant,
}

pub struct Resolver {
    blocked: HashMap<u64, Instant>,
    cache: HashMap<u64, CachedName>,
}

#[derive(Default, Clone, Copy)]
pub struct ResolverStats {
    pub threads_abandoned: u64,
    pub pending: u64,
    pub object_addresses: bool,
}

impl ResolverStats {
    fn add(&mut self, o: &ResolverStats) {
        self.threads_abandoned += o.threads_abandoned;
        self.pending += o.pending;
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    pub fn new() -> Self {
        Resolver {
            blocked: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    pub fn resolve_all(
        &mut self,
        raw: &[RawHandle],
        want: &HashSet<u16>,
    ) -> (HashMap<u64, Option<String>>, ResolverStats) {
        let now = Instant::now();
        self.blocked.retain(|_, t| now.duration_since(*t) < BLOCK_TTL);
        self.cache.retain(|_, c| now.duration_since(c.at) < NAME_CACHE_TTL);

        let mut stats = ResolverStats {
            object_addresses: raw.iter().any(|h| h.object != 0),
            ..Default::default()
        };

        let present: HashSet<(u32, u64, u64)> =
            raw.iter().map(|h| (h.pid, h.value, h.object)).collect();

        let mut names: HashMap<u64, Option<String>> = HashMap::new();
        let mut by_pid: HashMap<u32, Vec<&RawHandle>> = HashMap::new();
        let mut seen_objects: HashSet<u64> = HashSet::new();
        let mut openable: HashMap<u32, bool> = HashMap::new();
        let mut unreachable: Vec<u64> = Vec::new();
        for h in raw {
            if !want.is_empty() && !want.contains(&h.type_index) {
                continue;
            }
            if h.pid == 0 || h.pid == 4 {
                continue;
            }
            let key = dedupe_key(h);
            if seen_objects.contains(&key) {
                continue;
            }
            if let Some(c) = self.cache.get(&key)
                && present.contains(&(c.pid, c.value, h.object))
            {
                seen_objects.insert(key);
                names.insert(key, c.name.clone());
                continue;
            }
            let ok = *openable.entry(h.pid).or_insert_with(|| can_duplicate_from(h.pid));
            if !ok {
                unreachable.push(key);
                continue;
            }
            seen_objects.insert(key);
            by_pid.entry(h.pid).or_default().push(h);
        }
        for key in unreachable {
            if !seen_objects.contains(&key) {
                seen_objects.insert(key);
                names.insert(key, None);
            }
        }

        let mut work: Vec<(u32, Vec<&RawHandle>)> = by_pid.into_iter().collect();
        work.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));

        let n_workers = RESOLVE_WORKERS.min(work.len().max(1));
        let mut buckets: Vec<Vec<(u32, Vec<&RawHandle>)>> =
            (0..n_workers).map(|_| Vec::new()).collect();
        for (i, item) in work.into_iter().enumerate() {
            buckets[i % n_workers].push(item);
        }
        let bucket_sizes: Vec<u64> = buckets
            .iter()
            .map(|b| b.iter().map(|(_, l)| l.len() as u64).sum())
            .collect();

        let deadline = now + RESOLVE_BUDGET;
        let blocked_now: HashSet<u64> = self.blocked.keys().copied().collect();
        let blocked_ref = &blocked_now;

        let partials: Vec<Partial> = std::thread::scope(|scope| {
            let handles: Vec<_> = buckets
                .into_iter()
                .map(|bucket| scope.spawn(move || resolve_chunk(bucket, blocked_ref, deadline)))
                .collect();
            handles
                .into_iter()
                .zip(bucket_sizes)
                .map(|(h, size)| {
                    h.join().unwrap_or_else(|_| Partial {
                        stats: ResolverStats { pending: size, ..Default::default() },
                        ..Default::default()
                    })
                })
                .collect()
        });

        for p in partials {
            for (key, pid, value) in p.resolved_from {
                if !is_synthetic_key(key) {
                    let name = p.names.get(&key).cloned().flatten();
                    self.cache.insert(key, CachedName { name, pid, value, at: now });
                }
            }
            names.extend(p.names);
            stats.add(&p.stats);
            for k in p.newly_blocked {
                self.blocked.insert(k, now);
            }
        }
        (names, stats)
    }
}

pub const RESOLVE_WORKERS: usize = 8;
pub const RESOLVE_BUDGET: Duration = Duration::from_millis(4000);
pub const STRAGGLER_GRACE: Duration = Duration::from_millis(200);
pub const BLOCK_TTL: Duration = Duration::from_secs(300);
pub const NAME_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Partial {
    names: HashMap<u64, Option<String>>,
    resolved_from: Vec<(u64, u32, u64)>,
    newly_blocked: Vec<u64>,
    stats: ResolverStats,
}

fn resolve_chunk(
    chunk: Vec<(u32, Vec<&RawHandle>)>,
    blocked: &HashSet<u64>,
    deadline: Instant,
) -> Partial {
    let mut out = Partial::default();
    let mut guard = Guard::new();
    let me = unsafe { GetCurrentProcess() };
    for (pid, list) in chunk {
        let src = match unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) } {
            Ok(h) => h,
            Err(_) => {
                continue;
            }
        };
        for h in list {
            let key = dedupe_key(h);
            if blocked.contains(&key) {
                out.names.insert(key, None);
                continue;
            }
            if Instant::now() >= deadline {
                out.stats.pending += 1;
                out.names.insert(key, None);
                continue;
            }
            let mut dup = HANDLE::default();
            let ok = unsafe {
                DuplicateHandle(
                    src,
                    HANDLE(h.value as *mut c_void),
                    me,
                    &mut dup,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }
            .is_ok();
            if !ok || dup.is_invalid() {
                out.names.insert(key, None);
                continue;
            }
            match guard.query(dup) {
                Answer::Ready(v) => {
                    out.names.insert(key, v);
                    out.resolved_from.push((key, h.pid, h.value));
                    unsafe { let _ = CloseHandle(dup); }
                }
                Answer::Late(rx) => {
                    guard.stragglers.push(Straggler { key, pid: h.pid, value: h.value, dup, rx });
                }
                Answer::Failed => {
                    out.stats.pending += 1;
                    out.names.insert(key, None);
                    unsafe { let _ = CloseHandle(dup); }
                }
            }
        }
        unsafe { let _ = CloseHandle(src); }
    }
    guard.drain(&mut out);
    out
}

pub fn display_name(type_name: &str, raw: &str, dm: &DeviceMap) -> String {
    if raw.is_empty() {
        return String::new();
    }
    match type_name {
        "File" => dm.translate(raw),
        "Key" => pretty_registry(raw),
        _ => raw.to_string(),
    }
}

fn pretty_registry(raw: &str) -> String {
    let map = [
        ("\\REGISTRY\\MACHINE", "HKLM"),
        ("\\REGISTRY\\USER", "HKU"),
        ("\\REGISTRY\\A", "HKAPP"),
    ];
    for (prefix, short) in map {
        if let Some(rest) = crate::sys::strip_prefix_ci(raw, prefix) {
            return format!("{}{}", short, rest);
        }
    }
    raw.to_string()
}

pub fn access_text(type_name: &str, mask: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if type_name == "File" {
        const BITS: [(u32, &str); 9] = [
            (0x0001, "ReadData"),
            (0x0002, "WriteData"),
            (0x0004, "AppendData"),
            (0x0008, "ReadEA"),
            (0x0010, "WriteEA"),
            (0x0020, "Execute"),
            (0x0040, "DeleteChild"),
            (0x0080, "ReadAttr"),
            (0x0100, "WriteAttr"),
        ];
        for (bit, label) in BITS {
            if mask & bit != 0 {
                parts.push(label);
            }
        }
    } else if type_name == "Key" {
        const BITS: [(u32, &str); 6] = [
            (0x0001, "QueryValue"),
            (0x0002, "SetValue"),
            (0x0004, "CreateSubKey"),
            (0x0008, "EnumSubKeys"),
            (0x0010, "Notify"),
            (0x0020, "CreateLink"),
        ];
        for (bit, label) in BITS {
            if mask & bit != 0 {
                parts.push(label);
            }
        }
    } else {
        let bits: &[(u32, &str)] = match type_name {
            "Section" => &[(0x0001, "Query"), (0x0002, "MapWrite"), (0x0004, "MapRead"), (0x0008, "MapExecute"), (0x0010, "ExtendSize")],
            "Directory" => &[(0x0001, "Query"), (0x0002, "Traverse"), (0x0004, "CreateObject"), (0x0008, "CreateSubdirectory")],
            "SymbolicLink" => &[(0x0001, "Query")],
            "Event" => &[(0x0001, "QueryState"), (0x0002, "ModifyState")],
            "Mutant" => &[(0x0001, "QueryState")],
            "Semaphore" => &[(0x0001, "QueryState"), (0x0002, "ModifyState")],
            "Timer" | "IRTimer" => &[(0x0001, "QueryState"), (0x0002, "ModifyState")],
            "Process" => &[
                (0x0001, "Terminate"), (0x0002, "CreateThread"), (0x0008, "VmOperation"), (0x0010, "VmRead"),
                (0x0020, "VmWrite"), (0x0040, "DupHandle"), (0x0080, "CreateProcess"), (0x0100, "SetQuota"),
                (0x0200, "SetInfo"), (0x0400, "QueryInfo"), (0x0800, "SuspendResume"), (0x1000, "QueryLimitedInfo"),
            ],
            "Thread" => &[
                (0x0001, "Terminate"), (0x0002, "SuspendResume"), (0x0008, "GetContext"), (0x0010, "SetContext"),
                (0x0020, "SetInfo"), (0x0040, "QueryInfo"), (0x0080, "SetToken"), (0x0100, "Impersonate"),
                (0x0200, "DirectImpersonation"), (0x0400, "SetLimitedInfo"), (0x0800, "QueryLimitedInfo"),
            ],
            "Token" => &[
                (0x0001, "AssignPrimary"), (0x0002, "Duplicate"), (0x0004, "Impersonate"), (0x0008, "Query"),
                (0x0010, "QuerySource"), (0x0020, "AdjustPrivileges"), (0x0040, "AdjustGroups"), (0x0080, "AdjustDefault"),
                (0x0100, "AdjustSessionId"),
            ],
            "Job" => &[(0x0001, "AssignProcess"), (0x0002, "SetAttributes"), (0x0004, "Query"), (0x0008, "Terminate"), (0x0010, "SetSecurityAttributes")],
            "ALPC Port" => &[(0x0001, "Connect")],
            "Desktop" => &[(0x0001, "ReadObjects"), (0x0002, "CreateWindow"), (0x0004, "CreateMenu"), (0x0008, "HookControl"), (0x0010, "JournalRecord"), (0x0020, "JournalPlayback"), (0x0040, "Enumerate"), (0x0080, "WriteObjects"), (0x0100, "SwitchDesktop")],
            "WindowStation" => &[(0x0001, "EnumDesktops"), (0x0002, "ReadAttributes"), (0x0004, "AccessClipboard"), (0x0008, "CreateDesktop"), (0x0010, "WriteAttributes"), (0x0020, "AccessGlobalAtoms"), (0x0040, "ExitWindows"), (0x0100, "Enumerate"), (0x0200, "ReadScreen")],
            "IoCompletion" => &[(0x0001, "Query"), (0x0002, "Modify")],
            "EtwRegistration" | "EtwConsumer" => &[(0x0001, "Query"), (0x0002, "Modify")],
            _ => &[],
        };
        for (bit, label) in bits {
            if mask & bit != 0 {
                parts.push(label);
            }
        }
    }
    if mask & 0x1000_0000 != 0 {
        parts.push("AllAccess");
    } else {
        if mask & 0x8000_0000 != 0 { parts.push("GenericRead"); }
        if mask & 0x4000_0000 != 0 { parts.push("GenericWrite"); }
        if mask & 0x2000_0000 != 0 { parts.push("GenericExecute"); }
    }
    const STD: [(u32, &str); 5] = [
        (0x0001_0000, "Delete"),
        (0x0002_0000, "ReadControl"),
        (0x0004_0000, "WriteDac"),
        (0x0008_0000, "WriteOwner"),
        (0x0010_0000, "Synchronize"),
    ];
    for (bit, label) in STD {
        if mask & bit != 0 {
            parts.push(label);
        }
    }
    if parts.is_empty() {
        format!("0x{:08X}", mask)
    } else {
        parts.join(", ")
    }
}

fn can_duplicate_from(pid: u32) -> bool {
    unsafe {
        match OpenProcess(PROCESS_DUP_HANDLE, false, pid) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}
