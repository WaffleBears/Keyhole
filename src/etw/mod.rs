pub mod schema;

use crate::model::{ActivityRow, ActivityTotals};
use crate::sys::devpath::SharedDeviceMap;
use crate::sys::wide;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use schema::{SchemaCache, decode, guid_to_u128};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, EVENT_RECORD, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, CloseTrace,
    WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

const SESSION_NAME: &str = "Keyhole-Activity";

const KERNEL_FILE: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
const KERNEL_DISK: GUID = GUID::from_u128(0xc7bde69a_e1e0_4177_b6ef_283ad1525271);
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const PROCESS_KEYWORDS: u64 = 0x10;
const EV_PROCESS_START: u16 = 1;

const FILE_KEYWORDS: u64 = 0x10 | 0x80 | 0x100 | 0x200 | 0x1000;
const DISK_KEYWORDS: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const NET_KEYWORDS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

const EV_FILE_CREATE: u16 = 12;
const EV_FILE_CLOSE: u16 = 14;
const EV_FILE_READ: u16 = 15;
const EV_FILE_WRITE: u16 = 16;
const EV_FILE_CREATE_NEW: u16 = 30;
const EV_DISK_READ: u16 = 10;
const EV_DISK_WRITE: u16 = 11;
const NET_SEND: [u16; 2] = [10, 26];
const NET_RECV: [u16; 2] = [11, 27];
const NET_UDP_SEND: [u16; 2] = [42, 58];
const NET_UDP_RECV: [u16; 2] = [43, 59];

const IRP_PAGING: u64 = 0x2 | 0x40;
const WINDOW: usize = 6;
const HISTORY: usize = 90;
const MAX_KEYS: usize = 8192;
const NAME_RESET_AT: usize = 150_000;

#[derive(Default, Clone, Copy)]
struct Acc {
    read: u64,
    write: u64,
    ops: u64,
}

impl Acc {
    fn add(&mut self, other: &Acc) {
        self.read += other.read;
        self.write += other.write;
        self.ops += other.ops;
    }
    fn total(&self) -> u64 {
        self.read + self.write
    }
}

#[derive(Default, Clone, Copy)]
struct DiskAcc {
    read: u64,
    write: u64,
    ops: u64,
    response_ticks: u64,
}

impl DiskAcc {
    fn add(&mut self, other: &DiskAcc) {
        self.read += other.read;
        self.write += other.write;
        self.ops += other.ops;
        self.response_ticks += other.response_ticks;
    }
}

#[derive(Default)]
struct Bucket {
    files: HashMap<(u32, u32), Acc>,
    procs: HashMap<u32, Acc>,
    disks: HashMap<u32, DiskAcc>,
    disk_procs: HashMap<u32, Acc>,
    net_procs: HashMap<u32, Acc>,
}

struct Interner {
    map: HashMap<String, u32>,
    list: Vec<String>,
}

impl Interner {
    fn new() -> Self {
        Interner {
            map: HashMap::new(),
            list: vec![String::new()],
        }
    }
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(id) = self.map.get(s) {
            return *id;
        }
        if self.list.len() >= NAME_RESET_AT + 50_000 {
            return 0;
        }
        let id = self.list.len() as u32;
        self.list.push(s.to_string());
        self.map.insert(s.to_string(), id);
        id
    }
    fn get(&self, id: u32) -> &str {
        self.list.get(id as usize).map(|s| s.as_str()).unwrap_or("")
    }
}

struct Aggregator {
    buckets: Vec<Bucket>,
    names: Interner,
    file_objects: HashMap<u64, u32>,
    file_openers: HashMap<u32, u32>,
    thread_pids: HashMap<u32, u32>,
    rotations: u64,
    history_file: (Vec<u64>, Vec<u64>),
    history_disk: (Vec<u64>, Vec<u64>),
    history_net: (Vec<u64>, Vec<u64>),
    events_seen: u64,
    events_dropped: u64,
    process_names: HashMap<u32, String>,
    remembered_names: HashMap<u32, (String, std::time::Instant)>,
}

impl Aggregator {
    fn new() -> Self {
        let mut buckets = Vec::with_capacity(WINDOW);
        for _ in 0..WINDOW {
            buckets.push(Bucket::default());
        }
        Aggregator {
            buckets,
            names: Interner::new(),
            file_objects: HashMap::new(),
            file_openers: HashMap::new(),
            thread_pids: HashMap::new(),
            rotations: 0,
            history_file: (vec![0; HISTORY], vec![0; HISTORY]),
            history_disk: (vec![0; HISTORY], vec![0; HISTORY]),
            history_net: (vec![0; HISTORY], vec![0; HISTORY]),
            events_seen: 0,
            events_dropped: 0,
            process_names: HashMap::new(),
            remembered_names: HashMap::new(),
        }
    }

    fn names_opener(&self, name_id: u32) -> Option<u32> {
        if name_id == 0 { None } else { self.file_openers.get(&name_id).copied() }
    }

    fn current(&mut self) -> &mut Bucket {
        self.buckets.last_mut().unwrap()
    }

    fn rotate(&mut self) {
        let last = self.buckets.last().unwrap();
        let fr: u64 = last.procs.values().map(|a| a.read).sum();
        let fw: u64 = last.procs.values().map(|a| a.write).sum();
        let dr: u64 = last.disk_procs.values().map(|a| a.read).sum();
        let dw: u64 = last.disk_procs.values().map(|a| a.write).sum();
        let nr: u64 = last.net_procs.values().map(|a| a.read).sum();
        let nw: u64 = last.net_procs.values().map(|a| a.write).sum();

        push_history(&mut self.history_file.0, fr);
        push_history(&mut self.history_file.1, fw);
        push_history(&mut self.history_disk.0, dr);
        push_history(&mut self.history_disk.1, dw);
        push_history(&mut self.history_net.0, nr);
        push_history(&mut self.history_net.1, nw);

        self.buckets.push(Bucket::default());
        if self.buckets.len() > WINDOW {
            self.buckets.remove(0);
        }
        self.rotations += 1;
        if self.file_objects.len() > 300_000 {
            self.file_objects.clear();
            self.file_openers.clear();
        }
        if self.rotations.is_multiple_of(60) {
            self.thread_pids.clear();
        }
        if self.names.list.len() > NAME_RESET_AT {
            self.names = Interner::new();
            self.file_objects.clear();
            self.file_openers.clear();
            for b in self.buckets.iter_mut() {
                b.files.clear();
            }
        }
    }
}

fn push_history(v: &mut Vec<u64>, value: u64) {
    v.push(value);
    if v.len() > HISTORY {
        v.remove(0);
    }
}

#[derive(Default, Clone)]
pub struct ActivitySnapshot {
    pub file_rows: Vec<ActivityRow>,
    pub file_procs: Vec<ActivityRow>,
    pub disk_rows: Vec<ActivityRow>,
    pub disk_procs: Vec<ActivityRow>,
    pub net_procs: Vec<ActivityRow>,
    pub totals_file: ActivityTotals,
    pub totals_disk: ActivityTotals,
    pub totals_net: ActivityTotals,
    pub active: bool,
    pub note: String,
}

pub struct Activity {
    snapshot: ArcSwap<ActivitySnapshot>,
    agg: Arc<Mutex<Aggregator>>,
    running: Arc<AtomicU64>,
    generation: AtomicU64,
    control: Arc<AtomicU64>,
    devices: SharedDeviceMap,
    last_error: Mutex<String>,
}

struct CallbackContext {
    agg: Arc<Mutex<Aggregator>>,
    schemas: Mutex<SchemaCache>,
}

impl Activity {
    pub fn new(devices: SharedDeviceMap) -> Arc<Self> {
        Arc::new(Activity {
            snapshot: ArcSwap::from_pointee(ActivitySnapshot {
                note: "not started".into(),
                ..Default::default()
            }),
            agg: Arc::new(Mutex::new(Aggregator::new())),
            running: Arc::new(AtomicU64::new(0)),
            generation: AtomicU64::new(0),
            control: Arc::new(AtomicU64::new(0)),
            devices,
            last_error: Mutex::new(String::new()),
        })
    }

    pub fn snapshot(&self) -> Arc<ActivitySnapshot> {
        self.snapshot.load_full()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed) != 0
    }

    pub fn last_error(&self) -> String {
        self.last_error.lock().clone()
    }

    fn fail(&self, message: String) -> Result<(), String> {
        *self.last_error.lock() = message.clone();
        Err(message)
    }

    pub fn set_process_names(&self, names: HashMap<u32, String>) {
        let mut agg = self.agg.lock();
        let now = std::time::Instant::now();
        for (pid, name) in &names {
            if !name.is_empty() {
                agg.remembered_names.insert(*pid, (name.clone(), now));
            }
        }
        agg.remembered_names.retain(|_, (_, at)| now.duration_since(*at) < std::time::Duration::from_secs(180));
        agg.process_names = names;
    }

    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        stop_stale_session();

        let handle = match start_session() {
            Ok(h) => h,
            Err(e) => return self.fail(e),
        };
        self.control.store(handle.Value, Ordering::SeqCst);

        for (guid, keywords) in [
            (KERNEL_FILE, FILE_KEYWORDS),
            (KERNEL_DISK, DISK_KEYWORDS),
            (KERNEL_NETWORK, NET_KEYWORDS),
            (KERNEL_PROCESS, PROCESS_KEYWORDS),
        ] {
            let r = unsafe {
                EnableTraceEx2(
                    handle,
                    &guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    4,
                    keywords,
                    0,
                    0,
                    None,
                )
            };
            if r != ERROR_SUCCESS {
                let _ = stop_session(handle);
                self.control.store(0, Ordering::SeqCst);
                return self.fail(format!("the {} provider could not be enabled ({})", provider_label(&guid), crate::sys::winerr::text(r.0)));
            }
        }

        let generation_id = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.running.store(generation_id, Ordering::SeqCst);
        self.last_error.lock().clear();

        let ctx = Box::new(CallbackContext {
            agg: self.agg.clone(),
            schemas: Mutex::new(SchemaCache::new()),
        });
        let ctx_addr = Box::into_raw(ctx) as usize;

        let me = self.clone();
        let reader = std::thread::Builder::new()
            .name("keyhole-etw".into())
            .spawn(move || {
                let name = wide(SESSION_NAME);
                let mut logfile = EVENT_TRACE_LOGFILEW::default();
                logfile.LoggerName = PWSTR(name.as_ptr() as *mut u16);
                logfile.Anonymous1.ProcessTraceMode =
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                logfile.Anonymous2.EventRecordCallback = Some(event_callback);
                logfile.Context = ctx_addr as *mut c_void;

                let trace = unsafe { OpenTraceW(&mut logfile) };
                if trace.Value == u64::MAX {
                    let why = crate::sys::winerr::text(unsafe { windows::Win32::Foundation::GetLastError() }.0);
                    let _ = me.fail(format!("the trace session could not be opened for reading: {}", why));
                    me.stop();
                    drop(unsafe { Box::from_raw(ctx_addr as *mut CallbackContext) });
                    return;
                }
                let handles = [trace];
                let _ = unsafe { ProcessTrace(&handles, None, None) };
                let _ = unsafe { CloseTrace(trace) };
                if me.running.compare_exchange(generation_id, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    let _ = me.fail("the kernel trace session stopped. Press Start to trace again".to_string());
                    me.stop();
                }
                drop(unsafe { Box::from_raw(ctx_addr as *mut CallbackContext) });
            });
        if let Err(e) = reader {
            self.stop();
            drop(unsafe { Box::from_raw(ctx_addr as *mut CallbackContext) });
            return self.fail(format!("the trace reader thread could not start: {}", e));
        }

        let me = self.clone();
        let ticker = std::thread::Builder::new()
            .name("keyhole-etw-tick".into())
            .spawn(move || {
                while me.running.load(Ordering::Relaxed) == generation_id {
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                    me.publish();
                }
                me.publish();
            });
        if let Err(e) = ticker {
            self.stop();
            return self.fail(format!("the trace publisher thread could not start: {}", e));
        }

        Ok(())
    }

    pub fn stop(&self) {
        let value = self.control.swap(0, Ordering::SeqCst);
        if value != 0 {
            let _ = stop_session(CONTROLTRACE_HANDLE { Value: value });
        }
        self.running.store(0, Ordering::SeqCst);
    }

    fn publish(&self) {
        let dm = self.devices.get();
        let disk_info = crate::sys::disks::map();
        let mut agg = self.agg.lock();
        agg.rotate();

        let mut files: HashMap<(u32, u32), Vec<u64>> = HashMap::new();
        let mut file_acc: HashMap<(u32, u32), Acc> = HashMap::new();
        let mut procs: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut proc_acc: HashMap<u32, Acc> = HashMap::new();
        let mut ddisks: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut ddisk_acc: HashMap<u32, DiskAcc> = HashMap::new();
        let mut dprocs: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut dproc_acc: HashMap<u32, Acc> = HashMap::new();
        let mut nprocs: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut nproc_acc: HashMap<u32, Acc> = HashMap::new();

        let n = agg.buckets.len();
        for (i, b) in agg.buckets.iter().enumerate() {
            for (k, v) in &b.files {
                file_acc.entry(*k).or_default().add(v);
                files.entry(*k).or_insert_with(|| vec![0; n])[i] = v.total();
            }
            for (k, v) in &b.procs {
                proc_acc.entry(*k).or_default().add(v);
                procs.entry(*k).or_insert_with(|| vec![0; n])[i] = v.total();
            }
            for (k, v) in &b.disks {
                ddisk_acc.entry(*k).or_default().add(v);
                ddisks.entry(*k).or_insert_with(|| vec![0; n])[i] = v.read + v.write;
            }
            for (k, v) in &b.disk_procs {
                dproc_acc.entry(*k).or_default().add(v);
                dprocs.entry(*k).or_insert_with(|| vec![0; n])[i] = v.total();
            }
            for (k, v) in &b.net_procs {
                nproc_acc.entry(*k).or_default().add(v);
                nprocs.entry(*k).or_insert_with(|| vec![0; n])[i] = v.total();
            }
        }

        let file_rows = build_file_rows(&agg, &file_acc, &files, &dm);
        let disk_rows = build_disk_rows(&disk_info, &ddisk_acc, &ddisks);
        let file_procs = build_proc_rows(&agg, &proc_acc, &procs, false);
        let disk_procs = build_proc_rows(&agg, &dproc_acc, &dprocs, true);
        let net_procs = build_proc_rows(&agg, &nproc_acc, &nprocs, false);

        let last = agg.buckets.len().saturating_sub(2);
        let bucket = &agg.buckets[last];
        let totals_file = ActivityTotals {
            read_rate: bucket.procs.values().map(|a| a.read).sum(),
            write_rate: bucket.procs.values().map(|a| a.write).sum(),
            ops_rate: bucket.procs.values().map(|a| a.ops).sum(),
            events_seen: agg.events_seen,
            events_dropped: agg.events_dropped,
            history_read: agg.history_file.0.clone(),
            history_write: agg.history_file.1.clone(),
        };
        let totals_disk = ActivityTotals {
            read_rate: bucket.disk_procs.values().map(|a| a.read).sum(),
            write_rate: bucket.disk_procs.values().map(|a| a.write).sum(),
            ops_rate: bucket.disk_procs.values().map(|a| a.ops).sum(),
            events_seen: agg.events_seen,
            events_dropped: agg.events_dropped,
            history_read: agg.history_disk.0.clone(),
            history_write: agg.history_disk.1.clone(),
        };
        let totals_net = ActivityTotals {
            read_rate: bucket.net_procs.values().map(|a| a.read).sum(),
            write_rate: bucket.net_procs.values().map(|a| a.write).sum(),
            ops_rate: bucket.net_procs.values().map(|a| a.ops).sum(),
            events_seen: agg.events_seen,
            events_dropped: agg.events_dropped,
            history_read: agg.history_net.0.clone(),
            history_write: agg.history_net.1.clone(),
        };

        drop(agg);

        self.snapshot.store(Arc::new(ActivitySnapshot {
            file_rows,
            file_procs,
            disk_rows,
            disk_procs,
            net_procs,
            totals_file,
            totals_disk,
            totals_net,
            active: self.is_running(),
            note: self.last_error(),
        }));
    }
}

fn process_label(agg: &Aggregator, pid: u32) -> String {
    agg.process_names
        .get(&pid)
        .cloned()
        .or_else(|| agg.remembered_names.get(&pid).filter(|(n, _)| !n.is_empty()).map(|(n, _)| format!("{} (exited)", n)))
        .unwrap_or_else(|| format!("pid {}", pid))
}

fn build_file_rows(
    agg: &Aggregator,
    acc: &HashMap<(u32, u32), Acc>,
    spark: &HashMap<(u32, u32), Vec<u64>>,
    dm: &crate::sys::devpath::DeviceMap,
) -> Vec<ActivityRow> {
    struct Merged {
        acc: Acc,
        spark: Vec<u64>,
        by_pid: HashMap<u32, u64>,
    }
    let mut merged: HashMap<(u32, u32), Merged> = HashMap::new();
    for ((pid, name_id), a) in acc.iter().filter(|(_, a)| a.total() > 0 || a.ops > 0) {
        let key = (*name_id, if *name_id == 0 { *pid } else { 0 });
        let m = merged.entry(key).or_insert_with(|| Merged { acc: Acc::default(), spark: Vec::new(), by_pid: HashMap::new() });
        m.acc.add(a);
        *m.by_pid.entry(*pid).or_default() += a.total().max(a.ops);
        if let Some(s) = spark.get(&(*pid, *name_id)) {
            if m.spark.len() < s.len() {
                m.spark.resize(s.len(), 0);
            }
            for (i, v) in s.iter().enumerate() {
                m.spark[i] += v;
            }
        }
    }
    let mut rows: Vec<ActivityRow> = merged
        .into_iter()
        .map(|((name_id, unnamed_pid), m)| {
            let raw = agg.names.get(name_id);
            let path = dm.translate(raw);
            let label = path.rsplit('\\').next().unwrap_or(&path).to_string();
            let mut pids: Vec<(u32, u64)> = m.by_pid.into_iter().collect();
            pids.sort_by(|a, b| b.1.cmp(&a.1));
            let top_pid = pids.first().map(|p| p.0).unwrap_or(0);
            let mut who = process_label(agg, top_pid);
            if let Some(opener) = agg.names_opener(name_id)
                && opener != top_pid && !pids.iter().any(|(p, _)| *p == opener) {
                    who.push_str(&format!(" (created by {})", process_label(agg, opener)));
                }
            if pids.len() > 1 {
                who.push_str(&format!(" and {} other process{}", pids.len() - 1, if pids.len() == 2 { "" } else { "es" }));
            }
            let (label, detail) = if path.is_empty() {
                (format!("{}: files without a captured name", process_label(agg, unnamed_pid)), "I/O on files opened before tracing started or by the kernel, so their names were never seen".to_string())
            } else if label.is_empty() {
                (path.clone(), path.clone())
            } else {
                (label, path.clone())
            };
            ActivityRow {
                key: if name_id == 0 { format!("u{}", unnamed_pid) } else { format!("f{}", name_id) },
                label,
                detail,
                who,
                pid: top_pid,
                read_bytes: m.acc.read,
                write_bytes: m.acc.write,
                ops: m.acc.ops,
                spark: m.spark,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (b.read_bytes + b.write_bytes)
            .cmp(&(a.read_bytes + a.write_bytes))
            .then(b.ops.cmp(&a.ops))
    });
    rows.truncate(200);
    rows
}

fn build_proc_rows(
    agg: &Aggregator,
    acc: &HashMap<u32, Acc>,
    spark: &HashMap<u32, Vec<u64>>,
    disk: bool,
) -> Vec<ActivityRow> {
    let mut rows: Vec<ActivityRow> = Vec::new();
    let mut exited: HashMap<String, (Acc, Vec<u64>, u32)> = HashMap::new();
    for (pid, a) in acc.iter().filter(|(_, a)| a.total() > 0 || a.ops > 0) {
        let live = agg.process_names.contains_key(pid);
        let label = process_label(agg, *pid);
        if !live && label.ends_with(" (exited)") {
            let e = exited.entry(label).or_insert_with(|| (Acc::default(), Vec::new(), 0));
            e.0.add(a);
            e.2 += 1;
            if let Some(s) = spark.get(pid) {
                if e.1.len() < s.len() {
                    e.1.resize(s.len(), 0);
                }
                for (i, v) in s.iter().enumerate() {
                    e.1[i] += v;
                }
            }
            continue;
        }
        rows.push(ActivityRow {
            key: format!("p{}", pid),
            label,
            detail: if disk && *pid == 4 { "pid 4 · includes cache flushes and paging done on behalf of other processes".to_string() } else { format!("pid {}", pid) },
            who: String::new(),
            pid: *pid,
            read_bytes: a.read,
            write_bytes: a.write,
            ops: a.ops,
            spark: spark.get(pid).cloned().unwrap_or_default(),
        });
    }
    for (label, (a, s, count)) in exited {
        rows.push(ActivityRow {
            key: format!("x{}", label),
            detail: if count == 1 { "exited".to_string() } else { format!("{} short-lived instances, all exited", count) },
            label,
            who: String::new(),
            pid: 0,
            read_bytes: a.read,
            write_bytes: a.write,
            ops: a.ops,
            spark: s,
        });
    }
    rows.sort_by(|a, b| {
        (b.read_bytes + b.write_bytes)
            .cmp(&(a.read_bytes + a.write_bytes))
            .then(b.ops.cmp(&a.ops))
    });
    rows.truncate(200);
    rows
}

fn start_session() -> Result<CONTROLTRACE_HANDLE, String> {
    let name = wide(SESSION_NAME);
    let name_bytes = name.len() * 2;
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name_bytes + 64;
    let mut buf = vec![0u8; total];

    unsafe {
        let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        props.Wnode.BufferSize = total as u32;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.ClientContext = 1;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.BufferSize = 128;
        props.MinimumBuffers = 16;
        props.MaximumBuffers = 128;
        props.FlushTimer = 1;
        props.LoggerNameOffset = props_size as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            buf.as_mut_ptr().add(props_size) as *mut u16,
            name.len(),
        );

        let mut handle = CONTROLTRACE_HANDLE::default();
        let r = StartTraceW(
            &mut handle,
            PCWSTR(name.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
        );
        if r == ERROR_SUCCESS {
            return Ok(handle);
        }
        if r == ERROR_ALREADY_EXISTS {
            return Err("a Keyhole trace session is already running".into());
        }
        Err(format!("the trace session could not be started: {}", crate::sys::winerr::text(r.0)))
    }
}

fn stop_session(handle: CONTROLTRACE_HANDLE) -> WIN32_ERROR {
    let name = wide(SESSION_NAME);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name.len() * 2 + 64;
    let mut buf = vec![0u8; total];
    unsafe {
        let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        props.Wnode.BufferSize = total as u32;
        props.LoggerNameOffset = props_size as u32;
        ControlTraceW(
            handle,
            PCWSTR::null(),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        )
    }
}

fn stop_stale_session() {
    let name = wide(SESSION_NAME);
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + name.len() * 2 + 64;
    let mut buf = vec![0u8; total];
    unsafe {
        let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        props.Wnode.BufferSize = total as u32;
        props.LoggerNameOffset = props_size as u32;
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    unsafe {
        if record.is_null() {
            return;
        }
        let record = &*record;
        let ctx = record.UserContext as *const CallbackContext;
        if ctx.is_null() {
            return;
        }
        let ctx = &*ctx;

        let provider = guid_to_u128(&record.EventHeader.ProviderId);
        let is_file = provider == guid_to_u128(&KERNEL_FILE);
        let is_disk = provider == guid_to_u128(&KERNEL_DISK);
        let is_net = provider == guid_to_u128(&KERNEL_NETWORK);
        let is_proc = provider == guid_to_u128(&KERNEL_PROCESS);
        if !is_file && !is_disk && !is_net && !is_proc {
            return;
        }

        let id = record.EventHeader.EventDescriptor.Id;
        if is_proc {
            if id != EV_PROCESS_START {
                return;
            }
            let layout = ctx.schemas.lock().layout(record);
            if !layout.usable {
                return;
            }
            let decoded = decode(record, &layout);
            if let (Some(new_pid), Some(image)) = (decoded.u64("ProcessID"), decoded.text("ImageName")) {
                let name = image.rsplit('\\').next().unwrap_or(image).to_string();
                if !name.is_empty() {
                    let mut agg = ctx.agg.lock();
                    agg.remembered_names.insert(new_pid as u32, (name, std::time::Instant::now()));
                }
            }
            return;
        }
        let interesting = if is_file {
            matches!(
                id,
                EV_FILE_READ | EV_FILE_WRITE | EV_FILE_CREATE | EV_FILE_CREATE_NEW | EV_FILE_CLOSE
            )
        } else if is_disk {
            matches!(id, EV_DISK_READ | EV_DISK_WRITE)
        } else {
            NET_SEND.contains(&id) || NET_RECV.contains(&id) || NET_UDP_SEND.contains(&id) || NET_UDP_RECV.contains(&id)
        };
        if !interesting {
            return;
        }

        let layout = ctx.schemas.lock().layout(record);
        if !layout.usable {
            return;
        }
        let decoded = decode(record, &layout);
        let pid = if record.EventHeader.ProcessId == u32::MAX { 4 } else { record.EventHeader.ProcessId };

        let unknown = pid > 4 && {
            let agg = ctx.agg.lock();
            !agg.process_names.contains_key(&pid) && !agg.remembered_names.contains_key(&pid)
        };
        let fresh_name = if unknown { Some(quick_process_name(pid)) } else { None };
        let mut agg = ctx.agg.lock();
        agg.events_seen += 1;
        if let Some(name) = fresh_name {
            agg.remembered_names.entry(pid).or_insert((name, std::time::Instant::now()));
        }

        if is_file {
            match id {
                EV_FILE_CREATE | EV_FILE_CREATE_NEW => {
                    if let (Some(obj), Some(name)) =
                        (decoded.u64("FileObject"), decoded.text("FileName"))
                        && !name.is_empty() {
                            let interned = agg.names.intern(name);
                            agg.file_objects.insert(obj, interned);
                            let disposition = (decoded.u64("CreateOptions").unwrap_or(0) >> 24) & 0xff;
                            if pid > 4 && disposition != 1 {
                                agg.file_openers.insert(interned, pid);
                            }
                        }
                }
                EV_FILE_CLOSE => {}
                EV_FILE_READ | EV_FILE_WRITE => {
                    let flags = decoded.u64("IOFlags").unwrap_or(0);
                    if flags & IRP_PAGING != 0 {
                        return;
                    }
                    let size = decoded.u64("IOSize").unwrap_or(0);
                    let obj = decoded
                        .u64("FileObject")
                        .or_else(|| decoded.u64("FileKey"))
                        .unwrap_or(0);
                    let name_id = agg.file_objects.get(&obj).copied().unwrap_or(0);
                    let is_read = id == EV_FILE_READ;
                    record_io(&mut agg, pid, name_id, size, is_read);
                }
                _ => {}
            }
        } else if is_disk {
            let size = decoded
                .u64("TransferSize")
                .or_else(|| decoded.u64("IOSize"))
                .unwrap_or(0);
            let disk = decoded.u64("DiskNumber").unwrap_or(0) as u32;
            let response = decoded.u64("HighResResponseTime").unwrap_or(0);
            let is_read = id == EV_DISK_READ;
            let effective_pid = if pid == 0 || pid == 4 || pid == u32::MAX {
                let tid = decoded.u64("IssuingThreadId").map(|t| t as u32).unwrap_or(record.EventHeader.ThreadId);
                if tid != 0 && tid != u32::MAX {
                    let owner = *agg.thread_pids.entry(tid).or_insert_with(|| process_of_thread(tid));
                    if owner == 0 { 4 } else { owner }
                } else {
                    4
                }
            } else {
                pid
            };
            record_disk(&mut agg, effective_pid, disk, size, is_read, response);
        } else {
            let size = decoded
                .u64("size")
                .or_else(|| decoded.u64("NumberOfBytes"))
                .unwrap_or(0);
            let net_pid = decoded.u64("PID").map(|v| v as u32).unwrap_or(pid);
            let is_recv = NET_RECV.contains(&id) || NET_UDP_RECV.contains(&id);
            record_net(&mut agg, net_pid, size, is_recv);
        }
    }
}

fn process_of_thread(tid: u32) -> u32 {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION};
    unsafe {
        let Ok(h) = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) else {
            return 0;
        };
        let pid = GetProcessIdOfThread(h);
        let _ = CloseHandle(h);
        pid
    }
}

fn provider_label(guid: &GUID) -> &'static str {
    if *guid == KERNEL_FILE {
        "Kernel-File"
    } else if *guid == KERNEL_DISK {
        "Kernel-Disk"
    } else if *guid == KERNEL_NETWORK {
        "Kernel-Network"
    } else {
        "Kernel-Process"
    }
}

fn quick_process_name(pid: u32) -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return String::new();
        };
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = CloseHandle(h);
        if !ok {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        full.rsplit('\\').next().unwrap_or(&full).to_string()
    }
}

fn record_net(agg: &mut Aggregator, pid: u32, size: u64, is_recv: bool) {
    let bucket = agg.current();
    let p = bucket.net_procs.entry(pid).or_default();
    if is_recv {
        p.read += size;
    } else {
        p.write += size;
    }
    p.ops += 1;
}

fn record_disk(agg: &mut Aggregator, pid: u32, disk: u32, size: u64, is_read: bool, response_ticks: u64) {
    let bucket = agg.current();
    let d = bucket.disks.entry(disk).or_default();
    if is_read {
        d.read += size;
    } else {
        d.write += size;
    }
    d.ops += 1;
    d.response_ticks += response_ticks;
    let p = bucket.disk_procs.entry(pid).or_default();
    if is_read {
        p.read += size;
    } else {
        p.write += size;
    }
    p.ops += 1;
}

fn qpc_frequency() -> u64 {
    static FREQ: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *FREQ.get_or_init(|| {
        let mut f = 0i64;
        let _ = unsafe { windows::Win32::System::Performance::QueryPerformanceFrequency(&mut f) };
        if f <= 0 { 10_000_000 } else { f as u64 }
    })
}

fn build_disk_rows(info: &HashMap<u32, crate::sys::disks::DiskInfo>, acc: &HashMap<u32, DiskAcc>, spark: &HashMap<u32, Vec<u64>>) -> Vec<ActivityRow> {
    let freq = qpc_frequency() as f64;
    let mut rows: Vec<ActivityRow> = acc
        .iter()
        .filter(|(_, a)| a.ops > 0)
        .map(|(number, a)| {
            let (label, mut detail) = match info.get(number) {
                Some(i) => (crate::sys::disks::label(i), crate::sys::disks::detail(i)),
                None => (format!("Disk {}", number), String::new()),
            };
            let avg_ms = if a.ops > 0 { (a.response_ticks as f64 / a.ops as f64) / freq * 1000.0 } else { 0.0 };
            let latency = if avg_ms >= 10.0 { format!("{:.0} ms avg", avg_ms) } else { format!("{:.1} ms avg", avg_ms) };
            if detail.is_empty() {
                detail = latency;
            } else {
                detail = format!("{} · {}", detail, latency);
            }
            ActivityRow {
                key: format!("d{}", number),
                label,
                detail,
                who: String::new(),
                pid: 0,
                read_bytes: a.read,
                write_bytes: a.write,
                ops: a.ops,
                spark: spark.get(number).cloned().unwrap_or_default(),
            }
        })
        .collect();
    rows.sort_by(|a, b| (b.read_bytes + b.write_bytes).cmp(&(a.read_bytes + a.write_bytes)).then(a.label.cmp(&b.label)));
    rows
}

fn record_io(agg: &mut Aggregator, pid: u32, name_id: u32, size: u64, is_read: bool) {
    let over_capacity = agg.buckets.last().unwrap().files.len() >= MAX_KEYS;
    if over_capacity {
        agg.events_dropped += 1;
    }

    let bucket = agg.current();
    let (files, procs) = (&mut bucket.files, &mut bucket.procs);

    if !over_capacity || files.contains_key(&(pid, name_id)) {
        let e = files.entry((pid, name_id)).or_default();
        if is_read {
            e.read += size;
        } else {
            e.write += size;
        }
        e.ops += 1;
    }

    let p = procs.entry(pid).or_default();
    if is_read {
        p.read += size;
    } else {
        p.write += size;
    }
    p.ops += 1;
}
