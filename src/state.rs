use crate::etw::Activity;
use crate::model::*;
use crate::sys::detail::{DetailCache, ProcessDetail};
use crate::sys::devpath::SharedDeviceMap;
use crate::sys::handles::{Resolver, TypeTable};
use crate::sys::icons::IconCache;
use crate::sys::process::{RawProcess, build_tree, flatten, sample};
use crate::sys::{filetime_to_unix_ms, privilege, process, services};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

const DEAD_LINGER: Duration = Duration::from_millis(4000);
const NEW_HIGHLIGHT: Duration = Duration::from_millis(4000);
const SIGNATURE_BATCH: usize = 24;
const MIN_METRIC_INTERVAL: Duration = Duration::from_millis(200);
const DEVICE_REFRESH: Duration = Duration::from_secs(20);
const SERVICE_REFRESH: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Name,
    Pid,
    Cpu,
    Private,
    Working,
    Handles,
    Threads,
    Io,
    Start,
    User,
    Description,
    Company,
    Session,
    Trust,
    Path,
    Cmd,
}

impl SortKey {
    pub fn parse(s: &str) -> SortKey {
        match s {
            "pid" => SortKey::Pid,
            "cpu" => SortKey::Cpu,
            "private" => SortKey::Private,
            "working" => SortKey::Working,
            "handles" => SortKey::Handles,
            "threads" => SortKey::Threads,
            "io" => SortKey::Io,
            "start" => SortKey::Start,
            "user" => SortKey::User,
            "description" => SortKey::Description,
            "company" => SortKey::Company,
            "session" => SortKey::Session,
            "trust" => SortKey::Trust,
            "path" => SortKey::Path,
            "cmd" => SortKey::Cmd,
            _ => SortKey::Name,
        }
    }
}

pub struct ViewOptions {
    pub sort: SortKey,
    pub descending: bool,
    pub flat: bool,
    pub filter: String,
}

impl Default for ViewOptions {
    fn default() -> Self {
        ViewOptions {
            sort: SortKey::Name,
            descending: false,
            flat: false,
            filter: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct Metrics {
    pub cpu: f32,
    pub read_rate: u64,
    pub write_rate: u64,
}

struct PrevSample {
    create_time: i64,
    cpu_100ns: i64,
    read_bytes: u64,
    write_bytes: u64,
}

#[derive(Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub session: u32,
    pub create_time: i64,
    pub image_path: String,
    pub command_line: String,
}

pub struct TreeSnapshot {
    pub rows: Vec<ProcessRow>,
    pub stats: SystemStats,
    pub icon_count: usize,
    pub live_pids: Vec<u32>,
    pub procs: HashMap<u32, ProcInfo>,
}

impl TreeSnapshot {
    pub fn name_of(&self, pid: u32) -> String {
        match self.procs.get(&pid) {
            Some(p) if !p.name.is_empty() => p.name.clone(),
            _ => format!("pid {}", pid),
        }
    }

    pub fn started_at(&self, pid: u32) -> i64 {
        self.procs.get(&pid).map(|p| p.create_time).unwrap_or(0)
    }
}

pub struct App {
    pub devices: SharedDeviceMap,
    pub details: DetailCache,
    pub icons: IconCache,
    pub signatures: Arc<crate::sys::signature::SignatureCache>,
    pub versions: crate::sys::version::VersionCache,
    pub types: TypeTable,
    pub activity: Arc<Activity>,
    pub tree: ArcSwap<TreeSnapshot>,
    pub options: Mutex<ViewOptions>,
    pub collapsed: Mutex<HashSet<u32>>,
    pub paused: AtomicBool,
    pub interval_ms: std::sync::atomic::AtomicU64,
    pub elevated: bool,
    pub debug_privilege: bool,
    pub events: Mutex<Option<crate::sys::eventlog::Tail>>,
    pub(crate) resolver: Mutex<Resolver>,
    refresh_lock: Mutex<()>,
    prev: Mutex<HashMap<u32, PrevSample>>,
    prev_instant: Mutex<Instant>,
    known_pids: Mutex<HashMap<u32, (i64, Instant)>>,
    prev_procs: Mutex<Vec<RawProcess>>,
    last_metrics: Mutex<HashMap<u32, Metrics>>,
    dead_pids: Mutex<Vec<(RawProcess, Instant)>>,
    services: Mutex<(HashMap<u32, Vec<String>>, Instant)>,
    devices_refreshed: Mutex<Instant>,
    signing: Arc<AtomicBool>,
    cpu_count: u32,
    boot: Instant,
}

impl App {
    pub fn new() -> Arc<Self> {
        unsafe {
            use windows::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX, SetErrorMode};
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
        }
        let elevated = privilege::is_elevated();
        let debug_privilege = privilege::enable_debug_privilege();
        let devices = SharedDeviceMap::new();
        let activity = Activity::new(devices.clone());

        Arc::new(App {
            devices,
            details: DetailCache::new(),
            icons: IconCache::new(),
            signatures: Arc::new(crate::sys::signature::SignatureCache::new()),
            versions: crate::sys::version::VersionCache::new(),
            types: TypeTable::build(),
            activity,
            tree: ArcSwap::from_pointee(TreeSnapshot {
                rows: Vec::new(),
                stats: SystemStats::default(),
                icon_count: 1,
                live_pids: Vec::new(),
                procs: HashMap::new(),
            }),
            options: Mutex::new(ViewOptions::default()),
            collapsed: Mutex::new(HashSet::new()),
            paused: AtomicBool::new(false),
            interval_ms: std::sync::atomic::AtomicU64::new(1000),
            elevated,
            debug_privilege,
            events: Mutex::new(None),
            resolver: Mutex::new(Resolver::new()),
            refresh_lock: Mutex::new(()),
            prev: Mutex::new(HashMap::new()),
            prev_instant: Mutex::new(Instant::now()),
            known_pids: Mutex::new(HashMap::new()),
            prev_procs: Mutex::new(Vec::new()),
            last_metrics: Mutex::new(HashMap::new()),
            dead_pids: Mutex::new(Vec::new()),
            services: Mutex::new((HashMap::new(), Instant::now() - Duration::from_secs(60))),
            devices_refreshed: Mutex::new(Instant::now()),
            signing: Arc::new(AtomicBool::new(false)),
            cpu_count: crate::sys::processor_count(),
            boot: Instant::now(),
        })
    }

    pub fn refresh_tree(&self) {
        let _guard = self.refresh_lock.lock();
        let paused = self.paused.load(Ordering::Relaxed);
        let now = Instant::now();
        let procs = if paused { self.prev_procs.lock().clone() } else { sample(false) };
        if procs.is_empty() {
            return;
        }

        if !paused {
            self.refresh_periodic(now);
        }
        let service_map = self.services.lock().0.clone();

        let live_keys: Vec<(u32, i64)> = procs.iter().map(|p| (p.pid, p.create_time)).collect();
        let live_set: HashSet<u32> = procs.iter().map(|p| p.pid).collect();

        let mut known = self.known_pids.lock();
        if !paused {
            self.track_lifetimes(&procs, &live_set, now, &mut known);
        }

        let mut all: Vec<RawProcess> = procs.clone();
        for (d, _) in self.dead_pids.lock().iter() {
            if !live_set.contains(&d.pid) {
                all.push(d.clone());
            }
        }

        let metrics = if paused { self.last_metrics.lock().clone() } else { self.update_metrics(&procs, now) };

        let details: HashMap<u32, ProcessDetail> = all
            .iter()
            .map(|p| (p.pid, self.details.get(p.pid, p.create_time, false)))
            .collect();

        let view = {
            let o = self.options.lock();
            ViewOptions { sort: o.sort, descending: o.descending, flat: o.flat, filter: o.filter.clone() }
        };
        let collapsed = self.collapsed.lock().clone();
        let rows = self.build_rows(&all, &live_set, &metrics, &details, &service_map, &known, now, &view, &collapsed);
        if !paused {
            self.warm_signatures(&details);
        }
        drop(known);

        if !paused {
            *self.prev_procs.lock() = procs.clone();
            self.details.prune(&live_keys);
            self.activity.set_process_names(procs.iter().map(|p| (p.pid, p.name.clone())).collect());
        }

        let inaccessible = procs.iter().filter(|p| p.pid != 0 && !details.get(&p.pid).map(|d| d.accessible).unwrap_or(true)).count() as u32;
        let stats = self.stats(&procs, &metrics, inaccessible);
        let proc_map: HashMap<u32, ProcInfo> = procs
            .iter()
            .map(|p| {
                let d = details.get(&p.pid);
                (
                    p.pid,
                    ProcInfo {
                        pid: p.pid,
                        ppid: p.ppid,
                        name: p.name.clone(),
                        session: p.session,
                        create_time: p.create_time,
                        image_path: d.map(|d| d.image_path.clone()).unwrap_or_default(),
                        command_line: d.map(|d| d.command_line.clone()).unwrap_or_default(),
                    },
                )
            })
            .collect();

        self.tree.store(Arc::new(TreeSnapshot {
            rows,
            stats,
            icon_count: self.icons.len(),
            live_pids: procs.iter().map(|p| p.pid).collect(),
            procs: proc_map,
        }));
    }

    fn warm_signatures(&self, details: &HashMap<u32, ProcessDetail>) {
        if self.signing.load(Ordering::Relaxed) {
            return;
        }
        let mut seen = HashSet::new();
        let mut pending: Vec<String> = details
            .values()
            .map(|d| d.image_path.clone())
            .filter(|p| !p.is_empty() && self.signatures.peek(p).is_none())
            .filter(|p| seen.insert(p.to_lowercase()))
            .collect();
        if pending.is_empty() {
            return;
        }
        pending.truncate(SIGNATURE_BATCH);
        self.signing.store(true, Ordering::Relaxed);
        let flag = self.signing.clone();
        let signatures = self.signatures.clone();
        struct Reset(Arc<AtomicBool>);
        impl Drop for Reset {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let spawned = std::thread::Builder::new().name("keyhole-signatures".into()).spawn({
            let flag = flag.clone();
            move || {
                let _reset = Reset(flag);
                unsafe {
                    let _ = windows::Win32::System::Threading::SetThreadPriority(
                        windows::Win32::System::Threading::GetCurrentThread(),
                        windows::Win32::System::Threading::THREAD_MODE_BACKGROUND_BEGIN,
                    );
                }
                for p in &pending {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| signatures.get(p)));
                }
            }
        });
        if spawned.is_err() {
            flag.store(false, Ordering::Relaxed);
        }
    }

    fn refresh_periodic(&self, now: Instant) {
        let mut svc = self.services.lock();
        if now.duration_since(svc.1) > SERVICE_REFRESH {
            svc.0 = services::by_pid();
            svc.1 = now;
        }
        drop(svc);
        let mut dev = self.devices_refreshed.lock();
        if now.duration_since(*dev) > DEVICE_REFRESH {
            self.devices.refresh();
            *dev = now;
        }
    }

    fn track_lifetimes(&self, procs: &[RawProcess], live_set: &HashSet<u32>, now: Instant, known: &mut HashMap<u32, (i64, Instant)>) {
        let prev_procs = self.prev_procs.lock();
        let mut dead = self.dead_pids.lock();
        for old in prev_procs.iter() {
            if !live_set.contains(&old.pid) && !dead.iter().any(|(d, _)| d.pid == old.pid) {
                dead.push((old.clone(), now));
            }
        }
        let linger = DEAD_LINGER.max(Duration::from_millis(self.refresh_interval_ms() * 2 + 500));
        dead.retain(|(_, t)| now.duration_since(*t) < linger);
        for p in procs {
            let k = known.entry(p.pid).or_insert((p.create_time, now));
            if k.0 != p.create_time {
                *k = (p.create_time, now);
            }
        }
        known.retain(|pid, _| live_set.contains(pid));
    }

    fn update_metrics(&self, procs: &[RawProcess], now: Instant) -> HashMap<u32, Metrics> {
        let mut prev_instant = self.prev_instant.lock();
        let elapsed = now.duration_since(*prev_instant);
        let mut prev = self.prev.lock();
        if elapsed < MIN_METRIC_INTERVAL && !prev.is_empty() {
            return self.last_metrics.lock().clone();
        }
        *prev_instant = now;
        let secs = elapsed.as_secs_f64().max(0.001);
        let mut m = HashMap::new();
        for p in procs {
            let (cpu, read_rate, write_rate) = match prev.get(&p.pid).filter(|pv| pv.create_time == p.create_time) {
                Some(pv) => {
                    let d = (p.cpu_100ns - pv.cpu_100ns).max(0) as f64;
                    (
                        ((d / 10_000_000.0) / secs / self.cpu_count as f64 * 100.0) as f32,
                        (p.read_bytes.saturating_sub(pv.read_bytes) as f64 / secs) as u64,
                        (p.write_bytes.saturating_sub(pv.write_bytes) as f64 / secs) as u64,
                    )
                }
                None => (0.0, 0, 0),
            };
            m.insert(p.pid, Metrics { cpu, read_rate, write_rate });
        }
        prev.clear();
        for p in procs {
            prev.insert(p.pid, PrevSample { create_time: p.create_time, cpu_100ns: p.cpu_100ns, read_bytes: p.read_bytes, write_bytes: p.write_bytes });
        }
        *self.last_metrics.lock() = m.clone();
        m
    }

    fn stats(&self, procs: &[RawProcess], metrics: &HashMap<u32, Metrics>, inaccessible: u32) -> SystemStats {
        let mut mem = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        let _ = unsafe { GlobalMemoryStatusEx(&mut mem) };
        let total_cpu: f32 = procs
            .iter()
            .filter(|p| p.pid != 0)
            .filter_map(|p| metrics.get(&p.pid).map(|m| m.cpu))
            .sum();
        SystemStats {
            processes: procs.len() as u32,
            threads: procs.iter().map(|p| p.thread_count).sum(),
            handles: procs.iter().map(|p| p.handles).sum(),
            inaccessible,
            cpu: total_cpu.min(100.0),
            mem_used: mem.ullTotalPhys.saturating_sub(mem.ullAvailPhys),
            mem_total: mem.ullTotalPhys,
            debug_privilege: self.debug_privilege,
            etw_active: self.activity.is_running(),
            etw_note: self.activity.last_error(),
        }
    }

    fn build_rows(
        &self,
        all: &[RawProcess],
        live_set: &HashSet<u32>,
        metrics: &HashMap<u32, Metrics>,
        details: &HashMap<u32, ProcessDetail>,
        service_map: &HashMap<u32, Vec<String>>,
        known: &HashMap<u32, (i64, Instant)>,
        now: Instant,
        opts: &ViewOptions,
        collapsed: &HashSet<u32>,
    ) -> Vec<ProcessRow> {
        let (children, roots) = build_tree(all);
        let order_key = opts.sort;
        let desc = opts.descending;
        let filter = opts.filter.trim().to_lowercase();
        let flat = opts.flat;
        let filtering = !filter.is_empty();

        let empty = ProcessDetail::default();
        let detail_of = |pid: u32| details.get(&pid).unwrap_or(&empty);
        let user_of = |pid: u32| detail_of(pid).user.to_lowercase();
        let version_keys: HashMap<u32, (String, String)> = if matches!(order_key, SortKey::Description | SortKey::Company) {
            all.iter()
                .map(|p| {
                    let v = self.versions.get(&detail_of(p.pid).image_path);
                    (p.pid, (v.description.to_lowercase(), v.company.to_lowercase()))
                })
                .collect()
        } else {
            HashMap::new()
        };
        let order = |list: &mut Vec<usize>| {
            list.sort_by(|&a, &b| {
                let pa = &all[a];
                let pb = &all[b];
                let ma = metrics.get(&pa.pid);
                let mb = metrics.get(&pb.pid);
                let ord = match order_key {
                    SortKey::Pid => pa.pid.cmp(&pb.pid),
                    SortKey::Handles => pa.handles.cmp(&pb.handles),
                    SortKey::Threads => pa.thread_count.cmp(&pb.thread_count),
                    SortKey::Private => pa.private_bytes.cmp(&pb.private_bytes),
                    SortKey::Working => pa.working_set.cmp(&pb.working_set),
                    SortKey::Start => pa.create_time.cmp(&pb.create_time),
                    SortKey::Cpu => ma.map(|m| m.cpu).unwrap_or(0.0).total_cmp(&mb.map(|m| m.cpu).unwrap_or(0.0)),
                    SortKey::Io => ma
                        .map(|m| m.read_rate + m.write_rate)
                        .unwrap_or(0)
                        .cmp(&mb.map(|m| m.read_rate + m.write_rate).unwrap_or(0)),
                    SortKey::User => user_of(pa.pid).cmp(&user_of(pb.pid)),
                    SortKey::Session => pa.session.cmp(&pb.session),
                    SortKey::Path => detail_of(pa.pid).image_path.to_lowercase().cmp(&detail_of(pb.pid).image_path.to_lowercase()),
                    SortKey::Cmd => detail_of(pa.pid).command_line.to_lowercase().cmp(&detail_of(pb.pid).command_line.to_lowercase()),
                    SortKey::Trust => {
                        let t = |pid: u32| self.signatures.peek(&detail_of(pid).image_path).map(|t| t.label()).unwrap_or("");
                        t(pa.pid).cmp(t(pb.pid))
                    }
                    SortKey::Description | SortKey::Company => {
                        let pick = |pid: u32| {
                            version_keys
                                .get(&pid)
                                .map(|v| if order_key == SortKey::Description { v.0.as_str() } else { v.1.as_str() })
                                .unwrap_or("")
                        };
                        let (a, b) = (pick(pa.pid), pick(pb.pid));
                        if desc {
                            b.is_empty().cmp(&a.is_empty()).then(a.cmp(b))
                        } else {
                            a.is_empty().cmp(&b.is_empty()).then(a.cmp(b))
                        }
                    }
                    _ => pa.name.to_lowercase().cmp(&pb.name.to_lowercase()),
                };
                let ord = ord.then(pa.pid.cmp(&pb.pid));
                if desc { ord.reverse() } else { ord }
            });
        };

        let flat_list = if flat {
            let mut idx: Vec<usize> = (0..all.len()).collect();
            order(&mut idx);
            idx.into_iter().map(|i| (i, 0u32, 0u32, 0u32)).collect()
        } else {
            flatten(&children, &roots, &order, |i| filtering || !collapsed.contains(&all[i].pid))
        };

        let matches = |p: &RawProcess| -> bool {
            if !filtering {
                return true;
            }
            let detail = detail_of(p.pid);
            if let Some(sid) = filter.strip_prefix("session:") {
                return sid.trim().parse::<u32>().ok() == Some(p.session);
            }
            if let Some(u) = filter.strip_prefix("user:") {
                return detail.user.to_lowercase().contains(u.trim());
            }
            if let Some(pid) = filter.strip_prefix("pid:") {
                return pid.trim().parse::<u32>().ok() == Some(p.pid);
            }
            let name = if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.to_lowercase() };
            name.contains(&filter)
                || p.pid.to_string().contains(&filter)
                || detail.image_path.to_lowercase().contains(&filter)
                || detail.command_line.to_lowercase().contains(&filter)
        };
        let matched: Vec<bool> = flat_list.iter().map(|(i, _, _, _)| matches(&all[*i])).collect();
        let mut context = vec![false; flat_list.len()];
        if filtering && !flat_list.is_empty() {
            let mut stack: Vec<(usize, u32)> = Vec::new();
            for (pos, (_, depth, _, _)) in flat_list.iter().enumerate() {
                while let Some(&(_, d)) = stack.last() {
                    if d >= *depth { stack.pop(); } else { break; }
                }
                if matched[pos] {
                    for &(anc, _) in &stack {
                        context[anc] = true;
                    }
                }
                stack.push((pos, *depth));
            }
        }

        let mut rows = Vec::with_capacity(flat_list.len());
        for (pos, (index, depth, kids, hidden)) in flat_list.into_iter().enumerate() {
            if !matched[pos] && !context[pos] {
                continue;
            }
            let p = &all[index];
            let is_dead = !live_set.contains(&p.pid);
            let detail = detail_of(p.pid);
            let (cpu, read_rate, write_rate) = metrics.get(&p.pid).map(|m| (m.cpu, m.read_rate, m.write_rate)).unwrap_or((0.0, 0, 0));
            let first_seen = known.get(&p.pid).map(|k| k.1).unwrap_or(now);
            let highlight = NEW_HIGHLIGHT.max(Duration::from_millis(self.refresh_interval_ms() * 2 + 500));
            let state = if is_dead {
                LifeState::Dead
            } else if now.duration_since(first_seen) < highlight && self.boot.elapsed() > NEW_HIGHLIGHT {
                LifeState::New
            } else {
                LifeState::Normal
            };
            let access = if p.pid == 0 || p.pid == 4 || !detail.protection.is_empty() {
                Access::Protected
            } else if !detail.accessible {
                Access::Denied
            } else if !detail.handles_readable {
                Access::Partial
            } else {
                Access::Full
            };
            let icon = if detail.image_path.is_empty() { 0 } else { self.icons.id_for(&detail.image_path) };
            let ver = self.versions.get(&detail.image_path);
            rows.push(ProcessRow {
                pid: p.pid,
                ppid: p.ppid,
                depth,
                name: if p.name.is_empty() { format!("pid {}", p.pid) } else { p.name.clone() },
                image_path: detail.image_path.clone(),
                command_line: detail.command_line.clone(),
                user: detail.user.clone(),
                session: p.session,
                integrity: detail.integrity.clone(),
                elevated: detail.elevated,
                arch: detail.arch.clone(),
                start_time: filetime_to_unix_ms(p.create_time),
                cpu,
                private_bytes: p.private_bytes,
                working_set: p.working_set,
                handle_count: p.handles,
                thread_count: p.thread_count,
                read_rate,
                write_rate,
                read_total: p.read_bytes,
                write_total: p.write_bytes,
                state,
                suspended: p.suspended,
                critical: detail.critical,
                access,
                access_note: detail.note.clone(),
                protection: detail.protection.clone(),
                icon,
                children: kids,
                collapsed_descendants: hidden,
                service_names: service_map.get(&p.pid).cloned().unwrap_or_default(),
                description: ver.description,
                company: ver.company,
                trust: self.signatures.peek(&detail.image_path).map(|t| t.label().to_string()).unwrap_or_default(),
                filter_context: !matched[pos],
            });
        }
        rows
    }

    pub fn full_rows(&self) -> Vec<ProcessRow> {
        let _guard = self.refresh_lock.lock();
        let procs = self.prev_procs.lock().clone();
        if procs.is_empty() {
            return Vec::new();
        }
        let live_set: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
        let metrics = self.last_metrics.lock().clone();
        let details: HashMap<u32, ProcessDetail> = procs.iter().map(|p| (p.pid, self.details.get(p.pid, p.create_time, false))).collect();
        let service_map = self.services.lock().0.clone();
        let known = self.known_pids.lock().clone();
        let view = ViewOptions { sort: SortKey::Name, descending: false, flat: false, filter: String::new() };
        self.build_rows(&procs, &live_set, &metrics, &details, &service_map, &known, Instant::now(), &view, &HashSet::new())
    }

    pub fn threads_for(&self, pid: u32) -> Vec<ThreadRow> {
        let procs = process::sample(true);
        let Some(p) = procs.iter().find(|p| p.pid == pid) else {
            return Vec::new();
        };
        let mods = crate::sys::modules::list(pid).unwrap_or_default();
        let mut rows: Vec<ThreadRow> = p
            .threads
            .iter()
            .map(|t| {
                let win32 = process::win32_start_address(t.tid);
                let start_address = if win32 != 0 { win32 } else { t.start_address };
                let start_module = mods
                    .iter()
                    .find(|m| m.size > 0 && start_address >= m.base && start_address < m.base + m.size)
                    .map(|m| format!("{}+0x{:X}", m.name, start_address - m.base))
                    .unwrap_or_default();
                ThreadRow {
                    tid: t.tid,
                    start_address,
                    start_module,
                    priority: t.priority,
                    state: thread_state(t.state, t.wait_reason),
                    cpu_time_ms: (t.cpu_100ns / 10_000).max(0) as u64,
                    created: filetime_to_unix_ms(t.create_time),
                }
            })
            .collect();
        rows.sort_by(|a, b| b.cpu_time_ms.cmp(&a.cpu_time_ms).then(a.tid.cmp(&b.tid)));
        rows
    }

    pub fn refresh_interval_ms(&self) -> u64 {
        self.interval_ms.load(Ordering::Relaxed)
    }

    pub fn set_refresh_interval_ms(&self, ms: u64) {
        self.interval_ms.store(ms, Ordering::Relaxed);
    }

    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let tree = self.tree.load();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in tree.procs.values() {
            if p.pid != p.ppid {
                children.entry(p.ppid).or_default().push(p.pid);
            }
        }
        let start_time = tree.procs.get(&pid).map(|p| p.create_time).unwrap_or(0);
        let mut out = vec![pid];
        let mut stack = vec![pid];
        let mut seen: HashSet<u32> = HashSet::from([pid]);
        while let Some(p) = stack.pop() {
            if let Some(kids) = children.get(&p) {
                for &k in kids {
                    let child_ok = tree.procs.get(&k).map(|c| c.create_time >= start_time).unwrap_or(false);
                    if child_ok && seen.insert(k) {
                        out.push(k);
                        stack.push(k);
                    }
                }
            }
        }
        out
    }
}

pub fn type_rank(type_name: &str) -> u8 {
    match type_name {
        "File" => 0,
        "Key" => 1,
        "Directory" => 2,
        "Section" => 3,
        "SymbolicLink" => 4,
        "Process" => 5,
        "Thread" => 6,
        "Token" => 7,
        "Job" => 8,
        "Mutant" => 9,
        "Semaphore" => 10,
        "Event" => 11,
        "ALPC Port" => 12,
        _ => 13,
    }
}

fn thread_state(state: u32, wait_reason: u32) -> String {
    let base = match state {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        4 => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        _ => "Unknown",
    };
    if state != 5 {
        return base.to_string();
    }
    if wait_reason == 5 || wait_reason == 12 {
        return "Suspended".to_string();
    }
    let reason = match wait_reason {
        0 | 7 => "kernel call",
        1 | 8 => "free page",
        2 | 9 => "page in",
        3 | 10 => "pool allocation",
        4 | 11 => "sleep / delay",
        6 | 13 => "user request",
        14 => "spin lock",
        15 => "work queue",
        16 => "LPC receive",
        17 => "LPC reply",
        18 => "virtual memory",
        19 => "page out",
        20 => "rendezvous",
        21 => "keyed event",
        22 => "terminated",
        23 => "process in swap",
        24 => "CPU rate control",
        25 => "callout stack",
        26 => "kernel",
        27 => "resource",
        28 => "push lock",
        29 => "mutex",
        30 => "quantum end",
        31 => "dispatch interrupt",
        32 => "preempted",
        33 => "yield",
        34 => "fast mutex",
        35 => "guarded mutex",
        36 => "rundown",
        37 => "ALPC",
        38 => "deferred preempt",
        39 => "physical fault",
        40 => "I/O ring",
        41 => "MDL cache",
        _ => "",
    };
    if reason.is_empty() { base.to_string() } else { format!("Waiting ({})", reason) }
}
