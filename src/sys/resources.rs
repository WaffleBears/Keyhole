use super::wide;
use crate::nt::{
    NtQuerySystemInformation, SYSTEM_MEMORY_LIST_INFORMATION, SYSTEM_PAGEFILE_INFORMATION, SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION,
    SystemMemoryListInformation, SystemPagefileInformation, SystemProcessorPerformanceInformation, nt_ok,
};
use std::collections::HashMap;
use std::time::Instant;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows::Win32::System::Ioctl::{DISK_PERFORMANCE, IOCTL_DISK_PERFORMANCE};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::core::PCWSTR;

#[derive(Clone, Debug, Default)]
pub struct CoreSample {
    pub index: u32,
    pub usage: f32,
    pub kernel: f32,
}

#[derive(Clone, Debug, Default)]
pub struct MemInfo {
    pub total: u64,
    pub avail: u64,
    pub in_use: u64,
    pub standby: u64,
    pub modified: u64,
    pub free: u64,
    pub cached: u64,
    pub paged_pool: u64,
    pub nonpaged_pool: u64,
    pub commit_used: u64,
    pub commit_limit: u64,
    pub commit_peak: u64,
    pub handles: u32,
    pub processes: u32,
    pub threads: u32,
}

#[derive(Clone, Debug, Default)]
pub struct PageFile {
    pub path: String,
    pub total: u64,
    pub used: u64,
    pub peak: u64,
}

#[derive(Clone, Debug, Default)]
pub struct NicSample {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub up: bool,
    pub speed: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub rx_total: u64,
    pub tx_total: u64,
    pub errors: u64,
    pub discards: u64,
    pub new_errors: u64,
    pub address: String,
}

#[derive(Clone, Debug, Default)]
pub struct DiskSample {
    pub number: u32,
    pub label: String,
    pub busy: f32,
    pub read_rate: u64,
    pub write_rate: u64,
    pub read_latency_ms: f32,
    pub write_latency_ms: f32,
    pub queue: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub cpu: f32,
    pub kernel: f32,
    pub cores: Vec<CoreSample>,
    pub mem: MemInfo,
    pub pagefiles: Vec<PageFile>,
    pub nics: Vec<NicSample>,
    pub disks: Vec<DiskSample>,
    pub uptime_ms: u64,
}

#[derive(Clone, Copy, Default)]
struct CpuRaw {
    idle: i64,
    kernel: i64,
    user: i64,
}

#[derive(Clone, Copy, Default)]
struct NicRaw {
    rx: u64,
    tx: u64,
    errors: u64,
}

#[derive(Clone, Copy, Default)]
struct DiskRaw {
    read_bytes: i64,
    write_bytes: i64,
    read_time: i64,
    write_time: i64,
    idle_time: i64,
    reads: u32,
    writes: u32,
    at: i64,
}

pub struct Sampler {
    cpu: Vec<CpuRaw>,
    nics: HashMap<u64, NicRaw>,
    disks: HashMap<u32, DiskRaw>,
    at: Option<Instant>,
    addresses: HashMap<u64, String>,
    addresses_at: Option<Instant>,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

fn cpu_raw() -> Vec<CpuRaw> {
    unsafe {
        let mut buf = vec![SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION::default(); 1024];
        let mut len = 0u32;
        let status = NtQuerySystemInformation(SystemProcessorPerformanceInformation, buf.as_mut_ptr() as *mut _, (buf.len() * std::mem::size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>()) as u32, &mut len);
        if !nt_ok(status) {
            return Vec::new();
        }
        let n = len as usize / std::mem::size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>();
        buf.iter().take(n).map(|p| CpuRaw { idle: p.IdleTime, kernel: p.KernelTime, user: p.UserTime }).collect()
    }
}

fn memory() -> MemInfo {
    let mut m = MemInfo::default();
    unsafe {
        let mut ms = MEMORYSTATUSEX { dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
        if GlobalMemoryStatusEx(&mut ms).is_ok() {
            m.total = ms.ullTotalPhys;
            m.avail = ms.ullAvailPhys;
        }
        let mut pi = PERFORMANCE_INFORMATION { cb: std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32, ..Default::default() };
        if GetPerformanceInfo(&mut pi, pi.cb).is_ok() {
            let page = pi.PageSize as u64;
            m.commit_used = pi.CommitTotal as u64 * page;
            m.commit_limit = pi.CommitLimit as u64 * page;
            m.commit_peak = pi.CommitPeak as u64 * page;
            m.paged_pool = pi.KernelPaged as u64 * page;
            m.nonpaged_pool = pi.KernelNonpaged as u64 * page;
            m.handles = pi.HandleCount;
            m.processes = pi.ProcessCount;
            m.threads = pi.ThreadCount;
            if m.total == 0 {
                m.total = pi.PhysicalTotal as u64 * page;
                m.avail = pi.PhysicalAvailable as u64 * page;
            }
            let mut ml = SYSTEM_MEMORY_LIST_INFORMATION::default();
            let mut len = 0u32;
            if nt_ok(NtQuerySystemInformation(SystemMemoryListInformation, &mut ml as *mut _ as *mut _, std::mem::size_of::<SYSTEM_MEMORY_LIST_INFORMATION>() as u32, &mut len)) {
                m.standby = ml.PageCountByPriority.iter().sum::<usize>() as u64 * page;
                m.modified = (ml.ModifiedPageCount + ml.ModifiedNoWritePageCount) as u64 * page;
                m.free = (ml.FreePageCount + ml.ZeroPageCount) as u64 * page;
            }
        }
    }
    m.in_use = m.total.saturating_sub(m.avail);
    m.cached = m.standby + m.modified;
    m
}

fn pagefiles() -> Vec<PageFile> {
    let mut out = Vec::new();
    unsafe {
        let mut buf = vec![0u8; 64 * 1024];
        let mut len = 0u32;
        if !nt_ok(NtQuerySystemInformation(SystemPagefileInformation, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut len)) || len == 0 {
            return out;
        }
        let page = 4096u64;
        let map = super::devpath::DeviceMap::build();
        let mut offset = 0usize;
        loop {
            if offset + std::mem::size_of::<SYSTEM_PAGEFILE_INFORMATION>() > buf.len() {
                break;
            }
            let p = &*(buf.as_ptr().add(offset) as *const SYSTEM_PAGEFILE_INFORMATION);
            let nt = p.PageFileName.to_string();
            let path = map.translate(&nt);
            out.push(PageFile { path: if path.is_empty() { nt } else { path }, total: p.TotalSize as u64 * page, used: p.TotalInUse as u64 * page, peak: p.PeakUsage as u64 * page });
            if p.NextEntryOffset == 0 {
                break;
            }
            offset += p.NextEntryOffset as usize;
        }
    }
    out
}

fn disk_perf(number: u32) -> Option<DISK_PERFORMANCE> {
    let path = wide(&format!("\\\\.\\PhysicalDrive{}", number));
    unsafe {
        let h: HANDLE = CreateFileW(PCWSTR(path.as_ptr()), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, Default::default(), None).ok()?;
        let mut perf = DISK_PERFORMANCE::default();
        let mut got = 0u32;
        let ok = DeviceIoControl(h, IOCTL_DISK_PERFORMANCE, None, 0, Some(&mut perf as *mut _ as *mut _), std::mem::size_of::<DISK_PERFORMANCE>() as u32, Some(&mut got), None).is_ok();
        let _ = CloseHandle(h);
        if ok { Some(perf) } else { None }
    }
}

fn nic_kind(if_type: u32) -> &'static str {
    super::netconfig::kind_name(if_type)
}

impl Sampler {
    pub fn new() -> Self {
        let mut s = Sampler { cpu: Vec::new(), nics: HashMap::new(), disks: HashMap::new(), at: None, addresses: HashMap::new(), addresses_at: None };
        s.cpu = cpu_raw();
        s.nics = nic_raw();
        s.disks = disk_raw();
        s.at = Some(Instant::now());
        s
    }

    fn refresh_addresses(&mut self) {
        if self.addresses_at.map(|t| t.elapsed().as_secs() < 60).unwrap_or(false) {
            return;
        }
        self.addresses = super::netconfig::adapters().into_iter().map(|a| (a.luid, a.ipv4.first().or(a.ipv6.first()).map(|s| s.split('/').next().unwrap_or("").to_string()).unwrap_or_default())).collect();
        self.addresses_at = Some(Instant::now());
    }

    pub fn sample(&mut self) -> Snapshot {
        let now = Instant::now();
        let elapsed = self.at.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0).max(0.001);
        let mut snap = Snapshot { uptime_ms: unsafe { GetTickCount64() }, ..Default::default() };
        let cpu = cpu_raw();
        let mut total_busy = 0.0f64;
        let mut total_kernel = 0.0f64;
        let mut counted = 0.0f64;
        for (i, raw) in cpu.iter().enumerate() {
            let prev = self.cpu.get(i).copied().unwrap_or_default();
            let idle = (raw.idle - prev.idle).max(0) as f64;
            let kernel = (raw.kernel - prev.kernel).max(0) as f64;
            let user = (raw.user - prev.user).max(0) as f64;
            let all = kernel + user;
            let (usage, kernel_pct) = if all > 0.0 && self.at.is_some() { (((all - idle) / all * 100.0).clamp(0.0, 100.0), ((kernel - idle) / all * 100.0).clamp(0.0, 100.0)) } else { (0.0, 0.0) };
            total_busy += usage;
            total_kernel += kernel_pct;
            counted += 1.0;
            snap.cores.push(CoreSample { index: i as u32, usage: usage as f32, kernel: kernel_pct as f32 });
        }
        if counted > 0.0 {
            snap.cpu = (total_busy / counted) as f32;
            snap.kernel = (total_kernel / counted) as f32;
        }
        self.cpu = cpu;
        snap.mem = memory();
        snap.pagefiles = pagefiles();
        self.refresh_addresses();
        let (nics, raw) = nic_samples(&self.nics, elapsed, &self.addresses);
        snap.nics = nics;
        self.nics = raw;
        let (disks, raw) = disk_samples(&self.disks, elapsed);
        snap.disks = disks;
        self.disks = raw;
        self.at = Some(now);
        snap
    }
}

fn nic_raw() -> HashMap<u64, NicRaw> {
    nic_samples(&HashMap::new(), 1.0, &HashMap::new()).1
}

fn nic_samples(prev: &HashMap<u64, NicRaw>, elapsed: f64, addresses: &HashMap<u64, String>) -> (Vec<NicSample>, HashMap<u64, NicRaw>) {
    let mut out = Vec::new();
    let mut raw = HashMap::new();
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut table).0 != 0 || table.is_null() {
            return (out, raw);
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for r in rows {
            let hardware = r.InterfaceAndOperStatusFlags._bitfield & 1 != 0;
            let filter = r.InterfaceAndOperStatusFlags._bitfield & 2 != 0;
            let moved = r.InOctets > 0 || r.OutOctets > 0;
            if r.Type == 24 || filter || (!hardware && !moved) {
                continue;
            }
            let key = r.InterfaceLuid.Value;
            let cur = NicRaw { rx: r.InOctets, tx: r.OutOctets, errors: r.InErrors + r.OutErrors };
            raw.insert(key, cur);
            let p = prev.get(&key).copied();
            let rate = |now: u64, before: Option<u64>| before.map(|b| ((now.saturating_sub(b)) as f64 / elapsed) as u64).unwrap_or(0);
            let alias = super::from_wide(&r.Alias);
            let description = super::from_wide(&r.Description);
            out.push(NicSample {
                name: if alias.is_empty() { description.clone() } else { alias },
                description,
                kind: nic_kind(r.Type).to_string(),
                up: r.OperStatus.0 == 1,
                speed: if r.TransmitLinkSpeed == u64::MAX { 0 } else { r.TransmitLinkSpeed },
                rx_rate: rate(cur.rx, p.map(|p| p.rx)),
                tx_rate: rate(cur.tx, p.map(|p| p.tx)),
                rx_total: cur.rx,
                tx_total: cur.tx,
                errors: cur.errors,
                discards: r.InDiscards + r.OutDiscards,
                new_errors: p.map(|p| cur.errors.saturating_sub(p.errors)).unwrap_or(0),
                address: addresses.get(&key).cloned().unwrap_or_default(),
            });
        }
        FreeMibTable(table as *const _);
    }
    out.sort_by(|a, b| (!a.up).cmp(&!b.up).then((b.rx_rate + b.tx_rate).cmp(&(a.rx_rate + a.tx_rate))).then(a.name.cmp(&b.name)));
    (out, raw)
}

fn disk_raw() -> HashMap<u32, DiskRaw> {
    disk_samples(&HashMap::new(), 1.0).1
}

fn disk_samples(prev: &HashMap<u32, DiskRaw>, elapsed: f64) -> (Vec<DiskSample>, HashMap<u32, DiskRaw>) {
    let mut out = Vec::new();
    let mut raw = HashMap::new();
    let disks = super::disks::map();
    let mut numbers: Vec<u32> = disks.keys().copied().collect();
    numbers.sort();
    for n in numbers {
        let Some(perf) = disk_perf(n) else { continue };
        let cur = DiskRaw { read_bytes: perf.BytesRead, write_bytes: perf.BytesWritten, read_time: perf.ReadTime, write_time: perf.WriteTime, idle_time: perf.IdleTime, reads: perf.ReadCount, writes: perf.WriteCount, at: perf.QueryTime };
        raw.insert(n, cur);
        let info = &disks[&n];
        let letters = info.letters.join(" ");
        let label = if letters.is_empty() { format!("Disk {}", n) } else { format!("Disk {}  {}", n, letters) };
        let mut s = DiskSample { number: n, label, queue: perf.QueueDepth, ..Default::default() };
        if let Some(p) = prev.get(&n) {
            let span = (cur.at - p.at).max(1) as f64;
            let idle = (cur.idle_time - p.idle_time).max(0) as f64;
            s.busy = ((1.0 - idle / span) * 100.0).clamp(0.0, 100.0) as f32;
            s.read_rate = ((cur.read_bytes - p.read_bytes).max(0) as f64 / elapsed) as u64;
            s.write_rate = ((cur.write_bytes - p.write_bytes).max(0) as f64 / elapsed) as u64;
            let reads = cur.reads.wrapping_sub(p.reads) as f64;
            let writes = cur.writes.wrapping_sub(p.writes) as f64;
            if reads > 0.0 {
                s.read_latency_ms = ((cur.read_time - p.read_time).max(0) as f64 / reads / 10_000.0) as f32;
            }
            if writes > 0.0 {
                s.write_latency_ms = ((cur.write_time - p.write_time).max(0) as f64 / writes / 10_000.0) as f32;
            }
        }
        out.push(s);
    }
    (out, raw)
}
