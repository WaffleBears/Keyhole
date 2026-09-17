use super::format::*;
use super::{Shared, model, spawn, ss, ui};
use crate::{BarRow, Metric};
use keyhole::api;
use keyhole::sys::resources::{DiskSample, NicSample, Sampler, Snapshot};
use std::sync::{Arc, Mutex};

const SLOTS: usize = 90;

#[derive(Default)]
pub struct ResourcesState {
    pub sampler: Option<Arc<Mutex<Sampler>>>,
    pub last: Option<Snapshot>,
    pub cpu: Vec<f32>,
    pub kernel: Vec<f32>,
    pub mem: Vec<f32>,
    pub commit: Vec<f32>,
    pub token: u64,
    pub busy: bool,
}

fn metric(label: &str, value: String, tone: i32) -> Metric {
    Metric { label: ss(label), value: ss(&value), tone }
}

fn push(v: &mut Vec<f32>, x: f32) {
    v.push(x);
    if v.len() > SLOTS {
        let extra = v.len() - SLOTS;
        v.drain(..extra);
    }
}

fn padded(v: &[f32]) -> Vec<f32> {
    let first = v.first().copied().unwrap_or(0.0) / 100.0;
    let mut out = vec![first; SLOTS.saturating_sub(v.len())];
    out.extend(v.iter().map(|x| x / 100.0));
    out
}

fn bar(label: &str, value: String, sub: String, fraction: f32, tone: i32, tip: String) -> BarRow {
    BarRow { label: ss(label), value: ss(&value), sub: ss(&sub), fraction, tone, tip: ss(&tip) }
}

fn pct_tone(p: f32) -> i32 {
    if p >= 90.0 { 4 } else if p >= 70.0 { 3 } else { 0 }
}

pub fn enter_resources(ctx: &Shared) {
    let fresh = ctx.st.borrow().resources.sampler.is_none();
    if fresh {
        ctx.st.borrow_mut().resources.sampler = Some(Arc::new(Mutex::new(api::resources_sampler())));
    }
    let u = ui(ctx);
    u.set_res_metrics(model(vec![metric("CPU", "sampling".into(), 1)]));
    u.set_res_devices_hint(ss("physical disks by busy time, interfaces by throughput against link speed"));
    refresh_resources(ctx);
}

pub fn refresh_resources(ctx: &Shared) {
    let (sampler, token) = {
        let mut st = ctx.st.borrow_mut();
        if st.resources.busy {
            return;
        }
        st.resources.busy = true;
        st.resources.token += 1;
        let sampler = match &st.resources.sampler {
            Some(s) => s.clone(),
            None => {
                let s = Arc::new(Mutex::new(api::resources_sampler()));
                st.resources.sampler = Some(s.clone());
                s
            }
        };
        (sampler, st.resources.token)
    };
    spawn(ctx, move |_| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut s = sampler.lock().unwrap_or_else(|e| e.into_inner());
            api::resources_sample(&mut s)
        })).ok()
    }, move |ctx, snap| {
        ctx.st.borrow_mut().resources.busy = false;
        if ctx.st.borrow().resources.token != token || ctx.st.borrow().mode != "resources" {
            return;
        }
        match snap {
            Some(snap) => apply(ctx, snap),
            None => super::bad(ctx, "Sampling failed unexpectedly inside Keyhole. Details are in %LOCALAPPDATA%\\Keyhole\\crash.log"),
        }
    });
}

fn apply(ctx: &Shared, snap: Snapshot) {
    {
        let mut st = ctx.st.borrow_mut();
        let r = &mut st.resources;
        push(&mut r.cpu, snap.cpu);
        push(&mut r.kernel, snap.kernel);
        let mem_pct = if snap.mem.total > 0 { snap.mem.in_use as f32 / snap.mem.total as f32 * 100.0 } else { 0.0 };
        let commit_pct = if snap.mem.commit_limit > 0 { snap.mem.commit_used as f32 / snap.mem.commit_limit as f32 * 100.0 } else { 0.0 };
        push(&mut r.mem, mem_pct);
        push(&mut r.commit, commit_pct);
    }
    let u = ui(ctx);
    let m = &snap.mem;
    let mem_pct = if m.total > 0 { m.in_use as f32 / m.total as f32 * 100.0 } else { 0.0 };
    let commit_pct = if m.commit_limit > 0 { m.commit_used as f32 / m.commit_limit as f32 * 100.0 } else { 0.0 };
    let pf_total: u64 = snap.pagefiles.iter().map(|p| p.total).sum();
    let pf_used: u64 = snap.pagefiles.iter().map(|p| p.used).sum();
    let pf_pct = if pf_total > 0 { pf_used as f32 / pf_total as f32 * 100.0 } else { 0.0 };
    let mut metrics = vec![
        metric("CPU", format!("{:.0} %", snap.cpu), pct_tone(snap.cpu)),
        metric("Kernel", format!("{:.0} %", snap.kernel), if snap.kernel >= 40.0 { 3 } else { 0 }),
        metric("Memory in use", format!("{} of {} ({:.0} %)", bytes(m.in_use), bytes(m.total), mem_pct), pct_tone(mem_pct)),
        metric("Commit", format!("{} of {} ({:.0} %)", bytes(m.commit_used), bytes(m.commit_limit), commit_pct), pct_tone(commit_pct)),
    ];
    if pf_total > 0 {
        metrics.push(metric("Page file", format!("{} of {} ({:.0} %)", bytes(pf_used), bytes(pf_total), pf_pct), pct_tone(pf_pct)));
    } else {
        metrics.push(metric("Page file", "none".into(), 3));
    }
    metrics.push(metric("Handles", thousands(m.handles as u64), 0));
    metrics.push(metric("Processes / threads", format!("{} / {}", thousands(m.processes as u64), thousands(m.threads as u64)), 0));
    metrics.push(metric("Uptime", fmt_uptime(snap.uptime_ms), 0));
    let width = u.get_win_width();
    let keep = if width < 1000.0 { 4 } else if width < 1200.0 { 6 } else { metrics.len() };
    metrics.truncate(keep);
    u.set_res_metrics(model(metrics));
    {
        let st = ctx.st.borrow();
        let r = &st.resources;
        let (cp, cf) = chart_paths(&padded(&r.cpu));
        let (kp, kf) = chart_paths(&padded(&r.kernel));
        let (mp, mf) = chart_paths(&padded(&r.mem));
        let (op, of) = chart_paths(&padded(&r.commit));
        u.set_res_cpu_path(ss(&cp));
        u.set_res_cpu_fill(ss(&cf));
        u.set_res_kernel_path(ss(&kp));
        u.set_res_kernel_fill(ss(&kf));
        u.set_res_mem_path(ss(&mp));
        u.set_res_mem_fill(ss(&mf));
        u.set_res_commit_path(ss(&op));
        u.set_res_commit_fill(ss(&of));
        let peak = r.cpu.iter().copied().fold(0.0f32, f32::max);
        u.set_res_cpu_scale(ss(&format!("CPU {:.0} %, peak {:.0} %", snap.cpu, peak)));
        u.set_res_mem_scale(ss(&format!("in use {:.0} %, commit {:.0} %", mem_pct, commit_pct)));
    }
    let cores: Vec<BarRow> = snap.cores.iter().map(|c| BarRow {
        label: ss(&format!("Core {}", c.index)),
        value: ss(&format!("{:.0} %", c.usage)),
        sub: ss(&format!("kernel {:.0} %", c.kernel)),
        fraction: c.usage / 100.0,
        tone: pct_tone(c.usage),
        tip: ss(&format!("Logical processor {}: {:.1} % busy, {:.1} % of the time in the kernel", c.index, c.usage, c.kernel)),
    }).collect();
    u.set_res_cores(model(cores));
    let of_total = |v: u64| if m.total > 0 { v as f32 / m.total as f32 } else { 0.0 };
    let pct_of_total = |v: u64| format!("{:.0} %", of_total(v) * 100.0);
    let mut mem_rows: Vec<BarRow> = vec![
        bar("In use", bytes_or_zero(m.in_use), format!("{} of {}", pct_of_total(m.in_use), bytes(m.total)), of_total(m.in_use), pct_tone(mem_pct), "Physical memory held by processes and the kernel right now".into()),
        bar("Available", bytes_or_zero(m.avail), format!("{}  ·  standby plus free", pct_of_total(m.avail)), of_total(m.avail), if mem_pct >= 90.0 { 4 } else { 0 }, "What Windows can hand out immediately: free pages plus standby pages it can repurpose".into()),
        bar("Standby (cache)", bytes_or_zero(m.standby), pct_of_total(m.standby), of_total(m.standby), 0, "File cache and pages of recently used programs kept in case they are needed again. Given up on demand".into()),
        bar("Modified", bytes_or_zero(m.modified), pct_of_total(m.modified), of_total(m.modified), if of_total(m.modified) > 0.1 { 3 } else { 0 }, "Pages waiting to be written to disk before they can be reused".into()),
        bar("Free", bytes_or_zero(m.free), pct_of_total(m.free), of_total(m.free), 0, "Pages with nothing in them at all".into()),
        bar("Paged pool", bytes_or_zero(m.paged_pool), pct_of_total(m.paged_pool), of_total(m.paged_pool), 0, "Kernel memory that can be paged out. Drivers and the registry live here".into()),
        bar("Nonpaged pool", bytes_or_zero(m.nonpaged_pool), pct_of_total(m.nonpaged_pool), of_total(m.nonpaged_pool), if of_total(m.nonpaged_pool) > 0.15 { 3 } else { 0 }, "Kernel memory that must stay in RAM. A steadily growing nonpaged pool is a driver leak".into()),
        bar("Commit", bytes_or_zero(m.commit_used), format!("{:.0} % of {} limit  ·  peak {}", commit_pct, bytes(m.commit_limit), bytes(m.commit_peak)), if m.commit_limit > 0 { m.commit_used as f32 / m.commit_limit as f32 } else { 0.0 }, pct_tone(commit_pct), "Memory promised to processes, backed by RAM plus page files. When it hits the limit allocations fail".into()),
    ];
    for p in &snap.pagefiles {
        let frac = if p.total > 0 { p.used as f32 / p.total as f32 } else { 0.0 };
        mem_rows.push(bar(&format!("Page file {}", p.path), bytes_or_zero(p.used), format!("{:.0} % of {}  ·  peak {}", frac * 100.0, bytes(p.total), bytes(p.peak)), frac, pct_tone(frac * 100.0), "How much of this page file is in use".into()));
    }
    if snap.pagefiles.is_empty() {
        mem_rows.push(bar("Page file", "none".into(), "no page file configured. Commit is limited to physical memory".into(), 0.0, 3, "Without a page file the commit limit is RAM alone and kernel dumps cannot be written".into()));
    }
    u.set_res_mem_doc(model(mem_rows));
    let mut devices: Vec<BarRow> = snap.disks.iter().map(disk_row).collect();
    devices.extend(snap.nics.iter().filter(|n| n.up || n.rx_total + n.tx_total > 0).map(nic_row));
    u.set_res_devices(model(devices));
    ctx.st.borrow_mut().resources.last = Some(snap);
}

fn disk_row(d: &DiskSample) -> BarRow {
    let lat = if d.read_latency_ms > 0.0 || d.write_latency_ms > 0.0 { format!("  ·  {:.1} / {:.1} ms", d.read_latency_ms, d.write_latency_ms) } else { String::new() };
    let tone = if d.busy >= 90.0 || d.read_latency_ms.max(d.write_latency_ms) >= 50.0 { 4 } else if d.busy >= 70.0 || d.read_latency_ms.max(d.write_latency_ms) >= 20.0 { 3 } else { 0 };
    BarRow {
        label: ss(&d.label),
        value: ss(&format!("{:.0} % busy", d.busy)),
        sub: ss(&format!("R {}/s  W {}/s{}{}", bytes_or_zero(d.read_rate), bytes_or_zero(d.write_rate), lat, if d.queue > 0 { format!("  ·  queue {}", d.queue) } else { String::new() })),
        fraction: d.busy / 100.0,
        tone,
        tip: ss(&format!("{}\n{:.0} % of the last interval busy\nRead {}/s, write {}/s\nAverage response: read {:.1} ms, write {:.1} ms\nQueue depth {}", d.label, d.busy, bytes(d.read_rate), bytes(d.write_rate), d.read_latency_ms, d.write_latency_ms, d.queue)),
    }
}

fn nic_row(n: &NicSample) -> BarRow {
    let total = n.rx_rate + n.tx_rate;
    let util = if n.speed > 0 { (total as f64 * 8.0 / n.speed as f64 * 100.0).min(100.0) } else { 0.0 };
    let tone = if n.new_errors > 0 { 4 } else if !n.up { 1 } else if util >= 80.0 { 3 } else { 0 };
    let speed = keyhole::sys::netconfig::speed_text(n.speed);
    BarRow {
        label: ss(&if n.address.is_empty() { n.name.clone() } else { format!("{}  {}", n.name, n.address) }),
        value: ss(&if n.up { format!("{}/s", bytes_or_zero(total)) } else { "down".to_string() }),
        sub: ss(&format!("\u{2193} {}/s  \u{2191} {}/s{}{}", bytes_or_zero(n.rx_rate), bytes_or_zero(n.tx_rate), if speed.is_empty() { String::new() } else { format!("  ·  {}", speed) }, if n.errors > 0 { format!("  ·  {} errors", thousands(n.errors)) } else { String::new() })),
        fraction: (util / 100.0) as f32,
        tone,
        tip: ss(&format!("{}\n{}\n{}  ·  {}\nReceived {}/s, sent {}/s ({:.1} % of {})\nTotal received {}, sent {}\nErrors {}, discards {}", n.name, n.description, n.kind, if n.up { "up" } else { "down" }, bytes_or_zero(n.rx_rate), bytes_or_zero(n.tx_rate), util, if speed.is_empty() { "unknown speed".to_string() } else { speed.clone() }, bytes(n.rx_total), bytes(n.tx_total), n.errors, n.discards)),
    }
}

pub fn resources_csv(ctx: &Shared) -> Option<(String, String)> {
    let st = ctx.st.borrow();
    let snap = st.resources.last.as_ref()?;
    let mut rows: Vec<Vec<String>> = Vec::new();
    for c in &snap.cores {
        rows.push(vec!["core".into(), format!("Core {}", c.index), format!("{:.1}", c.usage), format!("{:.1}", c.kernel), String::new(), String::new()]);
    }
    for d in &snap.disks {
        rows.push(vec!["disk".into(), d.label.clone(), format!("{:.1}", d.busy), d.read_rate.to_string(), d.write_rate.to_string(), format!("{:.2} / {:.2} ms, queue {}", d.read_latency_ms, d.write_latency_ms, d.queue)]);
    }
    for n in &snap.nics {
        rows.push(vec!["nic".into(), n.name.clone(), if n.up { "up".into() } else { "down".into() }, n.rx_rate.to_string(), n.tx_rate.to_string(), format!("{} errors, {} discards, {}", n.errors, n.discards, n.address)]);
    }
    let m = &snap.mem;
    for (k, v) in [("total", m.total), ("available", m.avail), ("in use", m.in_use), ("standby", m.standby), ("modified", m.modified), ("free", m.free), ("paged pool", m.paged_pool), ("nonpaged pool", m.nonpaged_pool), ("commit", m.commit_used), ("commit limit", m.commit_limit), ("commit peak", m.commit_peak)] {
        rows.push(vec!["memory".into(), k.into(), v.to_string(), String::new(), String::new(), String::new()]);
    }
    Some(("keyhole-resources".into(), csv(&rows, &["Kind", "Name", "Value", "Read or received", "Write or sent", "Detail"])))
}
