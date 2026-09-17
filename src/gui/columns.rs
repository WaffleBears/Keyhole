use super::{Shared, ss};
use crate::Col;
use slint::ModelRc;

#[derive(Clone, Copy)]
pub struct ColDef {
    pub id: &'static str,
    pub label: &'static str,
    pub w: f32,
    pub num: bool,
    pub sortable: bool,
    pub tip: &'static str,
}

pub const fn c(id: &'static str, label: &'static str, w: f32, num: bool, tip: &'static str) -> ColDef {
    ColDef { id, label, w, num, sortable: true, tip }
}

pub const TREE: &[ColDef] = &[
    c("name", "Process", 340.0, false, "Process name. Click to sort, drag the edge to resize. Right-click a header to pick columns."),
    c("pid", "PID", 70.0, true, "Process ID. Click to sort by PID."),
    c("cpu", "CPU", 62.0, true, "Share of total CPU used since the last refresh. Click to sort busiest first."),
    c("private", "Private", 84.0, true, "Private bytes: memory committed to this process alone. Click to sort."),
    c("working", "Working", 88.0, true, "Working set: physical RAM currently mapped by this process. Click to sort."),
    c("handles", "Handles", 74.0, true, "Number of open kernel handles. A steadily climbing count can mean a leak. Click to sort."),
    c("threads", "Threads", 72.0, true, "Thread count. Click to sort."),
    c("io", "I/O", 90.0, true, "Bytes per second through any handle: files, network, pipes and devices, the counter Task Manager calls I/O. The Disk view shows what reaches the disk. Click to sort."),
    c("user", "User", 130.0, false, "Account the process runs as. Click to sort by user."),
    c("description", "Description", 220.0, false, "What the program says it is, from the file's version information. Click to sort."),
    c("company", "Company", 170.0, false, "Publisher named in the file's version information. Click to sort."),
    c("start", "Started", 96.0, true, "How long ago the process started. Hover for the exact time. Click to sort newest first."),
    c("session", "Session", 70.0, true, "Logon session the process belongs to. Session 0 is services. The console user is usually 1. Click to sort."),
    c("trust", "Signature", 96.0, false, "Authenticode result for the image file, checked in the background: signed, unsigned, expired or untrusted. Click to sort."),
    c("path", "Path", 320.0, false, "Full path of the executable image. Click to sort."),
    c("cmd", "Command line", 420.0, false, "The full command line, which tells the many svchost, w3wp, java or python processes apart. Hover a row for all of it. Click to sort."),
];

pub const HANDLES: &[ColDef] = &[
    c("type_name", "Type", 108.0, false, "Kernel object type: File, Key, Section, and so on. Click to sort."),
    c("display", "Name", 480.0, false, "Resolved path or object name. Files as drive letter paths, registry keys as HKLM/HKU. Click to sort."),
    c("access_text", "Access", 200.0, false, "The access rights this handle was granted, decoded from the access mask."),
    c("handle", "Handle", 82.0, true, "The numeric handle value inside the owning process."),
    c("shared_with", "Shared", 70.0, true, "How many processes hold a handle to the same underlying object (needs SeDebugPrivilege). Click to sort."),
];

pub const NETWORK: &[ColDef] = &[
    c("proto", "Protocol", 90.0, false, "TCP, UDP, or their IPv6 variants."),
    c("local", "Local address", 220.0, false, "The local IP and port this endpoint is bound to."),
    c("remote", "Remote address", 260.0, false, "The peer address, shown once the connection is established. Tick Resolve names to look up its host name."),
    c("state", "State", 130.0, false, "TCP connection state (LISTEN, ESTABLISHED, TIME_WAIT, and so on)."),
];

pub const MODULES: &[ColDef] = &[
    c("name", "Module", 200.0, false, "DLL or executable file name loaded into this process. Click to sort."),
    c("version", "Version", 120.0, false, "File version from the module's version resource."),
    c("company", "Company", 180.0, false, "Company name from the module's version resource."),
    c("base", "Base", 130.0, true, "Address where the module is loaded in the process."),
    c("size", "Size", 84.0, true, "Size of the loaded image in memory. Click to sort."),
    c("path", "Path", 320.0, false, "Full path the module was loaded from: catches DLLs loaded from unexpected places."),
];

pub const THREADS: &[ColDef] = &[
    c("tid", "TID", 80.0, true, "Thread ID, unique across the system while the thread lives. Click to sort."),
    c("start_module", "Start address", 260.0, false, "Where the thread began, resolved to module+offset when possible."),
    c("state", "State", 170.0, false, "Scheduler state and, when waiting, the reason it is waiting."),
    c("cpu_time_ms", "CPU time", 96.0, true, "Total kernel+user CPU time this thread has used. Click to sort."),
    c("priority", "Priority", 76.0, true, "Current scheduling priority."),
    c("created", "Created", 160.0, false, "When the thread was created."),
];

pub const FINDER: &[ColDef] = &[
    c("process", "Process", 200.0, false, "Process holding the object. Click to sort."),
    c("pid", "PID", 70.0, true, "Process ID. Click to sort."),
    c("type_name", "Type", 90.0, false, "Kind of object. Click to sort."),
    c("handle", "Handle", 82.0, true, "Handle value inside the owning process."),
    c("display", "Path", 380.0, false, "Resolved path or object name. Click to sort."),
    c("access_text", "Access", 200.0, false, "Rights the handle was opened with. WriteData means the process can change the file."),
];

pub fn width_of(ctx: &Shared, table: &str, def: &ColDef) -> f32 {
    ctx.settings.borrow().widths.get(&format!("{}.{}", table, def.id)).copied().unwrap_or(def.w)
}

fn fit(defs: &[ColDef], widths: &mut [f32], pinned: &[bool], available: f32) {
    let total: f32 = widths.iter().sum::<f32>() + 14.0;
    if total <= available {
        return;
    }
    let overflow = total - available;
    let floor = |i: usize, w: f32| if defs[i].num || pinned[i] { w } else { (w * 0.5).max(110.0).min(w) };
    let room: f32 = widths.iter().enumerate().map(|(i, w)| w - floor(i, *w)).sum();
    if room <= 0.0 {
        return;
    }
    let share = (overflow / room).min(1.0);
    for (i, w) in widths.iter_mut().enumerate() {
        *w -= (*w - floor(i, *w)) * share;
    }
}

pub fn build(ctx: &Shared, table: &str, defs: &[ColDef]) -> (ModelRc<Col>, f32) {
    let mut widths: Vec<f32> = defs.iter().map(|d| width_of(ctx, table, d)).collect();
    let pinned: Vec<bool> = {
        let s = ctx.settings.borrow();
        defs.iter().map(|d| s.widths.contains_key(&format!("{}.{}", table, d.id))).collect()
    };
    let kind = table.split('.').next().unwrap_or(table);
    fit(defs, &mut widths, &pinned, super::table_width(ctx, kind));
    let mut x = 0.0f32;
    let mut cols = Vec::with_capacity(defs.len());
    for (i, d) in defs.iter().enumerate() {
        let w = widths[i].round();
        cols.push(Col { id: ss(d.id), title: ss(d.label), x, width: w, num: d.num, sortable: d.sortable, tip: ss(d.tip) });
        if i < defs.len() - 1 {
            x += w;
        }
    }
    (super::model(cols), x)
}

pub fn set_width(ctx: &Shared, table: &str, defs: &[ColDef], index: usize, width: f32) {
    if let Some(d) = defs.get(index) {
        ctx.settings.borrow_mut().widths.insert(format!("{}.{}", table, d.id), width.max(44.0));
    }
}
