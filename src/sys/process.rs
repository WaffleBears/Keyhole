use crate::nt::*;
use std::collections::HashMap;
use std::ffi::c_void;

#[derive(Clone)]
pub struct RawThread {
    pub tid: u32,
    pub start_address: u64,
    pub priority: i32,
    pub state: u32,
    pub wait_reason: u32,
    pub create_time: i64,
    pub cpu_100ns: i64,
}

#[derive(Clone)]
pub struct RawProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: i64,
    pub cpu_100ns: i64,
    pub handles: u32,
    pub thread_count: u32,
    pub session: u32,
    pub private_bytes: u64,
    pub working_set: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub suspended: bool,
    pub threads: Vec<RawThread>,
}

pub fn sample(with_threads: bool) -> Vec<RawProcess> {
    let mut cap: usize = 1 << 20;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.resize(cap, 0);
        let mut needed: u32 = 0;
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr() as *mut c_void,
                cap as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
            cap = (needed as usize).max(cap * 2) + 65536;
            continue;
        }
        if !nt_ok(status) {
            return Vec::new();
        }
        break;
    }

    let mut out = Vec::with_capacity(512);
    let mut offset = 0usize;
    loop {
        let entry = unsafe { &*(buf.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION) };
        let pid = entry.UniqueProcessId as usize as u32;
        if pid == 0 {
            if entry.NextEntryOffset == 0 {
                break;
            }
            offset += entry.NextEntryOffset as usize;
            continue;
        }
        let name = if entry.ImageName.Buffer.is_null() {
            String::new()
        } else {
            unsafe { entry.ImageName.to_string() }
        };

        let mut threads = Vec::new();
        let mut suspended = entry.NumberOfThreads > 0;
        if entry.NumberOfThreads > 0 {
            let base = unsafe {
                buf.as_ptr()
                    .add(offset + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>())
                    as *const SYSTEM_THREAD_INFORMATION
            };
            let n = entry.NumberOfThreads as usize;
            if with_threads {
                threads.reserve(n);
            }
            for i in 0..n {
                let t = unsafe { &*base.add(i) };
                if !(t.ThreadState == 5 && (t.WaitReason == 5 || t.WaitReason == 12)) {
                    suspended = false;
                }
                if !with_threads {
                    continue;
                }
                threads.push(RawThread {
                    tid: t.ClientId.UniqueThread as usize as u32,
                    start_address: t.StartAddress as u64,
                    priority: t.Priority,
                    state: t.ThreadState,
                    wait_reason: t.WaitReason,
                    create_time: t.CreateTime,
                    cpu_100ns: t.KernelTime.saturating_add(t.UserTime),
                });
            }
        }

        out.push(RawProcess {
            pid,
            ppid: entry.InheritedFromUniqueProcessId as usize as u32,
            name,
            create_time: entry.CreateTime,
            cpu_100ns: entry.KernelTime.saturating_add(entry.UserTime),
            handles: entry.HandleCount,
            thread_count: entry.NumberOfThreads,
            session: entry.SessionId,
            private_bytes: entry.PrivatePageCount as u64,
            working_set: entry.WorkingSetSize as u64,
            read_bytes: entry.ReadTransferCount.max(0) as u64,
            write_bytes: entry.WriteTransferCount.max(0) as u64,
            suspended,
            threads,
        });

        if entry.NextEntryOffset == 0 {
            break;
        }
        offset += entry.NextEntryOffset as usize;
        if offset >= buf.len() {
            break;
        }
    }
    out
}

pub fn win32_start_address(tid: u32) -> u64 {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenThread, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
    };

    if tid == 0 {
        return 0;
    }
    unsafe {
        let h = match OpenThread(THREAD_QUERY_INFORMATION, false, tid) {
            Ok(h) => h,
            Err(_) => match OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) {
                Ok(h) => h,
                Err(_) => return 0,
            },
        };
        let mut address: u64 = 0;
        let status = NtQueryInformationThread(
            h.0,
            ThreadQuerySetWin32StartAddress,
            &mut address as *mut _ as *mut c_void,
            std::mem::size_of::<u64>() as u32,
            std::ptr::null_mut(),
        );
        let _ = CloseHandle(h);
        if nt_ok(status) { address } else { 0 }
    }
}

pub fn build_tree(procs: &[RawProcess]) -> (Vec<Vec<usize>>, Vec<usize>) {
    let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, p) in procs.iter().enumerate() {
        by_pid.entry(p.pid).or_default().push(i);
    }

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); procs.len()];
    let mut roots: Vec<usize> = Vec::new();

    for (i, p) in procs.iter().enumerate() {
        let parent = resolve_parent(procs, &by_pid, i, p);
        match parent {
            Some(pi) => children[pi].push(i),
            None => roots.push(i),
        }
    }

    break_cycles(procs, &mut children, &mut roots);
    (children, roots)
}

fn resolve_parent(
    procs: &[RawProcess],
    by_pid: &HashMap<u32, Vec<usize>>,
    index: usize,
    p: &RawProcess,
) -> Option<usize> {
    if p.pid == 0 {
        return None;
    }
    if p.ppid == 0 && p.pid != 4 {
        return None;
    }
    let candidates = by_pid.get(&p.ppid)?;
    let mut best: Option<usize> = None;
    for &ci in candidates {
        if ci == index {
            continue;
        }
        let parent = &procs[ci];
        if parent.create_time > p.create_time {
            continue;
        }
        match best {
            Some(b) if procs[b].create_time >= parent.create_time => {}
            _ => best = Some(ci),
        }
    }
    best
}

fn break_cycles(procs: &[RawProcess], children: &mut Vec<Vec<usize>>, roots: &mut Vec<usize>) {
    let n = procs.len();
    let mut reachable = vec![false; n];
    let mut stack: Vec<usize> = roots.clone();
    while let Some(i) = stack.pop() {
        if reachable[i] {
            continue;
        }
        reachable[i] = true;
        for &c in &children[i] {
            if !reachable[c] {
                stack.push(c);
            }
        }
    }
    for i in 0..n {
        if !reachable[i] {
            for list in children.iter_mut() {
                list.retain(|&c| c != i);
            }
            roots.push(i);
            let mut stack = vec![i];
            while let Some(j) = stack.pop() {
                if reachable[j] {
                    continue;
                }
                reachable[j] = true;
                for &c in &children[j] {
                    stack.push(c);
                }
            }
        }
    }
}

pub fn flatten<F: Fn(usize) -> bool>(
    children: &[Vec<usize>],
    roots: &[usize],
    order: &dyn Fn(&mut Vec<usize>),
    expanded: F,
) -> Vec<(usize, u32, u32, u32)> {
    let mut out = Vec::new();
    let mut root_list = roots.to_vec();
    order(&mut root_list);
    let mut visited = vec![false; children.len()];
    for r in root_list {
        walk(children, r, 0, order, &expanded, &mut out, &mut visited);
    }
    out
}

fn walk<F: Fn(usize) -> bool>(
    children: &[Vec<usize>],
    node: usize,
    depth: u32,
    order: &dyn Fn(&mut Vec<usize>),
    expanded: &F,
    out: &mut Vec<(usize, u32, u32, u32)>,
    visited: &mut Vec<bool>,
) {
    if visited[node] {
        return;
    }
    visited[node] = true;
    let kids = &children[node];
    let hidden = if expanded(node) {
        0
    } else {
        count_descendants(children, node)
    };
    out.push((node, depth, kids.len() as u32, hidden));
    if hidden > 0 {
        return;
    }
    let mut list = kids.clone();
    order(&mut list);
    for c in list {
        walk(children, c, depth + 1, order, expanded, out, visited);
    }
}

pub fn count_descendants(children: &[Vec<usize>], node: usize) -> u32 {
    let mut total = 0u32;
    let mut seen = vec![false; children.len()];
    seen[node] = true;
    let mut stack = children[node].clone();
    while let Some(n) = stack.pop() {
        if seen[n] {
            continue;
        }
        seen[n] = true;
        total += 1;
        stack.extend_from_slice(&children[n]);
    }
    total
}
