use crate::model::*;
use crate::state::{App, TreeSnapshot, type_rank};
use crate::sys::devpath::DeviceMap;
use crate::sys::handles::{RawHandle, ResolverStats, access_text, dedupe_key, display_name, scan_raw};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub const SEARCH_LIMIT: usize = 5000;

pub struct SearchResult {
    pub rows: Vec<HandleRow>,
    pub stats: ResolverStats,
    pub truncated: bool,
}

pub struct ResolvedScan {
    raw: Vec<RawHandle>,
    want: HashSet<u16>,
    names: HashMap<u64, Option<String>>,
    sharing: HashMap<u64, u32>,
    pub stats: ResolverStats,
    dm: Arc<DeviceMap>,
    tree: Arc<TreeSnapshot>,
}

pub struct Named<'a> {
    pub handle: &'a RawHandle,
    pub type_name: String,
    pub raw_name: &'a str,
    pub display: String,
}

impl ResolvedScan {
    fn row(&self, n: &Named, process: String) -> HandleRow {
        HandleRow {
            pid: n.handle.pid,
            process,
            handle: n.handle.value,
            access_text: access_text(&n.type_name, n.handle.access),
            type_name: n.type_name.clone(),
            named: !n.raw_name.is_empty(),
            name: n.raw_name.to_string(),
            display: n.display.clone(),
            object: n.handle.object,
            shared_with: self.sharing.get(&n.handle.object).copied().unwrap_or(0),
            note: String::new(),
        }
    }

    fn named<'a>(&'a self, app: &App, h: &'a RawHandle, include_unnamed: bool) -> Option<Named<'a>> {
        if !self.want.contains(&h.type_index) {
            return None;
        }
        let raw_name = self.names.get(&dedupe_key(h)).and_then(|n| n.as_deref()).unwrap_or("");
        if raw_name.is_empty() && !include_unnamed {
            return None;
        }
        let type_name = app.types.name(h.type_index).to_string();
        let display = display_name(&type_name, raw_name, &self.dm);
        Some(Named { handle: h, type_name, raw_name, display })
    }

    fn each_named<'a>(&'a self, app: &'a App) -> impl Iterator<Item = Named<'a>> + 'a {
        self.each(app, false)
    }

    fn each<'a>(&'a self, app: &'a App, include_unnamed: bool) -> impl Iterator<Item = Named<'a>> + 'a {
        let mut seen: HashSet<(u32, u64)> = HashSet::new();
        self.raw.iter().filter_map(move |h| {
            let n = self.named(app, h, include_unnamed)?;
            if seen.insert((h.pid, h.value)) { Some(n) } else { None }
        })
    }
}

impl App {
    fn scan(&self, types: &[&str], only_pid: Option<u32>) -> ResolvedScan {
        let raw = scan_raw();
        let subject: Vec<RawHandle> = match only_pid {
            Some(pid) => raw.iter().filter(|h| h.pid == pid).copied().collect(),
            None => Vec::new(),
        };
        let want: HashSet<u16> = if only_pid.is_some() {
            subject.iter().map(|h| h.type_index).collect()
        } else {
            types.iter().filter_map(|t| self.types.index_of(t)).collect()
        };
        let (names, stats) = {
            let mut resolver = self.resolver.lock();
            match only_pid {
                Some(_) => resolver.resolve_all(&subject, &want),
                None => resolver.resolve_all(&raw, &want),
            }
        };
        let mut holders: Vec<(u64, u32)> = raw.iter().filter(|h| h.object != 0).map(|h| (h.object, h.pid)).collect();
        holders.sort_unstable();
        holders.dedup();
        let mut sharing: HashMap<u64, u32> = HashMap::new();
        for (object, _) in holders {
            *sharing.entry(object).or_default() += 1;
        }
        ResolvedScan {
            raw: if only_pid.is_some() { subject } else { raw },
            want,
            names,
            sharing,
            stats,
            dm: self.devices.get(),
            tree: self.tree.load_full(),
        }
    }

    pub fn handles_for(&self, pid: u32) -> (Vec<HandleRow>, ResolverStats) {
        let scan = self.scan(&[], Some(pid));
        if scan.raw.is_empty() {
            return (Vec::new(), ResolverStats::default());
        }
        let process = scan.tree.name_of(pid);
        let mut rows: Vec<HandleRow> = scan
            .raw
            .iter()
            .map(|h| {
                let type_name = self.types.name(h.type_index).to_string();
                let raw_name = scan.names.get(&dedupe_key(h)).cloned().flatten().unwrap_or_default();
                let display = display_name(&type_name, &raw_name, &scan.dm);
                let n = Named { handle: h, type_name, raw_name: &raw_name, display };
                scan.row(&n, process.clone())
            })
            .collect();
        rows.sort_by(|a, b| {
            b.named
                .cmp(&a.named)
                .then(type_rank(&a.type_name).cmp(&type_rank(&b.type_name)))
                .then(a.type_name.cmp(&b.type_name))
                .then(a.display.to_lowercase().cmp(&b.display.to_lowercase()))
        });
        (rows, scan.stats)
    }

    pub fn all_handles(&self, type_filter: &str, needle: &str, limit: usize) -> (Vec<HandleRow>, Vec<(String, u32)>, ResolverStats) {
        let types: Vec<&str> = if type_filter.is_empty() {
            vec!["File", "Key", "Section", "Directory", "SymbolicLink"]
        } else {
            vec![type_filter]
        };
        let scan = self.scan(&types, None);
        let needle = needle.trim().to_lowercase().replace('/', "\\");
        let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
        let mut rows = Vec::new();
        for n in scan.each(self, !type_filter.is_empty()) {
            if !needle.is_empty() && !n.display.to_lowercase().contains(&needle) {
                continue;
            }
            *counts.entry(n.type_name.clone()).or_default() += 1;
            if rows.len() < limit {
                rows.push(scan.row(&n, scan.tree.name_of(n.handle.pid)));
            }
        }
        rows.sort_by(|a, b| a.display.to_lowercase().cmp(&b.display.to_lowercase()).then(a.pid.cmp(&b.pid)));
        (rows, counts.into_iter().collect(), scan.stats)
    }

    pub fn search(&self, query: &str, subtree: bool) -> SearchResult {
        let needle = query.trim().to_lowercase().replace('/', "\\");
        if needle.is_empty() {
            return SearchResult { rows: Vec::new(), stats: ResolverStats::default(), truncated: false };
        }
        let trimmed = needle.trim_end_matches('\\').to_string();
        let anchored = trimmed.contains(':') || trimmed.starts_with('\\');
        let folder = format!("{}\\", trimmed);
        let inner = format!("\\{}\\", trimmed);
        let tail = format!("\\{}", trimmed);
        let scan = self.scan(&["File", "Key", "Section", "Directory", "SymbolicLink"], None);
        let mut rows = Vec::new();
        let mut truncated = false;
        for n in scan.each_named(self) {
            let hay = n.display.to_lowercase();
            let hit = if !subtree {
                hay.contains(&needle)
            } else if anchored {
                hay == trimmed || hay.starts_with(&folder)
            } else {
                hay.contains(&inner) || hay.ends_with(&tail) || hay.starts_with(&folder)
            };
            if !hit {
                continue;
            }
            if rows.len() >= SEARCH_LIMIT {
                truncated = true;
                break;
            }
            rows.push(scan.row(&n, scan.tree.name_of(n.handle.pid)));
        }
        rows.sort_by(|a, b| {
            a.process
                .to_lowercase()
                .cmp(&b.process.to_lowercase())
                .then(a.pid.cmp(&b.pid))
                .then(a.display.cmp(&b.display))
        });
        SearchResult { rows, stats: scan.stats, truncated }
    }

    pub fn open_files(&self) -> (Vec<OpenFileRow>, ResolverStats) {
        let scan = self.scan(&["File"], None);

        struct Agg {
            path: String,
            handles: u32,
            procs: HashMap<u32, (bool, u32)>,
            write: bool,
            delete: bool,
        }
        let mut files: HashMap<String, Agg> = HashMap::new();
        for n in scan.each_named(self) {
            let path = &n.display;
            let bytes = path.as_bytes();
            let is_dos = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
            let is_unc = path.starts_with("\\\\") && !path.starts_with("\\\\?\\") && !path.starts_with("\\\\.\\");
            let ntfs_metadata = is_dos && path[3..].split('\\').any(|seg| seg.starts_with('$'));
            if (!is_dos && !is_unc) || path.ends_with('\\') || ntfs_metadata {
                continue;
            }
            let access = n.handle.access;
            let write = access & 0x0002 != 0 || access & 0x0004 != 0 || access & 0x4000_0000 != 0 || access & 0x1000_0000 != 0;
            let delete = access & 0x0001_0000 != 0;
            let e = files
                .entry(path.to_lowercase())
                .or_insert_with(|| Agg { path: path.clone(), handles: 0, procs: HashMap::new(), write: false, delete: false });
            e.handles += 1;
            e.write |= write;
            e.delete |= delete;
            let p = e.procs.entry(n.handle.pid).or_insert((false, 0));
            p.0 |= write;
            p.1 += 1;
        }

        let snap = self.activity.snapshot();
        let mut activity: HashMap<String, (u64, u64, String)> = HashMap::new();
        if snap.active {
            for r in &snap.file_rows {
                if r.detail.is_empty() {
                    continue;
                }
                let e = activity.entry(r.detail.to_lowercase()).or_insert((0, 0, r.who.clone()));
                e.0 += r.read_bytes;
                e.1 += r.write_bytes;
            }
        }

        let mut drive_cache: HashMap<String, (String, String)> = HashMap::new();
        let mut kind_of = |path: &str| -> (String, String) {
            if path.starts_with("\\\\") {
                return ("Network".to_string(), crate::sys::netdrives::share_root(path));
            }
            let k = path[..2].to_lowercase();
            drive_cache
                .entry(k)
                .or_insert_with(|| {
                    let mut kind = drive_kind(path);
                    let remote = if kind == "Network" || kind == "Unknown" { crate::sys::netdrives::remote_of(&path[..2]) } else { String::new() };
                    if !remote.is_empty() {
                        kind = "Network".to_string();
                    }
                    (kind, remote)
                })
                .clone()
        };
        let split = |path: &str| -> (String, String) {
            match path.rfind('\\') {
                Some(i) => (path[i + 1..].to_string(), path[..i].to_string()),
                None => (path.to_string(), String::new()),
            }
        };

        let mut rows: Vec<OpenFileRow> = Vec::new();
        for (key, a) in files.into_iter() {
            let mut procs: Vec<OpenFileProcess> = a
                .procs
                .into_iter()
                .map(|(pid, (write, handles))| OpenFileProcess { pid, name: scan.tree.name_of(pid), write, handles })
                .collect();
            procs.sort_by(|x, y| y.write.cmp(&x.write).then(x.name.to_lowercase().cmp(&y.name.to_lowercase())).then(x.pid.cmp(&y.pid)));
            let mut names_list: Vec<String> = Vec::new();
            for p in &procs {
                if !names_list.contains(&p.name) {
                    names_list.push(p.name.clone());
                }
            }
            let procs_text = if names_list.len() > 3 {
                format!("{} +{} more", names_list[..3].join(", "), names_list.len() - 3)
            } else {
                names_list.join(", ")
            };
            let (read_bytes, write_bytes) = activity.remove(&key).map(|(r, w, _)| (r, w)).unwrap_or((0, 0));
            let (name, folder) = split(&a.path);
            let (drive_kind, remote) = kind_of(&a.path);
            rows.push(OpenFileRow {
                drive_kind,
                remote,
                system_area: crate::sys::is_system_area(&a.path),
                path: a.path,
                name,
                folder,
                handles: a.handles,
                processes: procs,
                procs_text,
                write: a.write,
                delete_access: a.delete,
                read_bytes,
                write_bytes,
                active: read_bytes + write_bytes > 0,
                open: true,
            });
        }
        for (key, (r, w, who)) in activity.into_iter() {
            if r + w == 0 {
                continue;
            }
            let path = snap.file_rows.iter().find(|x| x.detail.to_lowercase() == key).map(|x| x.detail.clone()).unwrap_or(key.clone());
            let bytes = path.as_bytes();
            let is_dos = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
            if !is_dos && (!path.starts_with("\\\\") || path.starts_with("\\\\?\\") || path.starts_with("\\\\.\\")) {
                continue;
            }
            let (name, folder) = split(&path);
            let (drive_kind, remote) = kind_of(&path);
            rows.push(OpenFileRow {
                drive_kind,
                remote,
                system_area: crate::sys::is_system_area(&path),
                path,
                name,
                folder,
                handles: 0,
                processes: Vec::new(),
                procs_text: who,
                write: w > 0,
                delete_access: false,
                read_bytes: r,
                write_bytes: w,
                active: true,
                open: false,
            });
        }
        rows.sort_by_key(|a| a.path.to_lowercase());
        (rows, scan.stats)
    }
}

fn drive_kind(path: &str) -> String {
    if path.starts_with("\\\\") {
        return "Network".into();
    }
    let root = format!("{}\\", &path[..2]);
    let w = crate::sys::wide(&root);
    match unsafe { windows::Win32::Storage::FileSystem::GetDriveTypeW(windows::core::PCWSTR(w.as_ptr())) } {
        2 => "Removable".into(),
        3 => "Local disk".into(),
        4 => "Network".into(),
        5 => "Optical".into(),
        6 => "RAM disk".into(),
        _ => "Unknown".into(),
    }
}
