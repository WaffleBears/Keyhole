use crate::model::{ActivityRow, ActivityTotals, EndpointRow, HandleRow, ModuleRow, OpenFileRow, ProcessRow, SystemStats, ThreadRow};
use crate::objects::SearchResult;
use crate::state::{App, SortKey};
use crate::sys::firewall::{FirewallRow, NewRule, ProfileStatus, RuleKey};
use crate::sys::eventlog::EventRow;
use crate::sys::handles::ResolverStats;
use crate::sys::sessions::SessionRow;
use crate::sys::{actions, modules, net};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Clone)]
pub struct TreeView {
    pub rows: Vec<ProcessRow>,
    pub stats: SystemStats,
    pub icon_count: usize,
    pub live_pids: Vec<u32>,
    pub paused: bool,
}

pub fn tree(app: &App) -> TreeView {
    let snap = app.tree.load();
    TreeView {
        rows: snap.rows.clone(),
        stats: snap.stats.clone(),
        icon_count: snap.icon_count,
        live_pids: snap.live_pids.clone(),
        paused: app.paused.load(Ordering::Relaxed),
    }
}

pub fn refresh(app: &App) -> TreeView {
    app.refresh_tree();
    tree(app)
}

pub struct ViewChange {
    pub sort: Option<SortKey>,
    pub descending: Option<bool>,
    pub flat: Option<bool>,
    pub filter: Option<String>,
}

impl ViewChange {
    pub fn filter(text: &str) -> Self {
        ViewChange { sort: None, descending: None, flat: None, filter: Some(text.to_string()) }
    }
    pub fn sort(sort: SortKey, descending: bool) -> Self {
        ViewChange { sort: Some(sort), descending: Some(descending), flat: None, filter: None }
    }
    pub fn flat(flat: bool) -> Self {
        ViewChange { sort: None, descending: None, flat: Some(flat), filter: None }
    }
}

pub fn set_view(app: &App, change: ViewChange) -> TreeView {
    {
        let mut o = app.options.lock();
        if let Some(s) = change.sort {
            o.sort = s;
        }
        if let Some(d) = change.descending {
            o.descending = d;
        }
        if let Some(f) = change.flat {
            o.flat = f;
        }
        if let Some(t) = change.filter {
            o.filter = t;
        }
    }
    refresh(app)
}

pub fn set_expanded(app: &App, pid: u32, expanded: bool) -> TreeView {
    {
        let mut c = app.collapsed.lock();
        if expanded {
            c.remove(&pid);
        } else {
            c.insert(pid);
        }
    }
    refresh(app)
}

pub fn reveal(app: &App, pid: u32) -> TreeView {
    app.options.lock().filter.clear();
    {
        let chain = parent_chain(app, pid);
        let mut c = app.collapsed.lock();
        for link in chain {
            c.remove(&link.pid);
        }
    }
    refresh(app)
}

pub fn expand_all(app: &App) -> TreeView {
    app.collapsed.lock().clear();
    refresh(app)
}

pub fn collapse_all(app: &App) -> TreeView {
    {
        let tree = app.tree.load();
        let mut c = app.collapsed.lock();
        for r in tree.rows.iter().filter(|r| r.children > 0) {
            c.insert(r.pid);
        }
    }
    refresh(app)
}

pub fn set_paused(app: &App, paused: bool) {
    app.paused.store(paused, Ordering::Relaxed);
}

pub fn set_interval_ms(app: &App, ms: u64) {
    app.set_refresh_interval_ms(ms);
}

pub struct Handles {
    pub rows: Vec<HandleRow>,
    pub note: String,
    pub summary: Vec<(String, u32)>,
    pub total: usize,
    pub named: usize,
    pub stats: ResolverStats,
}

pub fn handles(app: &App, pid: u32) -> Handles {
    let (rows, stats) = app.handles_for(pid);
    let note = app
        .tree
        .load()
        .procs
        .get(&pid)
        .map(|p| app.details.get(pid, p.create_time, false).note)
        .unwrap_or_default();
    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut named = 0usize;
    for r in &rows {
        *counts.entry(r.type_name.clone()).or_default() += 1;
        if r.named {
            named += 1;
        }
    }
    Handles { total: rows.len(), rows, note, summary: counts.into_iter().collect(), named, stats }
}

pub fn search(app: &App, query: &str, subtree: bool) -> SearchResult {
    app.search(query, subtree)
}

pub fn modules(app: &App, pid: u32) -> Result<Vec<ModuleRow>, String> {
    let mut rows = modules::list(pid)?;
    for m in rows.iter_mut() {
        let v = app.versions.get(&m.path);
        m.version = v.version;
        m.company = v.company;
    }
    Ok(rows)
}

pub fn threads(app: &App, pid: u32) -> Vec<ThreadRow> {
    app.threads_for(pid)
}

pub fn network(app: &App, pid: u32, resolve: bool) -> Vec<EndpointRow> {
    let tree = app.tree.load();
    let mut rows: Vec<EndpointRow> = net::endpoints().into_iter().filter(|e| pid == 0 || e.pid == pid).collect();
    for r in rows.iter_mut() {
        r.process = tree.name_of(r.pid);
        if resolve && !r.remote.is_empty() {
            r.remote_host = net::reverse_dns_cached(&r.remote);
        }
    }
    rows
}

#[derive(Clone, Serialize)]
pub struct ChainLink {
    pub pid: u32,
    pub name: String,
}

#[derive(Clone, Default)]
pub struct ProcessDetails {
    pub pid: u32,
    pub ppid: u32,
    pub session: u32,
    pub started_unix_ms: i64,
    pub image_path: String,
    pub description: String,
    pub company: String,
    pub product: String,
    pub file_version: String,
    pub parent_name: String,
    pub command_line: String,
    pub working_dir: String,
    pub user: String,
    pub integrity: String,
    pub elevated: bool,
    pub arch: String,
    pub trust: String,
    pub parent_chain: Vec<ChainLink>,
    pub accessible: bool,
    pub protection: String,
    pub handles_readable: bool,
    pub note: String,
    pub groups: Vec<String>,
    pub privileges: Vec<(String, bool)>,
    pub cpus: Vec<u32>,
    pub system_cpus: Vec<u32>,
}

pub fn details(app: &App, pid: u32) -> ProcessDetails {
    let tree = app.tree.load();
    let info = tree.procs.get(&pid);
    let create_time = info.map(|p| p.create_time).unwrap_or(0);
    let d = app.details.get(pid, create_time, true);
    let ver = app.versions.get(&d.image_path);
    let parent_name = info.and_then(|r| tree.procs.get(&r.ppid).filter(|p| p.create_time <= r.create_time).map(|p| p.name.clone())).unwrap_or_default();
    let (ppid, session, started) = info
        .map(|r| (r.ppid, r.session, crate::sys::filetime_to_unix_ms(r.create_time)))
        .unwrap_or((0, 0, 0));
    let (affinity, system_mask) = actions::affinity(pid).unwrap_or((0, 0));
    ProcessDetails {
        pid,
        ppid,
        session,
        started_unix_ms: started,
        description: ver.description,
        company: ver.company,
        product: ver.product,
        file_version: ver.version,
        parent_name,
        trust: app.signatures.get(&d.image_path).label().to_string(),
        parent_chain: parent_chain(app, pid),
        cpus: mask_to_cpus(affinity),
        system_cpus: mask_to_cpus(system_mask),
        image_path: d.image_path,
        command_line: d.command_line,
        working_dir: d.working_dir,
        user: d.user,
        integrity: d.integrity,
        elevated: d.elevated,
        arch: d.arch,
        accessible: d.accessible,
        protection: d.protection,
        handles_readable: d.handles_readable,
        note: d.note,
        groups: d.groups,
        privileges: d.privileges,
    }
}

pub fn parent_chain(app: &App, pid: u32) -> Vec<ChainLink> {
    let tree = app.tree.load();
    let mut chain = Vec::new();
    let mut current = tree.procs.get(&pid).map(|r| (r.ppid, r.create_time));
    let mut guard = 0;
    while let Some((ppid, born)) = current {
        guard += 1;
        if guard > 64 {
            break;
        }
        match tree.procs.get(&ppid) {
            Some(p) if p.create_time <= born => {
                chain.push(ChainLink { pid: p.pid, name: p.name.clone() });
                current = if p.ppid == ppid { None } else { Some((p.ppid, p.create_time)) };
            }
            _ => break,
        }
    }
    chain.reverse();
    chain
}

pub fn activity(app: &App) -> Arc<crate::etw::ActivitySnapshot> {
    app.activity.snapshot()
}

pub struct AllHandles {
    pub rows: Vec<HandleRow>,
    pub summary: Vec<(String, u32)>,
    pub total: u32,
    pub stats: ResolverStats,
}

pub fn all_handles(app: &App, type_filter: &str) -> AllHandles {
    let (rows, counts, stats) = app.all_handles(type_filter, "", 20000);
    let total = counts.iter().map(|(_, n)| *n).sum();
    AllHandles { rows, summary: counts, total, stats }
}

pub struct OpenFiles {
    pub rows: Vec<OpenFileRow>,
    pub open: usize,
    pub writing: usize,
    pub tracing: bool,
    pub stats: ResolverStats,
}

pub fn open_files(app: &App) -> OpenFiles {
    let (rows, stats) = app.open_files();
    let open = rows.iter().filter(|r| r.open).count();
    let writing = rows.iter().filter(|r| r.write && r.open).count();
    OpenFiles { rows, open, writing, tracing: app.activity.is_running(), stats }
}

pub fn environment() -> crate::sys::sysinfo::SysInfo {
    crate::sys::sysinfo::collect()
}

pub struct SessionEntry {
    pub row: SessionRow,
    pub processes: usize,
}

pub fn sessions(app: &App) -> Vec<SessionEntry> {
    let tree = app.tree.load();
    crate::sys::sessions::list()
        .into_iter()
        .map(|row| {
            let processes = tree.procs.values().filter(|p| p.session == row.id).count();
            SessionEntry { row, processes }
        })
        .collect()
}

pub fn software() -> Vec<crate::sys::software::SoftwareRow> {
    crate::sys::software::list()
}

pub struct Firewall {
    pub rows: Vec<FirewallRow>,
    pub profiles: Vec<ProfileStatus>,
}

pub fn firewall() -> Result<Firewall, String> {
    let rows = crate::sys::firewall::list()?;
    let profiles = crate::sys::firewall::profiles().unwrap_or_default();
    Ok(Firewall { rows, profiles })
}

#[derive(Clone, Serialize)]
pub struct StartupEntry {
    pub name: String,
    pub command: String,
    pub image_path: String,
    pub publisher: String,
    pub description: String,
    pub enabled: bool,
    pub location: String,
    pub scope: String,
    pub source: String,
    pub trust: String,
}

pub fn startup(app: &App) -> Vec<StartupEntry> {
    let entries = crate::sys::startup::list();
    let paths: Vec<String> = entries.iter().map(|e| e.image_path.clone()).collect();
    app.signatures.warm(&paths);
    entries
        .into_iter()
        .map(|e| {
            let trust = if e.image_path.is_empty() { "unchecked".to_string() } else { app.signatures.get(&e.image_path).label().to_string() };
            let ver = app.versions.get(&e.image_path);
            StartupEntry {
                name: e.name,
                command: e.command,
                image_path: e.image_path,
                publisher: ver.company,
                description: ver.description,
                enabled: e.enabled,
                location: e.location,
                scope: e.scope,
                source: e.source,
                trust,
            }
        })
        .collect()
}

pub fn drivers(app: &App) -> Vec<crate::sys::drivers::DriverRow> {
    let mut drivers = crate::sys::drivers::list();
    let paths: Vec<String> = drivers.iter().map(|d| d.path.clone()).collect();
    app.signatures.warm(&paths);
    for d in drivers.iter_mut() {
        d.trust = if d.path.is_empty() { "unchecked".to_string() } else { app.signatures.get(&d.path).label().to_string() };
    }
    drivers
}

pub fn tasks() -> Result<Vec<crate::sys::tasks::TaskRow>, String> {
    crate::sys::tasks::list()
}

pub fn services() -> Vec<crate::sys::services::ServiceRow> {
    crate::sys::services::list()
}

pub struct Connections {
    pub rows: Vec<EndpointRow>,
    pub listening: usize,
    pub established: usize,
}

pub fn connections(app: &App, resolve: bool, filter: &str) -> Connections {
    let filter = filter.to_lowercase();
    let mut rows = network(app, 0, resolve);
    if let Some(v) = filter.strip_prefix("remote:") {
        let v = v.trim().to_string();
        rows.retain(|r| address_matches(&r.remote, &v) || r.remote_host.to_lowercase().starts_with(&v));
    } else if let Some(v) = filter.strip_prefix("local:") {
        let v = v.trim().to_string();
        rows.retain(|r| address_matches(&r.local, &v));
    } else if let Some(v) = filter.strip_prefix("pid:") {
        let v = v.trim().to_string();
        rows.retain(|r| r.pid.to_string() == v);
    } else if let Some(v) = filter.strip_prefix("port:") {
        let v = format!(":{}", v.trim());
        rows.retain(|r| r.local.ends_with(&v) || r.remote.ends_with(&v));
    } else if !filter.is_empty() {
        rows.retain(|r| {
            r.process.to_lowercase().contains(&filter)
                || r.local.contains(&filter)
                || r.remote.contains(&filter)
                || r.remote_host.to_lowercase().contains(&filter)
                || r.state.to_lowercase().contains(&filter)
                || r.pid.to_string() == filter
        });
    }
    rows.sort_by(|a, b| {
        state_rank(&a.state)
            .cmp(&state_rank(&b.state))
            .then(a.process.to_lowercase().cmp(&b.process.to_lowercase()))
            .then(a.pid.cmp(&b.pid))
    });
    let listening = rows.iter().filter(|r| r.state == "LISTEN").count();
    let established = rows.iter().filter(|r| r.state == "ESTABLISHED").count();
    Connections { rows, listening, established }
}

fn address_matches(endpoint: &str, wanted: &str) -> bool {
    if wanted.parse::<std::net::IpAddr>().is_ok() {
        endpoint.starts_with(&format!("{}:", wanted)) || endpoint.starts_with(&format!("[{}]:", wanted))
    } else {
        endpoint.starts_with(wanted) || endpoint.starts_with(&format!("[{}", wanted))
    }
}

fn state_rank(s: &str) -> u8 {
    match s {
        "ESTABLISHED" => 0,
        "LISTEN" => 1,
        "" => 2,
        "CLOSE_WAIT" | "TIME_WAIT" => 4,
        _ => 3,
    }
}

pub fn start_activity(app: &App) -> Result<(), String> {
    app.activity.start()?;
    app.refresh_tree();
    Ok(())
}

pub fn stop_activity(app: &App) {
    app.activity.stop();
    app.refresh_tree();
}

pub fn new_icons(app: &App, since: usize) -> (Vec<(u32, Vec<u8>)>, usize) {
    app.icons.take_new(since)
}


pub fn descendant_names(app: &App, pid: u32) -> Vec<String> {
    let tree = app.tree.load();
    app.descendants(pid).iter().skip(1).map(|p| tree.name_of(*p)).collect()
}

pub fn mask_to_cpus(mask: u64) -> Vec<u32> {
    (0..64).filter(|i| mask & (1u64 << i) != 0).collect()
}

pub fn sha256(path: &str) -> Result<String, String> {
    actions::sha256_of(path)
}

pub fn task_xml(path: &str) -> Result<String, String> {
    crate::sys::tasks::xml(path)
}

pub fn write_dump(pid: u32, path: &str, full: bool) -> Result<(), String> {
    actions::write_dump(pid, path, full)
}

pub fn snapshot_json(app: &App) -> Result<String, String> {
    let snap = app.tree.load();
    let rows = app.full_rows();
    serde_json::to_string_pretty(&serde_json::json!({
        "generatedUnixSeconds": now_unix_seconds(),
        "stats": snap.stats,
        "processes": rows,
    }))
    .map_err(|e| e.to_string())
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Debug)]
pub enum Action {
    Terminate(u32),
    KillTree(u32),
    Suspend(u32),
    Resume(u32),
    CloseHandle { pid: u32, handle: u64, object: u64 },
    CloseFileHandles(String),
    Reveal(String),
    OpenFolder(String),
    FileProperties(String),
    OpenTool(String),
    OpenRegistryKey(String),
    Restart(u32),
    FirewallAdd(NewRule),
    FirewallDelete(RuleKey),
    FirewallEnabled { key: RuleKey, enabled: bool },
    StartupEnabled { source: String, scope: String, name: String, enabled: bool },
    RemoveStartup { source: String, name: String, command: String },
    Service { name: String, op: String },
    Task { path: String, op: String },
    TaskCreate(crate::sys::tasks::NewTask),
    CertImport { path: String, store: String, password: Secret, exportable: bool },
    CertRemove { thumbprint: String, store: String },
    SessionLogoff(u32),
    SessionDisconnect(u32),
    SessionMessage { id: u32, title: String, text: String },
    Uninstall(String),
    CloseConnection { local: String, remote: String },
    CloseSmbFile(u32),
    DisconnectSmbSession { client: String, user: String },
    DisconnectMount(String),
    AddGroupMember { group: String, account: String },
    SetPassword { user: String, password: Secret },
    StopSharing(String),
    FlushDns,
    RenewDhcp(u32),
    UserEnabled { name: String, enabled: bool },
    UserUnlock(String),
    RemoveGroupMember { group: String, sid: String, member: String },
}

pub fn run(app: &App, action: Action) -> Result<(), String> {
    let touches_tree = matches!(
        action,
        Action::Terminate(_) | Action::KillTree(_) | Action::Suspend(_) | Action::Resume(_) | Action::Restart(_) | Action::Service { .. } | Action::Uninstall(_) | Action::SessionLogoff(_)
    );
    let result = match action {
        Action::Terminate(pid) => {
            let tree = app.tree.load();
            actions::critical_guard(pid, &tree.name_of(pid), "terminate")
                .and_then(|_| actions::still_same_process(pid, tree.started_at(pid), "terminated"))
                .and_then(|_| actions::terminate(pid))
        }
        Action::KillTree(pid) => {
            let tree = app.tree.load();
            let members = app.descendants(pid);
            for p in &members {
                actions::critical_guard(*p, &tree.name_of(*p), "terminate").map_err(|e| format!("nothing was terminated: {}", e))?;
                actions::still_same_process(*p, tree.started_at(*p), "terminated").map_err(|e| format!("nothing was terminated: {}", e))?;
            }
            let mut errors = Vec::new();
            for p in members.iter().rev() {
                if let Err(e) = actions::still_same_process(*p, tree.started_at(*p), "terminated").and_then(|_| actions::terminate(*p)) {
                    errors.push(format!("pid {}: {}", p, e));
                }
            }
            if errors.is_empty() { Ok(()) } else { Err(errors.join(". ")) }
        }
        Action::Suspend(pid) if pid == std::process::id() => Err("Keyhole cannot suspend itself".into()),
        Action::Suspend(pid) => {
            let tree = app.tree.load();
            actions::critical_guard(pid, &tree.name_of(pid), "suspend")
                .and_then(|_| actions::still_same_process(pid, tree.started_at(pid), "suspended"))
                .and_then(|_| actions::suspend(pid))
        }
        Action::Resume(pid) => actions::resume(pid),
        Action::CloseHandle { pid, handle, object } => actions::critical_guard(pid, &app.tree.load().name_of(pid), "close a handle inside")
            .and_then(|_| if still_open(&crate::sys::handles::scan_raw(), pid, handle, object) { Ok(()) } else { Err("that handle is already gone, so nothing was closed. Refresh and try again".to_string()) })
            .and_then(|_| actions::close_handle(pid, handle)),
        Action::CloseFileHandles(path) => close_file_handles(app, &path),
        Action::Reveal(path) => actions::reveal_in_explorer(&path),
        Action::OpenFolder(path) => actions::open_containing_folder(&path),
        Action::FileProperties(path) => actions::file_properties(&path),
        Action::OpenTool(tool) => actions::open_tool(&tool),
        Action::OpenRegistryKey(key) => actions::open_registry_key(&key),
        Action::Restart(pid) => restart(app, pid),
        Action::FirewallAdd(rule) => crate::sys::firewall::add_rule(&rule),
        Action::FirewallDelete(key) => crate::sys::firewall::delete_rule(&key),
        Action::FirewallEnabled { key, enabled } => crate::sys::firewall::set_enabled(&key, enabled),
        Action::StartupEnabled { source, scope, name, enabled } => crate::sys::startup::set_enabled(&source, &scope, &name, enabled),
        Action::RemoveStartup { source, name, command } => crate::sys::startup::remove(&source, &name, &command),
        Action::Service { name, op } => crate::sys::services::control(&name, &op),
        Action::Task { path, op } => crate::sys::tasks::action(&path, &op),
        Action::TaskCreate(task) => crate::sys::tasks::create(&task).map(|_| ()),
        Action::CertImport { path, store, password, exportable } => crate::sys::certs::import_file(std::path::Path::new(&path), &store, &password.0, exportable).map(|_| ()),
        Action::CertRemove { thumbprint, store } => crate::sys::certs::remove(&thumbprint, &store),
        Action::SessionLogoff(id) => crate::sys::sessions::logoff(id),
        Action::SessionDisconnect(id) => crate::sys::sessions::disconnect(id),
        Action::SessionMessage { id, title, text } => crate::sys::sessions::send_message(id, &title, &text),
        Action::Uninstall(command) => actions::run_uninstall(&command),
        Action::CloseConnection { local, remote } => net::close_tcp(&local, &remote),
        Action::CloseSmbFile(id) => crate::sys::shares::close_file(id),
        Action::DisconnectSmbSession { client, user } => crate::sys::shares::disconnect(&client, &user),
        Action::DisconnectMount(name) => crate::sys::mounts::disconnect(&name),
        Action::AddGroupMember { group, account } => crate::sys::accounts::add_member(&group, &account),
        Action::SetPassword { user, password } => crate::sys::accounts::set_password(&user, &password.0),
        Action::StopSharing(name) => crate::sys::shares::stop_sharing(&name),
        Action::FlushDns => crate::sys::netconfig::flush_dns(),
        Action::RenewDhcp(index) => crate::sys::netconfig::renew_dhcp(index),
        Action::UserEnabled { name, enabled } => crate::sys::accounts::set_enabled(&name, enabled),
        Action::UserUnlock(name) => crate::sys::accounts::unlock(&name),
        Action::RemoveGroupMember { group, sid, .. } => crate::sys::accounts::remove_member(&group, &sid),
    };
    if result.is_ok() && touches_tree {
        app.refresh_tree();
    }
    result
}

fn still_open(raw: &[crate::sys::handles::RawHandle], pid: u32, handle: u64, object: u64) -> bool {
    if object == 0 {
        return true;
    }
    raw.iter().any(|h| h.pid == pid && h.value == handle && h.object == object)
}

fn close_file_handles(app: &App, path: &str) -> Result<(), String> {
    let path = path.to_lowercase().replace('/', "\\");
    let res = app.search(&path, false);
    let targets: Vec<(u32, u64, u64, String)> = res.rows.iter().filter(|r| r.type_name == "File" && r.display.to_lowercase() == path).map(|r| (r.pid, r.handle, r.object, r.process.clone())).collect();
    for (pid, _, _, process) in &targets {
        actions::critical_guard(*pid, process, "close a handle inside").map_err(|e| format!("nothing was closed: {}", e))?;
    }
    let raw = crate::sys::handles::scan_raw();
    let mut closed = 0usize;
    let mut errors = Vec::new();
    for (pid, handle, object, process) in &targets {
        if !still_open(&raw, *pid, *handle, *object) {
            continue;
        }
        match actions::close_handle(*pid, *handle) {
            Ok(()) => closed += 1,
            Err(e) => errors.push(format!("{} (pid {}): {}", process, pid, e)),
        }
    }
    if closed == 0 && errors.is_empty() {
        Err("no process has that file open any more".into())
    } else if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("closed {} of them. {}", closed, errors.join(". ")))
    }
}

fn restart(app: &App, pid: u32) -> Result<(), String> {
    if pid == std::process::id() {
        return Err("Keyhole cannot restart itself. Close it and start it again".into());
    }
    let info = app.tree.load().procs.get(&pid).cloned().ok_or_else(|| "process not found".to_string())?;
    actions::critical_guard(pid, &info.name, "restart")?;
    actions::still_same_process(pid, info.create_time, "restarted")?;
    let d = app.details.get(pid, info.create_time, true);
    let image = if d.image_path.is_empty() { info.image_path.clone() } else { d.image_path.clone() };
    let cmdline = if d.command_line.is_empty() { info.command_line.clone() } else { d.command_line.clone() };
    let owner = actions::owner_token(pid);
    actions::terminate(pid)?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    actions::relaunch(&image, &cmdline, &d.working_dir, owner)
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "(empty)" } else { "[redacted]" })
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Secret {
        Secret(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Secret {
        Secret(s.to_string())
    }
}

pub fn totals_of(snap: &crate::etw::ActivitySnapshot, disk: bool) -> (&[ActivityRow], &[ActivityRow], &ActivityTotals) {
    if disk {
        (&snap.disk_rows, &snap.disk_procs, &snap.totals_disk)
    } else {
        (&snap.file_rows, &snap.file_procs, &snap.totals_file)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventWindow {
    Hour,
    Day,
    Week,
    Month,
    All,
}

impl EventWindow {
    pub fn ms(self) -> i64 {
        match self {
            EventWindow::Hour => 3_600_000,
            EventWindow::Day => 86_400_000,
            EventWindow::Week => 604_800_000,
            EventWindow::Month => 2_592_000_000,
            EventWindow::All => 0,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            EventWindow::Hour => "1 h",
            EventWindow::Day => "24 h",
            EventWindow::Week => "7 d",
            EventWindow::Month => "30 d",
            EventWindow::All => "all",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            EventWindow::Hour => "hour",
            EventWindow::Day => "day",
            EventWindow::Week => "week",
            EventWindow::Month => "month",
            EventWindow::All => "all",
        }
    }

    pub fn parse(id: &str) -> EventWindow {
        match id {
            "hour" => EventWindow::Hour,
            "week" => EventWindow::Week,
            "month" => EventWindow::Month,
            "all" => EventWindow::All,
            _ => EventWindow::Day,
        }
    }
}

pub struct EventsData {
    pub rows: Vec<EventRow>,
    pub capped: Vec<String>,
    pub errors: Vec<(String, String)>,
    pub window: EventWindow,
    pub security: bool,
    pub all_logs: bool,
    pub channels: Vec<String>,
    pub seq: u64,
}

pub const INFORMATION_CAP: usize = 2000;

pub fn event_channels(security: bool, all_logs: bool) -> Vec<String> {
    let mut out: Vec<String> = crate::sys::eventlog::CORE_CHANNELS.iter().filter(|c| **c != "Setup" || crate::sys::eventlog::channel_exists(c)).map(|c| c.to_string()).collect();
    if security {
        out.push("Security".to_string());
    }
    if all_logs {
        out.extend(crate::sys::eventlog::all_channels());
    }
    out
}

pub fn ensure_event_tail(app: &App, channels: &[String]) -> u64 {
    let matches = app.events.lock().as_ref().map(|t| t.channels == channels).unwrap_or(false);
    if !matches {
        let refs: Vec<&str> = channels.iter().map(|c| c.as_str()).collect();
        let fresh = crate::sys::eventlog::Tail::start(&refs);
        let old = std::mem::replace(&mut *app.events.lock(), Some(fresh));
        drop(old);
    }
    app.events.lock().as_ref().map(|t| t.buffer.lock().seq).unwrap_or(0)
}

pub fn events(app: &App, window: EventWindow, security: bool, all_logs: bool) -> EventsData {
    let channels = event_channels(security, all_logs);
    let seq = ensure_event_tail(app, &channels);
    let mut rows = Vec::new();
    let mut capped = Vec::new();
    let mut errors = Vec::new();
    for ch in &channels {
        let plan = if ch.eq_ignore_ascii_case("Security") {
            [(crate::sys::eventlog::Levels::AuditFailures, crate::sys::eventlog::MAX_PER_CHANNEL), (crate::sys::eventlog::Levels::AuditSuccesses, INFORMATION_CAP)]
        } else {
            [(crate::sys::eventlog::Levels::Errors, crate::sys::eventlog::MAX_PER_CHANNEL), (crate::sys::eventlog::Levels::Information, INFORMATION_CAP)]
        };
        for (levels, cap) in plan {
            match crate::sys::eventlog::query(ch, window.ms(), levels, cap) {
                Ok(q) => {
                    if q.capped && !capped.iter().any(|c| c == ch) {
                        capped.push(ch.to_string());
                    }
                    rows.extend(q.rows);
                }
                Err(e) => {
                    if !errors.iter().any(|(c, _)| c == ch) {
                        errors.push((ch.to_string(), e));
                    }
                    break;
                }
            }
        }
    }
    rows.sort_by(|a, b| b.time_ms.cmp(&a.time_ms).then(b.record_id.cmp(&a.record_id)));
    if let Some(t) = app.events.lock().as_ref() {
        for (ch, e) in t.errors() {
            if !errors.iter().any(|(c, _)| *c == ch) {
                errors.push((ch, e));
            }
        }
    }
    EventsData { rows, capped, errors, window, security, all_logs, channels, seq }
}

pub fn event_tail(app: &App, since: u64) -> (Vec<EventRow>, u64, u64) {
    match app.events.lock().as_ref() {
        Some(t) => t.since(since),
        None => (Vec::new(), 0, 0),
    }
}

pub fn event_xml(log: &str, record_id: u64) -> Result<String, String> {
    crate::sys::eventlog::xml(log, record_id)
}

pub fn event_export(log: &str, window: EventWindow, information: bool, path: &std::path::Path) -> Result<(), String> {
    crate::sys::eventlog::export(log, window.ms(), information, path)
}

pub fn crashes() -> crate::sys::crashes::CrashData {
    crate::sys::crashes::scan(&crate::sys::crashes::ScanRoots::system())
}

pub fn shares() -> crate::sys::shares::SharesData {
    crate::sys::shares::list()
}

pub fn accounts() -> crate::sys::accounts::AccountsData {
    crate::sys::accounts::list()
}

pub fn expand_domain_groups(members: &[crate::sys::accounts::MemberRow], machine_sid: &str) -> (Vec<crate::sys::accounts::MemberRow>, Vec<String>) {
    crate::sys::accounts::expand_domain_groups(members, &[crate::sys::accounts::administrators_group(), crate::sys::accounts::remote_desktop_group()], machine_sid)
}

pub fn expand_one_group(members: &[crate::sys::accounts::MemberRow], group: &str, machine_sid: &str) -> (Vec<crate::sys::accounts::MemberRow>, Vec<String>) {
    crate::sys::accounts::expand_domain_groups(members, &[group], machine_sid)
}

pub fn lookup_account(name: &str) -> Result<crate::sys::accounts::UserRow, String> {
    crate::sys::accounts::lookup_account(name)
}

pub fn updates() -> crate::sys::updates::UpdatesData {
    crate::sys::updates::history()
}

pub fn updates_pending() -> Result<Vec<crate::sys::updates::PendingRow>, String> {
    crate::sys::updates::search_pending()
}

pub fn install_updates(ids: &[(String, i32)]) -> Result<crate::sys::updates::InstallReport, String> {
    crate::sys::updates::install(ids)
}

pub fn certificates() -> crate::sys::certs::CertsData {
    crate::sys::certs::list()
}

pub fn export_cer(thumbprint: &str, path: &std::path::Path) -> Result<(), String> {
    crate::sys::certs::export_cer(thumbprint, path)
}

pub fn ping(target: &str) -> Result<String, String> {
    let r = crate::sys::netconfig::ping(target, 3, 1500)?;
    let text = crate::sys::netconfig::ping_text(target, &r);
    if r.replies.is_empty() { Err(text) } else { Ok(text) }
}

pub fn netconfig() -> crate::sys::netconfig::NetConfigData {
    crate::sys::netconfig::list()
}

pub fn resources_sampler() -> crate::sys::resources::Sampler {
    crate::sys::resources::Sampler::new()
}

pub fn resources_sample(sampler: &mut crate::sys::resources::Sampler) -> crate::sys::resources::Snapshot {
    sampler.sample()
}

pub fn analyze_dump(path: &std::path::Path) -> Result<crate::sys::dumpan::DumpReport, String> {
    crate::sys::dumpan::analyze(path)
}
