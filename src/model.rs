use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LifeState {
    New,
    Normal,
    Dead,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Full,
    Partial,
    Denied,
    Protected,
}

#[derive(Clone, Serialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub ppid: u32,
    pub depth: u32,
    pub name: String,
    pub image_path: String,
    pub command_line: String,
    pub user: String,
    pub session: u32,
    pub integrity: String,
    pub elevated: bool,
    pub arch: String,
    pub start_time: i64,
    pub cpu: f32,
    pub private_bytes: u64,
    pub working_set: u64,
    pub handle_count: u32,
    pub thread_count: u32,
    pub read_rate: u64,
    pub write_rate: u64,
    pub read_total: u64,
    pub write_total: u64,
    pub state: LifeState,
    pub suspended: bool,
    pub critical: bool,
    pub access: Access,
    pub access_note: String,
    pub protection: String,
    pub icon: u32,
    pub children: u32,
    pub collapsed_descendants: u32,
    pub service_names: Vec<String>,
    pub description: String,
    pub company: String,
    pub trust: String,
    pub filter_context: bool,
}

#[derive(Clone, Serialize)]
pub struct HandleRow {
    pub pid: u32,
    pub process: String,
    pub handle: u64,
    pub type_name: String,
    pub name: String,
    pub display: String,
    pub access_text: String,
    pub object: u64,
    pub shared_with: u32,
    pub named: bool,
    pub note: String,
}

#[derive(Clone, Serialize)]
pub struct OpenFileProcess {
    pub pid: u32,
    pub name: String,
    pub write: bool,
    pub handles: u32,
}

#[derive(Clone, Serialize)]
pub struct OpenFileRow {
    pub path: String,
    pub name: String,
    pub folder: String,
    pub handles: u32,
    pub processes: Vec<OpenFileProcess>,
    pub procs_text: String,
    pub write: bool,
    pub delete_access: bool,
    pub drive_kind: String,
    pub remote: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub active: bool,
    pub open: bool,
    pub system_area: bool,
}

#[derive(Clone, Serialize)]
pub struct ModuleRow {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u64,
    pub version: String,
    pub company: String,
}

#[derive(Clone, Serialize)]
pub struct EndpointRow {
    pub pid: u32,
    pub process: String,
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub remote_host: String,
    pub state: String,
}

#[derive(Clone, Serialize)]
pub struct ThreadRow {
    pub tid: u32,
    pub start_address: u64,
    pub start_module: String,
    pub priority: i32,
    pub state: String,
    pub cpu_time_ms: u64,
    pub created: i64,
}

#[derive(Clone, Serialize)]
pub struct ActivityRow {
    pub key: String,
    pub label: String,
    pub detail: String,
    pub who: String,
    pub pid: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub ops: u64,
    pub spark: Vec<u64>,
}

#[derive(Clone, Serialize, Default)]
pub struct ActivityTotals {
    pub read_rate: u64,
    pub write_rate: u64,
    pub ops_rate: u64,
    pub events_seen: u64,
    pub events_dropped: u64,
    pub history_read: Vec<u64>,
    pub history_write: Vec<u64>,
}

#[derive(Clone, Serialize, Default)]
pub struct SystemStats {
    pub processes: u32,
    pub threads: u32,
    pub handles: u32,
    pub inaccessible: u32,
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub debug_privilege: bool,
    pub etw_active: bool,
    pub etw_note: String,
}
