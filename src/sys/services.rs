use crate::sys::{from_wide, wide, winerr};
use std::collections::HashMap;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService, DeleteService,
    ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_TYPE, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatus, SC_ENUM_PROCESS_INFO,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_PAUSE_CONTINUE,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_CONTINUE,
    SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DEMAND_START,
    SERVICE_DESCRIPTIONW, SERVICE_DISABLED, SERVICE_DRIVER, SERVICE_ERROR, SERVICE_NO_CHANGE,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_START_TYPE, SERVICE_STATE_ALL,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_WIN32, StartServiceW,
};
use windows::core::PCWSTR;

const SERVICE_USER_SERVICE: u32 = 0x40;

struct Scm(SC_HANDLE);

impl Drop for Scm {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

struct Svc(SC_HANDLE);

impl Drop for Svc {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn open_scm(access: u32) -> Result<Scm, String> {
    unsafe {
        OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access)
            .map(Scm)
            .map_err(|e| scm_err(&e))
    }
}

fn open_service(scm: &Scm, name: &str, access: u32) -> Result<Svc, String> {
    let wname = wide(name);
    unsafe {
        OpenServiceW(scm.0, PCWSTR(wname.as_ptr()), access)
            .map(Svc)
            .map_err(|e| format!("could not open the service: {}", short(&e)))
    }
}

pub const CORE_SERVICES: &[&str] = &[
    "rpcss", "rpceptmapper", "dcomlaunch", "lsm", "samss", "keyiso", "cryptsvc", "eventlog", "winmgmt", "plugplay", "power", "brokerinfrastructure",
    "profsvc", "usermanager", "schedule", "themes", "seclogon", "coremessagingregistrar", "systemeventsbroker", "wlansvc", "nsi", "dhcp", "dnscache",
    "lanmanserver", "lanmanworkstation", "termservice", "sessionenv", "umrdpservice", "netlogon", "kdc", "ntds", "dfsr", "w32time", "wuauserv", "trustedinstaller",
];

pub fn core_guard(name: &str, verb: &str) -> Result<(), String> {
    if CORE_SERVICES.iter().any(|c| c.eq_ignore_ascii_case(name)) {
        return Err(format!("{} is a core Windows service. To {} it could leave this machine unbootable or unreachable, so Keyhole refuses", name, verb));
    }
    Ok(())
}

pub fn control(name: &str, action: &str) -> Result<(), String> {
    match action {
        "delete" => core_guard(name, "delete")?,
        "disable" => core_guard(name, "disable")?,
        _ => {}
    }
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let access = match action {
        "start" => SERVICE_START | SERVICE_QUERY_STATUS,
        "stop" | "restart" => SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS,
        "pause" | "continue" => SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        "delete" => windows::Win32::Storage::FileSystem::DELETE.0 | SERVICE_STOP | SERVICE_QUERY_STATUS,
        _ => SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG,
    };
    let svc = open_service(&scm, name, access)?;
    let result = unsafe {
        match action {
            "start" => start(svc.0),
            "stop" => stop(svc.0).map(|_| ()),
            "pause" => {
                let mut status = SERVICE_STATUS::default();
                ControlService(svc.0, SERVICE_CONTROL_PAUSE, &mut status).map_err(|e| format!("could not pause: {}", short(&e)))
            }
            "continue" => {
                let mut status = SERVICE_STATUS::default();
                ControlService(svc.0, SERVICE_CONTROL_CONTINUE, &mut status).map_err(|e| format!("could not continue: {}", short(&e)))
            }
            "enableAutoDelayed" => {
                set_start(svc.0, SERVICE_AUTO_START)?;
                let mut info = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: windows::core::BOOL(1) };
                ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some(&mut info as *mut _ as *mut std::ffi::c_void))
                    .map_err(|e| format!("could not set delayed start: {}", short(&e)))
            }
            "restart" => {
                let mut status = SERVICE_STATUS::default();
                let running = QueryServiceStatus(svc.0, &mut status).is_ok() && status.dwCurrentState != SERVICE_STOPPED;
                if running {
                    stop(svc.0)?;
                    if !wait_stopped(svc.0) {
                        return Err("it has not stopped after 30 seconds. Start it again once it has".into());
                    }
                }
                start(svc.0)
            }
            "enableAuto" => {
                set_start(svc.0, SERVICE_AUTO_START)?;
                let mut info = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: windows::core::BOOL(0) };
                ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some(&mut info as *mut _ as *mut std::ffi::c_void))
                    .map_err(|e| format!("could not clear delayed start: {}", short(&e)))
            }
            "enableManual" => set_start(svc.0, SERVICE_DEMAND_START),
            "disable" => set_start(svc.0, SERVICE_DISABLED),
            "delete" => {
                let _ = stop(svc.0);
                DeleteService(svc.0).map_err(|e| format!("could not delete: {}", short(&e)))
            }
            other => Err(format!("unknown service action {}", other)),
        }
    };
    forget_config(name);
    result
}

unsafe fn start(svc: SC_HANDLE) -> Result<(), String> {
    unsafe {
        StartServiceW(svc, None).map_err(|e| {
            if winerr::code_of(&e) == 1056 { "already running".to_string() } else { format!("could not start: {}", short(&e)) }
        })
    }
}

unsafe fn stop(svc: SC_HANDLE) -> Result<SERVICE_STATUS, String> {
    unsafe {
        let mut status = SERVICE_STATUS::default();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status)
            .map(|_| status)
            .map_err(|e| format!("could not stop: {}", short(&e)))
    }
}

unsafe fn wait_stopped(svc: SC_HANDLE) -> bool {
    unsafe {
        for _ in 0..300 {
            let mut status = SERVICE_STATUS::default();
            if QueryServiceStatus(svc, &mut status).is_err() || status.dwCurrentState == SERVICE_STOPPED {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }
}

unsafe fn set_start(svc: SC_HANDLE, start_type: SERVICE_START_TYPE) -> Result<(), String> {
    unsafe {
        ChangeServiceConfigW(
            svc,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start_type,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
        .map_err(|e| format!("could not change the start type: {}", short(&e)))
    }
}

fn scm_err(e: &windows::core::Error) -> String {
    format!("the Service Control Manager could not be reached: {}", short(e))
}

fn short(e: &windows::core::Error) -> String {
    winerr::describe(e)
}

pub struct RawService {
    pub name: String,
    pub display: String,
    pub state: u32,
    pub pid: u32,
    pub service_type: u32,
    pub controls_accepted: u32,
}

pub fn enumerate(service_type: ENUM_SERVICE_TYPE) -> Vec<RawService> {
    let mut out = Vec::new();
    let Ok(scm) = open_scm(SC_MANAGER_ENUMERATE_SERVICE) else { return out };
    unsafe {
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(scm.0, SC_ENUM_PROCESS_INFO, service_type, SERVICE_STATE_ALL, None, &mut needed, &mut count, Some(&mut resume), PCWSTR::null());
        if needed == 0 {
            return out;
        }
        let mut buf = vec![0u8; needed as usize + 8192];
        let mut resume2 = 0u32;
        for _ in 0..8 {
            let r = EnumServicesStatusExW(scm.0, SC_ENUM_PROCESS_INFO, service_type, SERVICE_STATE_ALL, Some(&mut buf), &mut needed, &mut count, Some(&mut resume2), PCWSTR::null());
            let more = matches!(&r, Err(e) if e.code() == windows::Win32::Foundation::ERROR_MORE_DATA.to_hresult());
            if r.is_err() && !more {
                return out;
            }
            let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
            for i in 0..count as usize {
                let e = &*entries.add(i);
                let name = read_pwstr(e.lpServiceName.0);
                if name.is_empty() {
                    continue;
                }
                let st = &e.ServiceStatusProcess;
                out.push(RawService {
                    name,
                    display: read_pwstr(e.lpDisplayName.0),
                    state: st.dwCurrentState.0,
                    pid: st.dwProcessId,
                    service_type: st.dwServiceType.0,
                    controls_accepted: st.dwControlsAccepted,
                });
            }
            if !more {
                break;
            }
            buf = vec![0u8; needed as usize + 8192];
        }
    }
    out
}

pub fn by_pid() -> HashMap<u32, Vec<String>> {
    let mut map: HashMap<u32, Vec<String>> = HashMap::new();
    for s in enumerate(SERVICE_WIN32) {
        if s.pid != 0 {
            map.entry(s.pid).or_default().push(s.name);
        }
    }
    for v in map.values_mut() {
        v.sort();
    }
    map
}

#[derive(Clone, serde::Serialize)]
pub struct ServiceRow {
    pub name: String,
    pub display: String,
    pub state: String,
    pub pid: u32,
    pub kind: String,
    pub start_type: String,
    pub account: String,
    pub binary: String,
    pub exe: String,
    pub in_windows: bool,
    pub description: String,
    pub depends_on: Vec<String>,
}

#[derive(Clone, Default)]
pub struct ServiceConfig {
    pub start_type: String,
    pub account: String,
    pub binary: String,
    pub description: String,
    pub depends_on: Vec<String>,
}

static CONFIG_CACHE: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, (ServiceConfig, std::time::Instant)>>> = std::sync::OnceLock::new();

pub fn forget_config(name: &str) {
    if let Some(c) = CONFIG_CACHE.get() {
        c.lock().remove(&name.to_lowercase());
    }
}

fn cached_config(scm: &Scm, name: &str) -> ServiceConfig {
    let cache = CONFIG_CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()));
    let key = name.to_lowercase();
    if let Some((cfg, at)) = cache.lock().get(&key)
        && at.elapsed() < std::time::Duration::from_secs(60) {
            return cfg.clone();
        }
    let cfg = open_service(scm, name, SERVICE_QUERY_CONFIG).ok().and_then(|svc| query_config(&svc)).unwrap_or_default();
    cache.lock().insert(key, (cfg.clone(), std::time::Instant::now()));
    cfg
}

pub fn start_type_text(t: u32, delayed: bool) -> String {
    match t {
        0 => "Boot".into(),
        1 => "System".into(),
        2 => if delayed { "Automatic (delayed)".into() } else { "Automatic".into() },
        3 => "Manual".into(),
        4 => "Disabled".into(),
        _ => String::new(),
    }
}

fn query_config(svc: &Svc) -> Option<ServiceConfig> {
    unsafe {
        let mut out = ServiceConfig::default();
        let mut needed = 0u32;
        let _ = QueryServiceConfigW(svc.0, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if QueryServiceConfigW(svc.0, Some(buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW), needed, &mut needed).is_err() {
            return None;
        }
        let cfg = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
        let mut delayed = false;
        let mut info = SERVICE_DELAYED_AUTO_START_INFO::default();
        let mut n2 = 0u32;
        if QueryServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            Some(std::slice::from_raw_parts_mut(&mut info as *mut _ as *mut u8, std::mem::size_of::<SERVICE_DELAYED_AUTO_START_INFO>())),
            &mut n2,
        )
        .is_ok()
        {
            delayed = info.fDelayedAutostart.as_bool();
        }
        out.start_type = start_type_text(cfg.dwStartType.0, delayed);
        out.binary = crate::sys::actions::expand_env(&read_pwstr(cfg.lpBinaryPathName.0));
        out.account = read_pwstr(cfg.lpServiceStartName.0);
        out.depends_on = read_multi(cfg.lpDependencies.0);
        let mut dneeded = 0u32;
        let _ = QueryServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, None, &mut dneeded);
        if dneeded > 0 {
            let mut dbuf = vec![0u8; dneeded as usize];
            if QueryServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, Some(&mut dbuf), &mut dneeded).is_ok() {
                let d = &*(dbuf.as_ptr() as *const SERVICE_DESCRIPTIONW);
                out.description = read_pwstr(d.lpDescription.0).replace(['\r', '\n'], " ");
            }
        }
        Some(out)
    }
}

pub fn state_text(s: u32) -> &'static str {
    match s {
        1 => "Stopped",
        2 => "Starting",
        3 => "Stopping",
        4 => "Running",
        5 => "Continue pending",
        6 => "Pause pending",
        7 => "Paused",
        _ => "Unknown",
    }
}

pub fn list() -> Vec<ServiceRow> {
    let raw = enumerate(SERVICE_WIN32 | ENUM_SERVICE_TYPE(SERVICE_USER_SERVICE));
    let Ok(scm) = open_scm(SC_MANAGER_CONNECT) else { return Vec::new() };
    let mut out: Vec<ServiceRow> = raw
        .into_iter()
        .map(|s| {
            let kind = if s.service_type & 0x80 != 0 {
                "User service (this logon)"
            } else if s.service_type & SERVICE_USER_SERVICE != 0 {
                "User service template"
            } else if s.service_type & 0x10 != 0 {
                "Own process"
            } else if s.service_type & 0x20 != 0 {
                "Shared process"
            } else {
                "Service"
            };
            let cfg = cached_config(&scm, &s.name);
            let exe = if cfg.binary.is_empty() { String::new() } else { crate::sys::actions::exe_from_command(&cfg.binary) };
            let in_windows = crate::sys::in_windows_dir(&exe);
            ServiceRow {
                name: s.name,
                display: s.display,
                state: state_text(s.state).to_string(),
                pid: s.pid,
                kind: kind.to_string(),
                start_type: cfg.start_type,
                account: cfg.account,
                binary: cfg.binary,
                exe,
                in_windows,
                description: cfg.description,
                depends_on: cfg.depends_on,
            }
        })
        .collect();
    out.sort_by_key(|a| a.display.to_lowercase());
    out
}

pub fn driver_states() -> HashMap<String, (u32, u32)> {
    enumerate(SERVICE_DRIVER)
        .into_iter()
        .map(|s| (s.name.to_lowercase(), (s.state, s.service_type)))
        .collect()
}

unsafe fn read_multi(p: *const u16) -> Vec<String> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    unsafe {
        let mut offset = 0usize;
        loop {
            let s = read_pwstr(p.add(offset));
            if s.is_empty() {
                break;
            }
            offset += s.encode_utf16().count() + 1;
            out.push(s.strip_prefix('+').map(|g| format!("{} (group)", g)).unwrap_or(s));
        }
    }
    out
}

unsafe fn read_pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 && len < 8192 {
            len += 1;
        }
        from_wide(std::slice::from_raw_parts(p, len))
    }
}
