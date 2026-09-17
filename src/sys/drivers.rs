use crate::sys::{actions, reg, services, strip_prefix_ci, system_root};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

#[derive(Clone, serde::Serialize)]
pub struct DriverRow {
    pub name: String,
    pub display: String,
    pub path: String,
    pub version: String,
    pub company: String,
    pub description: String,
    pub state: String,
    pub start_type: String,
    pub kind: String,
    pub running: bool,
    pub trust: String,
}

const SERVICES: &str = "SYSTEM\\CurrentControlSet\\Services";

pub fn list() -> Vec<DriverRow> {
    let mut out = Vec::new();
    let sysroot = system_root();
    let states = services::driver_states();
    let Some(root) = reg::open(HKEY_LOCAL_MACHINE, SERVICES) else { return out };
    for name in reg::subkeys(&root) {
        let Some(key) = reg::open(HKEY_LOCAL_MACHINE, &format!("{}\\{}", SERVICES, name)) else { continue };
        let kind = reg::dword(&key, "Type");
        if !matches!(kind, Some(1) | Some(2)) {
            continue;
        }
        let path = resolve_driver_path(reg::string(&key, "ImagePath").as_deref(), &name, &sysroot);
        let start = reg::dword(&key, "Start").unwrap_or(3);
        let display = reg::string(&key, "DisplayName").map(|d| crate::sys::firewall::resolve_indirect(&d)).unwrap_or_default();
        let ver = if path.is_empty() { Default::default() } else { crate::sys::version::read(&path) };
        let (state, running) = match states.get(&name.to_lowercase()) {
            Some((s, _)) => (services::state_text(*s).to_string(), *s == 4),
            None => ("Not registered".to_string(), false),
        };
        out.push(DriverRow {
            display: if display.is_empty() { name.clone() } else { display },
            name,
            path,
            version: ver.version,
            company: ver.company,
            description: ver.description,
            state,
            start_type: services::start_type_text(start, false),
            kind: if kind == Some(2) { "File system".into() } else { "Kernel".into() },
            running,
            trust: String::new(),
        });
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

fn resolve_driver_path(image: Option<&str>, name: &str, sysroot: &str) -> String {
    let raw = match image {
        Some(s) if !s.trim().is_empty() => actions::expand_env(s),
        _ => format!("{}\\System32\\drivers\\{}.sys", sysroot, name),
    };
    let raw = raw.trim();
    if let Some(rest) = strip_prefix_ci(raw, "\\SystemRoot\\") {
        format!("{}\\{}", sysroot, rest)
    } else if let Some(rest) = strip_prefix_ci(raw, "\\??\\") {
        rest.to_string()
    } else if let Some(rest) = strip_prefix_ci(raw, "System32\\") {
        format!("{}\\System32\\{}", sysroot, rest)
    } else if raw.as_bytes().get(1) == Some(&b':') && raw.as_bytes()[0].is_ascii_alphabetic() {
        raw.to_string()
    } else {
        format!("{}\\System32\\{}", sysroot, raw.trim_start_matches('\\'))
    }
}
