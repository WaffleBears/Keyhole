use crate::sys::{actions, from_wide, reg, wide, winerr};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY,
    REG_BINARY, REG_OPTION_NON_VOLATILE, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW,
};
use windows::core::PCWSTR;

#[derive(Clone, serde::Serialize)]
pub struct StartupRow {
    pub name: String,
    pub command: String,
    pub image_path: String,
    pub location: String,
    pub scope: String,
    pub source: String,
    pub enabled: bool,
}

const APPROVED: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved";
const RUN: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUNONCE: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
const RUNONCEEX: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx";
const WOW_RUN: &str = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
const POLICY_RUN: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run";
const WINLOGON: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

fn approved_key(source: &str, scope: &str) -> Option<(HKEY, String)> {
    let sub = match source {
        "hklm_run" => "Run",
        "hklm_wow_run" => "Run32",
        "hkcu_run" => "Run",
        "folder" => "StartupFolder",
        _ => return None,
    };
    let root = if source.starts_with("hkcu") || (source == "folder" && scope.starts_with("Current user")) {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    Some((root, format!("{}\\{}", APPROVED, sub)))
}

fn is_enabled(source: &str, scope: &str, name: &str) -> bool {
    let Some((root, sub)) = approved_key(source, scope) else { return true };
    let Some(key) = reg::open_with(root, &sub, KEY_READ | KEY_WOW64_64KEY) else { return true };
    match reg::raw(&key, name) {
        Some((_, data)) if !data.is_empty() => data[0] & 1 == 0,
        _ => true,
    }
}

pub fn set_enabled(source: &str, scope: &str, name: &str, enabled: bool) -> Result<(), String> {
    let (root, sub) = approved_key(source, scope).ok_or("this kind of entry cannot be toggled. Remove it instead")?;
    let wsub = wide(&sub);
    let wname = wide(name);
    let mut data = [0u8; 12];
    data[0] = if enabled { 0x02 } else { 0x03 };
    if !enabled {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64 / 100 + 116_444_736_000_000_000)
            .unwrap_or(0);
        data[4..12].copy_from_slice(&now.to_le_bytes());
    }
    unsafe {
        let mut key = HKEY::default();
        let r = RegCreateKeyExW(root, PCWSTR(wsub.as_ptr()), None, None, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_WOW64_64KEY, None, &mut key, None);
        if r.is_err() {
            return Err("could not open the startup settings key".into());
        }
        let key = reg::Key(key);
        let w = RegSetValueExW(key.0, PCWSTR(wname.as_ptr()), None, REG_BINARY, Some(&data));
        if w.is_ok() { Ok(()) } else { Err("could not write the startup state".into()) }
    }
}

fn source_key(source: &str) -> Option<(HKEY, &'static str, bool)> {
    Some(match source {
        "hklm_run" => (HKEY_LOCAL_MACHINE, RUN, true),
        "hklm_runonce" => (HKEY_LOCAL_MACHINE, RUNONCE, true),
        "hklm_runonceex" => (HKEY_LOCAL_MACHINE, RUNONCEEX, true),
        "hklm_wow_run" => (HKEY_LOCAL_MACHINE, WOW_RUN, false),
        "hklm_policy_run" => (HKEY_LOCAL_MACHINE, POLICY_RUN, true),
        "hkcu_run" => (HKEY_CURRENT_USER, RUN, false),
        "hkcu_runonce" => (HKEY_CURRENT_USER, RUNONCE, false),
        "hkcu_policy_run" => (HKEY_CURRENT_USER, POLICY_RUN, false),
        _ => return None,
    })
}

pub fn remove(source: &str, name: &str, command: &str) -> Result<(), String> {
    if source == "folder" {
        return std::fs::remove_file(command).map_err(|e| format!("could not delete the shortcut: {}", e));
    }
    if source == "winlogon" {
        return Err("Winlogon entries are system settings. Edit them in the Registry Editor instead".into());
    }
    let (root, subkey, wow) = source_key(source).ok_or("unknown startup source")?;
    let mut flags = KEY_SET_VALUE;
    if wow {
        flags |= KEY_WOW64_64KEY;
    }
    let key = reg::open_with(root, subkey, flags)
        .ok_or("could not open the registry key")?;
    let wname = wide(name);
    let r = unsafe { RegDeleteValueW(key.0, PCWSTR(wname.as_ptr())) };
    if r.is_err() {
        return Err(format!("could not delete the entry: {}", winerr::text(r.0)));
    }
    let scope = if source.starts_with("hkcu") { "Current user" } else { "All users" };
    if let Some((aroot, asub)) = approved_key(source, scope)
        && let Some(akey) = reg::open_with(aroot, &asub, KEY_SET_VALUE | KEY_WOW64_64KEY) {
            let _ = unsafe { RegDeleteValueW(akey.0, PCWSTR(wname.as_ptr())) };
        }
    Ok(())
}

fn read_run_key(root: HKEY, subkey: &str, wow64: bool, location: &str, scope: &str, source: &str, out: &mut Vec<StartupRow>) {
    let mut flags = KEY_READ;
    if wow64 {
        flags |= KEY_WOW64_64KEY;
    }
    let Some(key) = reg::open_with(root, subkey, flags) else { return };
    for (value_name, kind, data) in reg::values(&key) {
        if kind != reg::REG_SZ && kind != reg::REG_EXPAND_SZ {
            continue;
        }
        let command = reg::decode_string(kind, &data).unwrap_or_default();
        if command.trim().is_empty() {
            continue;
        }
        out.push(StartupRow {
            image_path: actions::exe_from_command(&command),
            enabled: is_enabled(source, scope, &value_name),
            name: value_name,
            command,
            location: location.to_string(),
            scope: scope.to_string(),
            source: source.to_string(),
        });
    }
}

fn read_run_once_ex(out: &mut Vec<StartupRow>) {
    let Some(key) = reg::open_with(HKEY_LOCAL_MACHINE, RUNONCEEX, KEY_READ | KEY_WOW64_64KEY) else { return };
    for sub in reg::subkeys(&key) {
        let Some(k) = reg::open_with(HKEY_LOCAL_MACHINE, &format!("{}\\{}", RUNONCEEX, sub), KEY_READ | KEY_WOW64_64KEY) else { continue };
        for (value_name, kind, data) in reg::values(&k) {
            if kind != reg::REG_SZ && kind != reg::REG_EXPAND_SZ {
                continue;
            }
            let command = reg::decode_string(kind, &data).unwrap_or_default();
            if command.trim().is_empty() {
                continue;
            }
            out.push(StartupRow {
                image_path: actions::exe_from_command(&command),
                enabled: true,
                name: if value_name.is_empty() { sub.clone() } else { format!("{} ({})", sub, value_name) },
                command,
                location: "HKLM\\...\\RunOnceEx".into(),
                scope: "All users".into(),
                source: "hklm_runonceex".into(),
            });
        }
    }
}

fn read_winlogon(out: &mut Vec<StartupRow>) {
    let Some(key) = reg::open(HKEY_LOCAL_MACHINE, WINLOGON) else { return };
    let defaults = [("Shell", "explorer.exe"), ("Userinit", "userinit.exe")];
    for (name, default) in defaults {
        let Some(value) = reg::string(&key, name) else { continue };
        let entries: Vec<&str> = value.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        for entry in entries {
            let lower = entry.to_lowercase();
            let is_default = lower.ends_with(default) && !lower.contains(' ');
            out.push(StartupRow {
                image_path: actions::exe_from_command(entry),
                enabled: true,
                name: if is_default { format!("{} (Windows default)", name) } else { format!("{} (custom)", name) },
                command: entry.to_string(),
                location: "HKLM\\...\\Winlogon".into(),
                scope: "All users".into(),
                source: "winlogon".into(),
            });
        }
    }
}

fn read_startup_folder(path: &std::path::Path, location: &str, scope: &str, out: &mut Vec<StartupRow>) {
    let Ok(entries) = std::fs::read_dir(path) else { return };
    for entry in entries.flatten() {
        let p = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if fname.eq_ignore_ascii_case("desktop.ini") {
            continue;
        }
        out.push(StartupRow {
            enabled: is_enabled("folder", scope, &fname),
            name: fname,
            command: p.to_string_lossy().to_string(),
            image_path: resolve_link(&p),
            location: location.to_string(),
            scope: scope.to_string(),
            source: "folder".to_string(),
        });
    }
}

fn resolve_link(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().to_string();
    if !s.to_lowercase().ends_with(".lnk") {
        return s;
    }
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, IPersistFile, STGM_READ};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::Interface;
    let _com = crate::sys::com::ComGuard::sta();
    unsafe {
        let Ok(link) = CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER) else {
            return String::new();
        };
        let Ok(file) = link.cast::<IPersistFile>() else {
            return String::new();
        };
        let wpath = wide(&s);
        if file.Load(PCWSTR(wpath.as_ptr()), STGM_READ).is_err() {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        if link.GetPath(&mut buf, std::ptr::null_mut(), 0).is_err() {
            return String::new();
        }
        actions::expand_env(&from_wide(&buf))
    }
}

pub fn current_user_scope(current_sid: &str) -> String {
    match crate::sys::privilege::desktop_user_sid() {
        Some(desktop) if !current_sid.is_empty() && desktop != current_sid => {
            let who = crate::sys::accounts::name_of_sid_text(current_sid).map(|n| n.rsplit('\\').next().unwrap_or(&n).to_string()).unwrap_or_else(|| current_sid.to_string());
            format!("Current user ({}, the account you elevated with)", who)
        }
        _ => "Current user".to_string(),
    }
}

pub fn other_user_hives() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(users) = reg::open(HKEY_USERS, "") else { return out };
    let profiles = reg::open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
    for sid in reg::subkeys(&users) {
        if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
            continue;
        }
        let label = profiles
            .as_ref()
            .and_then(|_| reg::string_at(HKEY_LOCAL_MACHINE, &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{}", sid), "ProfileImagePath"))
            .map(|p| p.rsplit('\\').next().unwrap_or(&p).to_string())
            .unwrap_or_else(|| sid.clone());
        out.push((sid, label));
    }
    out
}

pub fn list() -> Vec<StartupRow> {
    let mut out = Vec::new();
    read_run_key(HKEY_LOCAL_MACHINE, RUN, true, "HKLM\\...\\Run", "All users", "hklm_run", &mut out);
    read_run_key(HKEY_LOCAL_MACHINE, RUNONCE, true, "HKLM\\...\\RunOnce", "All users", "hklm_runonce", &mut out);
    read_run_once_ex(&mut out);
    read_run_key(HKEY_LOCAL_MACHINE, WOW_RUN, false, "HKLM\\WOW6432\\Run", "All users", "hklm_wow_run", &mut out);
    read_run_key(HKEY_LOCAL_MACHINE, POLICY_RUN, true, "HKLM\\...\\Policies\\Explorer\\Run", "All users", "hklm_policy_run", &mut out);
    let current_sid = crate::sys::privilege::current_user_sid().unwrap_or_default();
    let mine = current_user_scope(&current_sid);
    read_run_key(HKEY_CURRENT_USER, RUN, false, "HKCU\\...\\Run", &mine, "hkcu_run", &mut out);
    read_run_key(HKEY_CURRENT_USER, RUNONCE, false, "HKCU\\...\\RunOnce", &mine, "hkcu_runonce", &mut out);
    read_run_key(HKEY_CURRENT_USER, POLICY_RUN, false, "HKCU\\...\\Policies\\Explorer\\Run", &mine, "hkcu_policy_run", &mut out);
    read_winlogon(&mut out);

    for (sid, label) in other_user_hives() {
        if sid == current_sid {
            continue;
        }
        let scope = format!("User {}", label);
        read_run_key(HKEY_USERS, &format!("{}\\{}", sid, RUN), false, "HKU\\...\\Run", &scope, "hku_run", &mut out);
        read_run_key(HKEY_USERS, &format!("{}\\{}", sid, RUNONCE), false, "HKU\\...\\RunOnce", &scope, "hku_runonce", &mut out);
    }

    if let Ok(appdata) = std::env::var("APPDATA") {
        read_startup_folder(&std::path::Path::new(&appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"), "Startup folder", &mine, &mut out);
    }
    if let Ok(programdata) = std::env::var("ProgramData") {
        read_startup_folder(&std::path::Path::new(&programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"), "Startup folder", "All users", &mut out);
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}
