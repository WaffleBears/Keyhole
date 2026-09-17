use crate::sys::reg;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_SAM_FLAGS,
};

#[derive(Clone, serde::Serialize)]
pub struct SoftwareRow {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub installed: String,
    pub location: String,
    pub scope: String,
    pub uninstall: String,
    pub modify: String,
    pub key: String,
    pub size: u64,
}

const UNINSTALL: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

pub fn list() -> Vec<SoftwareRow> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    enum_key(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, "All users", &mut out, &mut seen);
    enum_key(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, "All users (32-bit)", &mut out, &mut seen);
    let me = crate::sys::privilege::current_user_sid().unwrap_or_default();
    enum_key(HKEY_CURRENT_USER, REG_SAM_FLAGS(0), &crate::sys::startup::current_user_scope(&me), &mut out, &mut seen);
    for (sid, label) in crate::sys::startup::other_user_hives() {
        if sid != me {
            enum_user_hive(&sid, &format!("User {}", label), &mut out, &mut seen);
        }
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

fn enum_user_hive(sid: &str, scope: &str, out: &mut Vec<SoftwareRow>, seen: &mut std::collections::HashSet<String>) {
    let base = format!("{}\\{}", sid, UNINSTALL);
    enum_under(windows::Win32::System::Registry::HKEY_USERS, &base, REG_SAM_FLAGS(0), &format!("HKU\\{}", base), scope, out, seen);
}

fn enum_key(root: HKEY, wow: REG_SAM_FLAGS, scope: &str, out: &mut Vec<SoftwareRow>, seen: &mut std::collections::HashSet<String>) {
    let key_prefix = format!(
        "{}\\{}",
        if root == HKEY_CURRENT_USER { "HKCU" } else { "HKLM" },
        if wow == KEY_WOW64_32KEY { UNINSTALL.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\") } else { UNINSTALL.to_string() }
    );
    enum_under(root, UNINSTALL, wow, &key_prefix, scope, out, seen);
}

fn enum_under(root: HKEY, base: &str, wow: REG_SAM_FLAGS, key_prefix: &str, scope: &str, out: &mut Vec<SoftwareRow>, seen: &mut std::collections::HashSet<String>) {
    let Some(key) = reg::open_with(root, base, KEY_READ | wow) else { return };
    for sub in reg::subkeys(&key) {
        let Some(item) = reg::open_with(root, &format!("{}\\{}", base, sub), KEY_READ | wow) else { continue };
        let Some(name) = reg::string(&item, "DisplayName") else { continue };
        if reg::dword(&item, "SystemComponent").unwrap_or(0) != 0 || reg::string(&item, "ParentKeyName").is_some() {
            continue;
        }
        let version = reg::string(&item, "DisplayVersion").unwrap_or_default();
        let owner = if root == HKEY_LOCAL_MACHINE { "machine" } else { scope };
        let uninstall_key = reg::string(&item, "UninstallString").unwrap_or_default().to_lowercase();
        if !seen.insert(format!("{}|{}|{}|{}", name.to_lowercase(), version, owner, uninstall_key)) {
            continue;
        }
        out.push(SoftwareRow {
            publisher: reg::string(&item, "Publisher").unwrap_or_default(),
            installed: fmt_install_date(reg::string(&item, "InstallDate")),
            location: reg::string(&item, "InstallLocation").unwrap_or_default(),
            scope: scope.to_string(),
            uninstall: reg::string(&item, "UninstallString")
                .or_else(|| reg::string(&item, "QuietUninstallString"))
                .unwrap_or_default(),
            modify: reg::string(&item, "ModifyPath").unwrap_or_default(),
            key: format!("{}\\{}", key_prefix, sub),
            size: reg::dword(&item, "EstimatedSize").map(|kb| kb as u64 * 1024).unwrap_or(0),
            name,
            version,
        });
    }
}

pub fn fmt_install_date(raw: Option<String>) -> String {
    match raw {
        Some(s) if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) => {
            let month: u32 = s[4..6].parse().unwrap_or(0);
            let day: u32 = s[6..8].parse().unwrap_or(0);
            if (1..=12).contains(&month) && (1..=31).contains(&day) {
                format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8])
            } else {
                String::new()
            }
        }
        Some(s) => s,
        None => String::new(),
    }
}
