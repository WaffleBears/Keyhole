use crate::sys::{from_wide, reg, wide};
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use windows::Win32::System::SystemInformation::{
    GetSystemInfo, GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::core::PCWSTR;

pub struct SysInfo {
    pub os: String,
    pub host: String,
    pub domain: String,
    pub user: String,
    pub cpu: String,
    pub cores: u32,
    pub arch: String,
    pub mem_total: u64,
    pub mem_avail: u64,
    pub uptime_ms: u64,
    pub boot_unix_ms: i64,
    pub install_unix_ms: i64,
    pub model: String,
    pub bios: String,
    pub firmware: String,
    pub reboot_pending: Vec<String>,
    pub env: Vec<EnvVar>,
    pub drives: Vec<DriveInfo>,
    pub disks: Vec<crate::sys::disks::DiskInfo>,
    pub adapters: Vec<AdapterInfo>,
}

#[derive(Clone, serde::Serialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
    pub scope: String,
}

#[derive(Clone, serde::Serialize)]
pub struct DriveInfo {
    pub letter: String,
    pub label: String,
    pub kind: String,
    pub fs: String,
    pub total: u64,
    pub free: u64,
    pub remote: String,
    pub provider: String,
    pub disk: i64,
    pub note: String,
}

#[derive(Clone, serde::Serialize)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub status: String,
    pub addresses: Vec<String>,
    pub gateways: Vec<String>,
    pub dns: Vec<String>,
    pub mac: String,
    pub kind: String,
}

fn registry_env(root: HKEY, subkey: &str, scope: &str, out: &mut Vec<EnvVar>) {
    let Some(key) = reg::open(root, subkey) else { return };
    for (k, kind, data) in reg::values(&key) {
        if k.is_empty() {
            continue;
        }
        let v = reg::decode_string(kind, &data).unwrap_or_default();
        out.push(EnvVar { key: k, value: v, scope: scope.to_string() });
    }
}

fn drives() -> Vec<DriveInfo> {
    use windows::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
    };
    let mut out = Vec::new();
    let connections = crate::sys::netdrives::connections();
    let disks = crate::sys::disks::map();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = format!("{}:\\", (b'A' + i as u8) as char);
        let wroot = wide(&letter);
        let kind = match unsafe { GetDriveTypeW(PCWSTR(wroot.as_ptr())) } {
            2 => "Removable",
            3 => "Local disk",
            4 => "Network",
            5 => "Optical",
            6 => "RAM disk",
            _ => "Unknown",
        };
        let mut label = [0u16; 261];
        let mut fs = [0u16; 261];
        let mut serial = 0u32;
        let mut maxlen = 0u32;
        let mut flags = 0u32;
        let has_volume = unsafe {
            GetVolumeInformationW(
                PCWSTR(wroot.as_ptr()),
                Some(&mut label),
                Some(&mut serial),
                Some(&mut maxlen),
                Some(&mut flags),
                Some(&mut fs),
            )
            .is_ok()
        };
        let mut free = 0u64;
        let mut total = 0u64;
        let mut total_free = 0u64;
        let _ = unsafe { GetDiskFreeSpaceExW(PCWSTR(wroot.as_ptr()), Some(&mut free), Some(&mut total), Some(&mut total_free)) };
        let short = letter.trim_end_matches('\\').to_string();
        let conn = connections.iter().find(|c| c.local.eq_ignore_ascii_case(&short));
        let disk = disks.values().find(|d| d.letters.iter().any(|l| l.eq_ignore_ascii_case(&short))).map(|d| d.number as i64).unwrap_or(-1);
        out.push(DriveInfo {
            letter: short,
            label: if has_volume { from_wide(&label) } else { String::new() },
            kind: kind.to_string(),
            fs: if has_volume { from_wide(&fs) } else { String::new() },
            total,
            free: total_free,
            remote: conn.map(|c| c.remote.clone()).unwrap_or_default(),
            provider: conn.map(|c| c.provider.clone()).unwrap_or_default(),
            disk,
            note: String::new(),
        });
    }
    let seen: Vec<String> = out.iter().map(|d| d.letter.clone()).collect();
    for c in connections.iter().filter(|c| c.local.is_empty() || !seen.iter().any(|l| l.eq_ignore_ascii_case(&c.local))) {
        out.push(DriveInfo {
            letter: c.local.clone(),
            label: String::new(),
            kind: "Network".into(),
            fs: String::new(),
            total: 0,
            free: 0,
            remote: c.remote.clone(),
            provider: c.provider.clone(),
            disk: -1,
            note: if c.local.is_empty() {
                String::new()
            } else if c.desktop {
                "mapped in your desktop session. Not visible to Keyhole while it runs as administrator".into()
            } else {
                "mapped at logon but not connected right now".into()
            },
        });
    }
    out
}

fn adapters() -> Vec<AdapterInfo> {
    let mut out: Vec<AdapterInfo> = super::netconfig::adapters()
        .into_iter()
        .filter(|a| a.kind != "Loopback" && !(a.ipv4.is_empty() && a.ipv6.is_empty() && !a.up))
        .map(|a| AdapterInfo {
            name: a.name,
            description: a.description,
            status: a.status,
            addresses: a.ipv4.into_iter().chain(a.ipv6).collect(),
            gateways: a.gateways,
            dns: a.dns,
            mac: a.mac,
            kind: a.kind,
        })
        .collect();
    out.sort_by(|x, y| (x.status != "Up").cmp(&(y.status != "Up")).then(x.name.to_lowercase().cmp(&y.name.to_lowercase())));
    out
}

pub fn host_and_domain() -> (String, String) {
    (computer_name(), domain_name())
}

fn domain_name() -> String {
    use windows::Win32::System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW};
    let mut size = 0u32;
    unsafe {
        let _ = GetComputerNameExW(ComputerNameDnsDomain, None, &mut size);
        if size == 0 {
            return String::new();
        }
        let mut buf = vec![0u16; size as usize];
        if GetComputerNameExW(ComputerNameDnsDomain, Some(windows::core::PWSTR(buf.as_mut_ptr())), &mut size).is_ok() {
            from_wide(&buf)
        } else {
            String::new()
        }
    }
}

pub fn collect() -> SysInfo {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    let arch = match unsafe { info.Anonymous.Anonymous.wProcessorArchitecture.0 } {
        9 => "x64",
        5 => "ARM",
        12 => "ARM64",
        0 => "x86",
        _ => "unknown",
    }
    .to_string();

    let mut mem = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let _ = unsafe { GlobalMemoryStatusEx(&mut mem) };
    let uptime = unsafe { GetTickCount64() };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let mut env: Vec<EnvVar> = Vec::new();
    registry_env(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "System", &mut env);
    registry_env(HKEY_CURRENT_USER, "Environment", "User", &mut env);
    registry_env(HKEY_CURRENT_USER, "Volatile Environment", "Session", &mut env);
    env.sort_by(|a, b| a.key.to_lowercase().cmp(&b.key.to_lowercase()).then(a.scope.cmp(&b.scope)));
    let install = reg_dword("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate").map(|d| d as i64 * 1000).unwrap_or(0);
    let manufacturer = reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer").unwrap_or_default();
    let product = reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName").unwrap_or_default();
    let model = format!("{} {}", manufacturer.trim(), product.trim()).trim().to_string();
    let bios_vendor = reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor").unwrap_or_default();
    let bios_version = reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion").unwrap_or_default();
    let bios_date = reg_string("HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSReleaseDate").unwrap_or_default();
    let bios = format!("{} {} {}", bios_vendor.trim(), bios_version.trim(), bios_date.trim()).split_whitespace().collect::<Vec<_>>().join(" ");

    SysInfo {
        os: os_string(),
        host: computer_name(),
        domain: domain_name(),
        user: user_name(),
        cpu: reg_string(
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "ProcessorNameString",
        )
        .unwrap_or_default()
        .trim()
        .to_string(),
        cores: crate::sys::processor_count(),
        arch,
        mem_total: mem.ullTotalPhys,
        mem_avail: mem.ullAvailPhys,
        uptime_ms: uptime,
        boot_unix_ms: now_ms - uptime as i64,
        install_unix_ms: install,
        model,
        bios,
        firmware: firmware(),
        reboot_pending: reboot_pending(),
        env,
        drives: drives(),
        disks: {
            let mut d: Vec<_> = crate::sys::disks::map().into_values().collect();
            d.sort_by_key(|x| x.number);
            d
        },
        adapters: adapters(),
    }
}

fn os_string() -> String {
    let product = reg_string(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "ProductName",
    )
    .unwrap_or_else(|| "Windows".into());
    let display = reg_string(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "DisplayVersion",
    )
    .unwrap_or_default();
    let build = reg_string(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "CurrentBuildNumber",
    )
    .unwrap_or_default();
    let ubr = reg_dword(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "UBR",
    );
    let build_num: u32 = build.parse().unwrap_or(0);
    let mut s = if build_num >= 22000 {
        product.replacen("Windows 10", "Windows 11", 1)
    } else {
        product
    };
    if !display.is_empty() {
        s.push_str(&format!("  {}", display));
    }
    if !build.is_empty() {
        s.push_str(&format!("  (build {}", build));
        if let Some(u) = ubr {
            s.push_str(&format!(".{}", u));
        }
        s.push(')');
    }
    s
}

fn computer_name() -> String {
    use windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
    let mut size = 0u32;
    unsafe {
        let _ = GetComputerNameExW(ComputerNameDnsHostname, None, &mut size);
        if size == 0 {
            return String::new();
        }
        let mut buf = vec![0u16; size as usize];
        if GetComputerNameExW(ComputerNameDnsHostname, Some(windows::core::PWSTR(buf.as_mut_ptr())), &mut size).is_ok() {
            from_wide(&buf)
        } else {
            String::new()
        }
    }
}

fn user_name() -> String {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();
    if domain.is_empty() {
        user
    } else {
        format!("{}\\{}", domain, user)
    }
}

fn firmware() -> String {
    use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, GetFirmwareType};
    let mut kind = FIRMWARE_TYPE::default();
    let base = match unsafe { GetFirmwareType(&mut kind) } {
        Ok(()) if kind.0 == 1 => "Legacy BIOS",
        Ok(()) if kind.0 == 2 => "UEFI",
        _ => "Unknown",
    };
    if base != "UEFI" {
        return base.to_string();
    }
    match reg_dword("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", "UEFISecureBootEnabled") {
        Some(1) => "UEFI, Secure Boot on".to_string(),
        Some(_) => "UEFI, Secure Boot off".to_string(),
        None => "UEFI".to_string(),
    }
}

fn reboot_pending() -> Vec<String> {
    super::updates::reboot_reasons().into_iter().map(|r| r.detail).collect()
}

fn reg_string(subkey: &str, value: &str) -> Option<String> {
    reg::string_at(HKEY_LOCAL_MACHINE, subkey, value)
}

fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
    reg::dword_at(HKEY_LOCAL_MACHINE, subkey, value)
}
