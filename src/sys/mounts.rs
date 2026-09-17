use super::shares::{enum_all, net_error};
use super::{from_wide, pw, wide};
use windows::Win32::NetworkManagement::NetManagement::{NetUseDel, NetUseEnum, USE_INFO_2, USE_LOTS_OF_FORCE};
use windows::Win32::Storage::IscsiDisc::{
    GetDevicesForIScsiSessionW, GetIScsiSessionListW, ISCSI_DEVICE_ON_SESSIONW, ISCSI_SESSION_INFOW, PERSISTENT_ISCSI_LOGIN_INFOW,
    ReportIScsiPersistentLoginsW,
};
use windows::core::PCWSTR;

#[derive(Clone, Debug, Default)]
pub struct MountRow {
    pub local: String,
    pub remote: String,
    pub kind: String,
    pub status: String,
    pub connected: bool,
    pub persistent: bool,
    pub user: String,
    pub detail: String,
    pub desktop: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MountsData {
    pub rows: Vec<MountRow>,
    pub notes: Vec<String>,
}

pub fn use_status(code: u32) -> (&'static str, bool) {
    match code {
        0 => ("connected", true),
        1 => ("paused", true),
        2 => ("disconnected", false),
        3 => ("network error", false),
        4 => ("connecting", false),
        5 => ("reconnecting", false),
        _ => ("unknown", false),
    }
}

pub fn kind_of_provider(provider: &str) -> String {
    let p = provider.to_lowercase();
    if p.contains("windows network") || p.contains("lanman") {
        "SMB".into()
    } else if p.contains("nfs") {
        "NFS".into()
    } else if p.contains("web client") || p.contains("webdav") {
        "WebDAV".into()
    } else if provider.is_empty() {
        "Network".into()
    } else {
        provider.to_string()
    }
}

fn smb_uses(data: &mut MountsData) {
    let mine = net_use_rows();
    match mine {
        Ok(rows) => data.rows.extend(rows),
        Err(2138) | Err(2139) | Err(2140) | Err(1717) | Err(1722) => data.notes.push("the Workstation service is not running, so SMB connections are unknown".into()),
        Err(code) => data.notes.push(format!("SMB connections could not be read ({})", net_error(code))),
    }
    let own = super::netdrives::own_session_id();
    let desktop = super::privilege::desktop_session_id();
    for m in super::netdrives::session_mappings() {
        if m.session == own {
            continue;
        }
        if let Some(row) = data.rows.iter_mut().find(|o| o.local.eq_ignore_ascii_case(&m.local)) {
            if !row.connected {
                row.status = "connected".into();
                row.connected = true;
                row.desktop = true;
                row.detail = if desktop.as_deref() == Some(m.session.as_str()) { "in your desktop session".into() } else { format!("in logon session {}", m.session) };
            }
            continue;
        }
        let mine = desktop.as_deref() == Some(m.session.as_str());
        data.rows.push(MountRow { local: m.local, remote: m.remote, kind: "SMB".into(), status: "connected".into(), connected: true, persistent: false, user: String::new(), detail: if mine { "in your desktop session".into() } else { format!("in logon session {}", m.session) }, desktop: true });
    }
}

fn net_use_rows() -> Result<Vec<MountRow>, u32> {
    let mut resume = 0u32;
    enum_all(
        |buf, read, total| unsafe { NetUseEnum(PCWSTR::null(), 2, Some(buf), u32::MAX, Some(read as *mut u32), total, Some(&mut resume)) },
        |u: &USE_INFO_2| {
            let (status, connected) = use_status(u.ui2_status);
            let user = pw(u.ui2_username);
            let domain = pw(u.ui2_domainname);
            let kind_text = match u.ui2_asg_type.0 {
                0 => "disk",
                1 => "printer",
                2 => "communication device",
                3 => "IPC",
                _ => "resource",
            };
            let detail = format!("{}{}", kind_text, if u.ui2_usecount > 0 { format!(", {} open", u.ui2_usecount) } else { String::new() });
            MountRow {
                local: pw(u.ui2_local).trim_end_matches('\\').to_uppercase(),
                remote: pw(u.ui2_remote),
                kind: "SMB".into(),
                status: status.into(),
                connected,
                persistent: false,
                user: if domain.is_empty() || user.contains('\\') || user.is_empty() { user } else { format!("{}\\{}", domain, user) },
                detail,
                desktop: false,
            }
        },
    )
}

fn other_connections(data: &mut MountsData) {
    let persistent = super::netdrives::persistent_letters();
    for c in super::netdrives::connections_fresh() {
        let is_persistent = persistent.iter().any(|l| l.eq_ignore_ascii_case(&c.local));
        if let Some(row) = data.rows.iter_mut().find(|r| (!c.local.is_empty() && r.local.eq_ignore_ascii_case(&c.local)) || (c.local.is_empty() && r.remote.eq_ignore_ascii_case(&c.remote))) {
            row.persistent = is_persistent;
            if row.kind == "SMB" && !c.provider.is_empty() {
                row.kind = kind_of_provider(&c.provider);
            }
            continue;
        }
        data.rows.push(MountRow {
            local: c.local.clone(),
            remote: c.remote.clone(),
            kind: kind_of_provider(&c.provider),
            status: if c.visible { "connected".into() } else { "remembered".into() },
            connected: c.visible,
            persistent: is_persistent || !c.visible,
            user: String::new(),
            detail: if c.desktop { "in another logon session".into() } else if c.visible { String::new() } else { "mapped at logon but not connected right now".into() },
            desktop: c.desktop,
        });
    }
}

fn wchars(buf: &[u16]) -> String {
    from_wide(buf)
}

fn iscsi_devices(session: &ISCSI_SESSION_INFOW) -> Vec<String> {
    unsafe {
        let mut id = session.SessionId;
        let mut count = 0u32;
        let rc = GetDevicesForIScsiSessionW(&mut id, &mut count, std::ptr::null_mut());
        if rc != 122 || count == 0 {
            return Vec::new();
        }
        let mut devices = vec![ISCSI_DEVICE_ON_SESSIONW::default(); count as usize];
        if GetDevicesForIScsiSessionW(&mut id, &mut count, devices.as_mut_ptr()) != 0 {
            return Vec::new();
        }
        devices
            .iter()
            .take(count as usize)
            .map(|d| {
                if d.StorageDeviceNumber.DeviceType == 7 && d.StorageDeviceNumber.DeviceNumber != u32::MAX {
                    format!("Disk {}", d.StorageDeviceNumber.DeviceNumber)
                } else {
                    let legacy = wchars(&d.LegacyName);
                    if legacy.is_empty() { format!("LUN {}", d.ScsiAddress.Lun) } else { legacy }
                }
            })
            .collect()
    }
}

fn iscsi(data: &mut MountsData) {
    unsafe {
        let mut size = 0u32;
        let mut count = 0u32;
        let rc = GetIScsiSessionListW(&mut size, &mut count, std::ptr::null_mut());
        if rc == 122 && size > 0 {
            let mut buf = vec![0u8; size as usize];
            let rc = GetIScsiSessionListW(&mut size, &mut count, buf.as_mut_ptr() as *mut ISCSI_SESSION_INFOW);
            if rc == 0 {
                let sessions = std::slice::from_raw_parts(buf.as_ptr() as *const ISCSI_SESSION_INFOW, count as usize);
                for s in sessions {
                    let target = pw(s.TargetName);
                    let mut detail = Vec::new();
                    if s.ConnectionCount > 0 && !s.Connections.is_null() {
                        let conns = std::slice::from_raw_parts(s.Connections, s.ConnectionCount as usize);
                        for c in conns {
                            detail.push(format!("{} to {}:{}", pw(c.InitiatorAddress), pw(c.TargetAddress), c.TargetSocket));
                        }
                    }
                    let disks = iscsi_devices(s);
                    data.rows.push(MountRow {
                        local: disks.join(", "),
                        remote: target,
                        kind: "iSCSI".into(),
                        status: "logged in".into(),
                        connected: true,
                        persistent: false,
                        user: String::new(),
                        detail: detail.join("  ·  "),
                        desktop: false,
                    });
                }
            } else {
                data.notes.push(format!("iSCSI sessions could not be read (error {})", rc));
            }
        } else if rc != 0 && rc != 122 {
            let text = match rc {
                1062 | 1058 | 1053 => "the iSCSI Initiator service is not running, so iSCSI targets are unknown".to_string(),
                0xEFFF0009 | 0xEFFF0016 => "the iSCSI Initiator service is not running, so iSCSI targets are unknown".to_string(),
                other => format!("iSCSI sessions could not be read (error {:#x})", other),
            };
            data.notes.push(text);
            return;
        }
        let mut size = 0u32;
        let mut count = 0u32;
        let rc = ReportIScsiPersistentLoginsW(&mut count, std::ptr::null_mut(), &mut size);
        if rc == 122 && size > 0 {
            let mut buf = vec![0u8; size as usize];
            if ReportIScsiPersistentLoginsW(&mut count, buf.as_mut_ptr() as *mut PERSISTENT_ISCSI_LOGIN_INFOW, &mut size) == 0 {
                let logins = std::slice::from_raw_parts(buf.as_ptr() as *const PERSISTENT_ISCSI_LOGIN_INFOW, count as usize);
                for l in logins {
                    let target = wchars(&l.TargetName);
                    let portal = format!("{}:{}", wchars(&l.TargetPortal.Address), l.TargetPortal.Socket);
                    if let Some(row) = data.rows.iter_mut().find(|r| r.kind == "iSCSI" && r.remote.eq_ignore_ascii_case(&target)) {
                        row.persistent = true;
                        continue;
                    }
                    data.rows.push(MountRow {
                        local: String::new(),
                        remote: target,
                        kind: "iSCSI".into(),
                        status: "favorite, not logged in".into(),
                        connected: false,
                        persistent: true,
                        user: String::new(),
                        detail: format!("portal {}", portal),
                        desktop: false,
                    });
                }
            }
        }
    }
}

pub fn list() -> MountsData {
    let mut data = MountsData::default();
    smb_uses(&mut data);
    other_connections(&mut data);
    iscsi(&mut data);
    data.rows.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.local.cmp(&b.local)).then_with(|| a.remote.to_lowercase().cmp(&b.remote.to_lowercase())));
    data
}

pub fn disconnect(name: &str) -> Result<(), String> {
    let w = wide(name);
    let rc = unsafe { NetUseDel(PCWSTR::null(), PCWSTR(w.as_ptr()), USE_LOTS_OF_FORCE) };
    if rc == 0 { Ok(()) } else { Err(net_error(rc)) }
}

pub fn summary(r: &MountRow) -> String {
    let mut s = format!("{}{}\n{}  ·  {}", if r.local.is_empty() { String::new() } else { format!("{}  ", r.local) }, r.remote, r.kind, r.status);
    if !r.user.is_empty() {
        s.push_str(&format!("\nAs {}", r.user));
    }
    if !r.detail.is_empty() {
        s.push_str(&format!("\n{}", r.detail));
    }
    if r.persistent {
        s.push_str("\nReconnects at logon");
    }
    s
}
