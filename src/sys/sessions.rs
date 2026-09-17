
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSClientAddress, WTSClientName, WTSDomainName,
    WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
};

pub fn logoff(id: u32) -> Result<(), String> {
    use windows::Win32::System::RemoteDesktop::WTSLogoffSession;
    unsafe {
        WTSLogoffSession(Some(WTS_CURRENT_SERVER_HANDLE), id, false)
            .map_err(|e| session_err(&e))
    }
}

pub fn disconnect(id: u32) -> Result<(), String> {
    use windows::Win32::System::RemoteDesktop::WTSDisconnectSession;
    unsafe {
        WTSDisconnectSession(Some(WTS_CURRENT_SERVER_HANDLE), id, false)
            .map_err(|e| session_err(&e))
    }
}

fn session_err(e: &windows::core::Error) -> String {
    crate::sys::winerr::describe(e)
}

#[derive(Clone, serde::Serialize)]
pub struct SessionRow {
    pub id: u32,
    pub user: String,
    pub state: String,
    pub win_station: String,
    pub client: String,
    pub client_address: String,
    pub logon_ms: i64,
    pub idle_ms: i64,
    pub connect_ms: i64,
}

pub fn send_message(id: u32, title: &str, text: &str) -> Result<(), String> {
    use windows::Win32::System::RemoteDesktop::WTSSendMessageW;
    let wtitle = crate::sys::wide(title);
    let wtext = crate::sys::wide(text);
    let mut response = windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT(0);
    unsafe {
        WTSSendMessageW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            id,
            windows::core::PCWSTR(wtitle.as_ptr()),
            ((wtitle.len() - 1) * 2) as u32,
            windows::core::PCWSTR(wtext.as_ptr()),
            ((wtext.len() - 1) * 2) as u32,
            windows::Win32::UI::WindowsAndMessaging::MB_OK | windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION,
            0,
            &mut response,
            false,
        )
        .map_err(|e| session_err(&e))
    }
}

unsafe fn session_times(id: u32) -> (i64, i64, i64) {
    use windows::Win32::System::RemoteDesktop::{WTSINFOW, WTSSessionInfo};
    unsafe {
        let mut buf: windows::core::PWSTR = windows::core::PWSTR::null();
        let mut bytes = 0u32;
        if WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), id, WTSSessionInfo, &mut buf, &mut bytes).is_err() || buf.is_null() {
            return (0, 0, 0);
        }
        if (bytes as usize) < std::mem::size_of::<WTSINFOW>() {
            WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
            return (0, 0, 0);
        }
        let info = &*(buf.0 as *const WTSINFOW);
        let logon = crate::sys::filetime_to_unix_ms(info.LogonTime);
        let connect = crate::sys::filetime_to_unix_ms(info.ConnectTime);
        let last_input = crate::sys::filetime_to_unix_ms(info.LastInputTime);
        let now = crate::sys::filetime_to_unix_ms(info.CurrentTime);
        let idle = if last_input > 0 && now > last_input { now - last_input } else { 0 };
        WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
        (logon, idle, connect)
    }
}

unsafe fn client_address(id: u32) -> String {
    use windows::Win32::System::RemoteDesktop::WTS_CLIENT_ADDRESS;
    unsafe {
        let mut buf: windows::core::PWSTR = windows::core::PWSTR::null();
        let mut bytes = 0u32;
        if WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), id, WTSClientAddress, &mut buf, &mut bytes).is_err() || buf.is_null() {
            return String::new();
        }
        if (bytes as usize) < std::mem::size_of::<WTS_CLIENT_ADDRESS>() {
            WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
            return String::new();
        }
        let a = &*(buf.0 as *const WTS_CLIENT_ADDRESS);
        let s = match a.AddressFamily {
            2 => format!("{}.{}.{}.{}", a.Address[2], a.Address[3], a.Address[4], a.Address[5]),
            23 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&a.Address[2..18]);
                std::net::Ipv6Addr::from(b).to_string()
            }
            _ => String::new(),
        };
        WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
        s
    }
}

pub fn state_text(s: i32) -> &'static str {
    match s {
        0 => "Active",
        1 => "Connected",
        2 => "Connect query",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listen",
        7 => "Reset",
        8 => "Down",
        9 => "Init",
        _ => "Unknown",
    }
}

pub fn list() -> Vec<SessionRow> {
    let mut out = Vec::new();
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count).is_err() {
            return out;
        }
        if info.is_null() || count == 0 {
            return out;
        }
        let slice = std::slice::from_raw_parts(info, count as usize);
        for s in slice {
            let id = s.SessionId;
            let win_station = if s.pWinStationName.is_null() {
                String::new()
            } else {
                s.pWinStationName.to_string().unwrap_or_default()
            };
            let (logon_ms, idle_ms, connect_ms) = session_times(id);
            let user = query_str(id, WTSUserName);
            let domain = query_str(id, WTSDomainName);
            out.push(SessionRow {
                id,
                user: if user.is_empty() || domain.is_empty() { user } else { format!("{}\\{}", domain, user) },
                state: state_text(s.State.0).to_string(),
                win_station,
                client: client_str(id),
                client_address: client_address(id),
                logon_ms,
                idle_ms,
                connect_ms,
            });
        }
        WTSFreeMemory(info as *mut core::ffi::c_void);
    }
    out.retain(|s| !s.user.is_empty() || s.state == "Active" || s.state == "Disconnected");
    out.sort_by_key(|a| a.id);
    out
}

unsafe fn query_str(
    id: u32,
    class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS,
) -> String {
    unsafe {
        let mut buf: windows::core::PWSTR = windows::core::PWSTR::null();
        let mut bytes = 0u32;
        if WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), id, class, &mut buf, &mut bytes).is_err() {
            return String::new();
        }
        let s = if buf.is_null() { String::new() } else { buf.to_string().unwrap_or_default() };
        if !buf.is_null() {
            WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
        }
        s
    }
}

fn client_str(id: u32) -> String {
    unsafe { query_str(id, WTSClientName) }
}
