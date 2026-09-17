pub fn code_of(e: &windows::core::Error) -> u32 {
    let raw = e.code().0 as u32;
    if raw & 0xFFFF_0000 == 0x8007_0000 { raw & 0xFFFF } else { raw }
}

pub fn text(code: u32) -> String {
    match code {
        2 => "the file could not be found".into(),
        3 => "the folder could not be found".into(),
        5 => "Windows refused access (the target is protected)".into(),
        6 => "the handle is no longer valid".into(),
        32 => "the file is in use by another process".into(),
        87 => "Windows rejected one of the parameters (error 87)".into(),
        122 => "the buffer Windows was given is too small".into(),
        267 => "the folder name is not valid".into(),
        299 => "only part of the data could be read".into(),
        1168 => "no such item".into(),
        1223 => "cancelled".into(),
        1314 => "a required privilege is not held by Keyhole".into(),
        1326 => "the user name or password is incorrect".into(),
        1327 => "account restrictions prevent that logon".into(),
        1385 => "that account is not allowed that logon type".into(),
        1450 => "Windows is short of system resources".into(),
        1460 => "the operation timed out".into(),
        1717 | 1722 => "the RPC server is unavailable".into(),
        1907 => "the password must be changed before that account can log on".into(),
        1909 => "the account is locked out".into(),
        1051 => "other services depend on it. Stop those first".into(),
        1052 => "it does not accept that request".into(),
        1053 => "it did not respond in time".into(),
        1056 => "it is already running".into(),
        1058 => "it is disabled. Set a start type first".into(),
        1060 => "no service by that name exists".into(),
        1061 => "it cannot accept that request right now".into(),
        1062 => "it is not running".into(),
        1069 => "its logon account could not sign in".into(),
        1072 => "it is marked for deletion".into(),
        7022 => "that session no longer exists".into(),
        0x8004_1326 => "the task is disabled. Enable it first".into(),
        0x8004_131F => "the task is already running".into(),
        0x8004_1315 => "the Task Scheduler service is not running".into(),
        0x8004_130B => "the task is not running".into(),
        0x8004_130E => "the task definition is invalid".into(),
        c if c & 0x8000_0000 != 0 => format!("Windows error 0x{:08X}", c),
        c => format!("Windows error {}", c),
    }
}

pub fn describe(e: &windows::core::Error) -> String {
    text(code_of(e))
}
