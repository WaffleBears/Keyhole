use crate::nt::{NtResumeProcess, NtSuspendProcess, nt_ok, status_text};
use crate::sys::wide;
use std::ffi::c_void;
use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DuplicateHandle, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
};
use windows::Win32::System::Diagnostics::Debug::{MiniDumpWithFullMemory, MiniDumpWriteDump};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegSetValueExW,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, PROCESS_VM_READ, TerminateProcess,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

pub const CRITICAL_NAMES: &[&str] = &["csrss.exe", "wininit.exe", "smss.exe", "lsass.exe", "services.exe", "winlogon.exe", "system", "secure system", "registry", "memory compression"];

pub fn is_critical(pid: u32) -> bool {
    use crate::nt::{NtQueryInformationProcess, ProcessBreakOnTermination, nt_ok};
    if pid == 0 || pid == 4 {
        return true;
    }
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) else { return false };
        let mut flag: u32 = 0;
        let mut needed = 0u32;
        let status = NtQueryInformationProcess(h.0, ProcessBreakOnTermination, &mut flag as *mut u32 as *mut c_void, 4, &mut needed);
        let _ = CloseHandle(h);
        nt_ok(status) && flag != 0
    }
}

pub fn critical_guard(pid: u32, name: &str, verb: &str) -> Result<(), String> {
    if pid == 0 || pid == 4 {
        return Err(format!("refusing to {} a kernel process", verb));
    }
    if is_critical(pid) || CRITICAL_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return Err(format!("{} is a critical Windows process. Ending it would blue screen this machine (CRITICAL_PROCESS_DIED), so Keyhole will not {} it", if name.is_empty() { format!("pid {}", pid) } else { name.to_string() }, verb));
    }
    Ok(())
}

pub fn terminate(pid: u32) -> Result<(), String> {
    if pid == 0 || pid == 4 {
        return Err("refusing to terminate a kernel process".into());
    }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| open_error(&e))?;
        let r = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
        r.map_err(|e| format!("could not terminate: {}", describe(&e)))
    }
}

pub fn suspend(pid: u32) -> Result<(), String> {
    if pid == 0 || pid == 4 {
        return Err("refusing to suspend a kernel process".into());
    }
    unsafe {
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)
            .map_err(|e| open_error(&e))?;
        let status = NtSuspendProcess(h.0);
        let _ = CloseHandle(h);
        if nt_ok(status) {
            Ok(())
        } else {
            Err(format!("could not suspend: {}", status_text(status)))
        }
    }
}

pub fn resume(pid: u32) -> Result<(), String> {
    if pid == 0 || pid == 4 {
        return Err("refusing to resume a kernel process".into());
    }
    unsafe {
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)
            .map_err(|e| open_error(&e))?;
        let status = NtResumeProcess(h.0);
        let _ = CloseHandle(h);
        if nt_ok(status) {
            Ok(())
        } else {
            Err(format!("could not resume: {}", status_text(status)))
        }
    }
}

pub fn close_handle(pid: u32, value: u64) -> Result<(), String> {
    if pid == 0 || pid == 4 {
        return Err("refusing to close a kernel handle".into());
    }
    if pid == std::process::id() {
        return Err("refusing to close one of Keyhole's own handles".into());
    }
    unsafe {
        let src = OpenProcess(PROCESS_DUP_HANDLE, false, pid)
            .map_err(|e| open_error(&e))?;
        let mut dup = HANDLE::default();
        let r = DuplicateHandle(
            src,
            HANDLE(value as *mut c_void),
            GetCurrentProcess(),
            &mut dup,
            0,
            false,
            DUPLICATE_CLOSE_SOURCE,
        );
        let _ = CloseHandle(src);
        match r {
            Ok(()) => {
                if !dup.is_invalid() {
                    let _ = CloseHandle(dup);
                }
                Ok(())
            }
            Err(e) => Err(format!("could not close the handle: {}", describe(&e))),
        }
    }
}

pub fn run_uninstall(command: &str) -> Result<(), String> {
    if command.trim().is_empty() {
        return Err("this program did not register an uninstaller".into());
    }
    let (exe, args) = split_command(command);
    let verb = wide("open");
    let file = wide(&exe);
    let params = wide(&args);
    let r = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            if args.is_empty() { PCWSTR::null() } else { PCWSTR(params.as_ptr()) },
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if r.0 as usize > 32 {
        Ok(())
    } else {
        Err("could not launch the uninstaller".into())
    }
}

pub fn split_command(command: &str) -> (String, String) {
    let c = expand_env(command.trim());
    let c = c.trim();
    if let Some(rest) = c.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (rest[..end].to_string(), rest[end + 1..].trim().to_string());
        }
        return (rest.to_string(), String::new());
    }
    let looks_like_exe = |s: &str| {
        let l = s.to_ascii_lowercase();
        [".exe", ".com", ".bat", ".cmd", ".dll", ".ps1", ".vbs", ".js", ".msi", ".scr"].iter().any(|e| l.ends_with(e))
    };
    let mut cut: Option<usize> = None;
    let mut first_exe: Option<usize> = None;
    for (i, ch) in c.char_indices().chain(std::iter::once((c.len(), ' '))) {
        if !ch.is_whitespace() {
            continue;
        }
        let head = &c[..i];
        if head.is_empty() {
            continue;
        }
        if first_exe.is_none() && looks_like_exe(head) {
            first_exe = Some(i);
        }
        if std::path::Path::new(head).is_file() {
            cut = Some(i);
            break;
        }
        if !looks_like_exe(head) && std::path::Path::new(&format!("{}.exe", head)).is_file() {
            cut = Some(i);
            break;
        }
    }
    let at = cut.or(first_exe).unwrap_or_else(|| c.find(char::is_whitespace).unwrap_or(c.len()));
    (c[..at].to_string(), c[at..].trim().to_string())
}

pub fn exe_from_command(command: &str) -> String {
    if command.trim().is_empty() {
        return String::new();
    }
    let (exe, _) = split_command(command);
    let exe = exe.trim_matches('"').to_string();
    if exe.as_bytes().get(1) == Some(&b':') || exe.starts_with("\\\\") {
        return exe;
    }
    let lower = exe.to_ascii_lowercase();
    if let Ok(root) = std::env::var("SystemRoot") {
        for prefix in ["", "System32\\"] {
            let p = format!("{}\\{}{}", root, prefix, exe);
            if std::path::Path::new(&p).is_file() {
                return p;
            }
            if !lower.ends_with(".exe") {
                let p = format!("{}.exe", p);
                if std::path::Path::new(&p).is_file() {
                    return p;
                }
            }
        }
    }
    exe
}

pub fn affinity(pid: u32) -> Result<(u64, u64), String> {
    use windows::Win32::System::Threading::GetProcessAffinityMask;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| open_error(&e))?;
        let mut process_mask = 0usize;
        let mut system_mask = 0usize;
        let r = GetProcessAffinityMask(h, &mut process_mask, &mut system_mask);
        let _ = CloseHandle(h);
        r.map_err(|e| format!("could not read affinity: {}", describe(&e)))?;
        Ok((process_mask as u64, system_mask as u64))
    }
}

pub fn sha256_of(path: &str) -> Result<String, String> {
    use sha2::Digest;
    let path = expand_env(path);
    let mut file = std::fs::File::open(&path).map_err(|e| format!("cannot open file: {}", e))?;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("cannot read file: {}", e))?;
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn open_tool(name: &str) -> Result<(), String> {
    if let Some(kb) = name.strip_prefix("kb:") {
        let digits: String = kb.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return Err("no KB number".into());
        }
        return shell_open(&format!("https://support.microsoft.com/help/{}", digits), None);
    }
    if let Some(log) = name.strip_prefix("eventvwr:") {
        let args = format!("/c:{}", log);
        return shell_open("eventvwr.exe", Some(&args));
    }
    let target = match name {
        "services" => "services.msc",
        "tasks" => "taskschd.msc",
        "firewall" => "wf.msc",
        "devices" => "devmgmt.msc",
        "apps" => "ms-settings:appsfeatures",
        "startup" => "ms-settings:startupapps",
        "eventlog" => "eventvwr.msc",
        "shares" => "fsmgmt.msc",
        "users" => "lusrmgr.msc",
        "wu" => "ms-settings:windowsupdate",
        "wuhistory" => "ms-settings:windowsupdate-history",
        "certlm" => "certlm.msc",
        "ncpa" => "ncpa.cpl",
        _ => return Err("unknown tool".into()),
    };
    shell_open(target, None)
}

pub struct OwnerToken(pub HANDLE);

impl Drop for OwnerToken {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

unsafe impl Send for OwnerToken {}

pub fn owner_token(pid: u32) -> Option<OwnerToken> {
    use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary};
    use windows::Win32::System::Threading::OpenProcessToken;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut token = HANDLE::default();
        let opened = OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token).is_ok();
        let _ = CloseHandle(h);
        if !opened {
            return None;
        }
        let mut primary = HANDLE::default();
        let dup = DuplicateTokenEx(token, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, &mut primary).is_ok();
        let _ = CloseHandle(token);
        if dup { Some(OwnerToken(primary)) } else { None }
    }
}

pub fn relaunch(image: &str, command_line: &str, cwd: &str, owner: Option<OwnerToken>) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    if image.is_empty() {
        return Err("the program's path is unknown, so it cannot be started again".into());
    }
    let rest = strip_first_token(command_line, image);
    if let Some(token) = owner {
        return relaunch_with_token(&token, image, &rest, cwd).map_err(|e| format!("the process was stopped but could not be started again under its own account, so it was not restarted as administrator: {}", e));
    }
    let mut cmd = std::process::Command::new(image);
    if !rest.is_empty() {
        cmd.raw_arg(rest);
    }
    if !cwd.is_empty() && std::path::Path::new(cwd).is_dir() {
        cmd.current_dir(cwd);
    }
    cmd.spawn().map(|_| ()).map_err(|e| format!("relaunch failed: {}", e))
}

fn relaunch_with_token(token: &OwnerToken, image: &str, args: &str, cwd: &str) -> Result<(), String> {
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::Threading::{CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW, PROCESS_INFORMATION, STARTUPINFOW};
    let quoted = if image.contains(' ') && !image.starts_with('"') { format!("\"{}\"", image) } else { image.to_string() };
    let mut cmdline = wide(&if args.is_empty() { quoted } else { format!("{} {}", quoted, args) });
    let dir = if !cwd.is_empty() && std::path::Path::new(cwd).is_dir() { Some(wide(cwd)) } else { None };
    let desktop = wide("winsta0\\default");
    unsafe {
        let mut env: *mut c_void = std::ptr::null_mut();
        let _ = CreateEnvironmentBlock(&mut env, Some(token.0), false);
        let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, lpDesktop: windows::core::PWSTR(desktop.as_ptr() as *mut u16), ..Default::default() };
        let mut pi = PROCESS_INFORMATION::default();
        let r = CreateProcessWithTokenW(
            token.0,
            windows::Win32::System::Threading::CREATE_PROCESS_LOGON_FLAGS(0),
            PCWSTR::null(),
            Some(windows::core::PWSTR(cmdline.as_mut_ptr())),
            CREATE_UNICODE_ENVIRONMENT,
            Some(env),
            dir.as_ref().map(|d| PCWSTR(d.as_ptr())).unwrap_or(PCWSTR::null()),
            &si,
            &mut pi,
        );
        if !env.is_null() {
            let _ = DestroyEnvironmentBlock(env);
        }
        match r {
            Ok(()) => {
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
                Ok(())
            }
            Err(e) => Err(format!("could not start it as its original user ({}): {}", crate::sys::winerr::code_of(&e), describe(&e))),
        }
    }
}

pub fn strip_first_token(command_line: &str, image: &str) -> String {
    let c = command_line.trim();
    let unquoted = c.strip_prefix('"').unwrap_or(c);
    if !image.is_empty() {
        if let Some(after) = crate::sys::strip_prefix_ci(unquoted, image) {
            let after = after.strip_prefix('"').unwrap_or(after);
            if after.is_empty() || after.starts_with(' ') {
                return after.trim().to_string();
            }
        }
        let exe_name = image.rsplit('\\').next().unwrap_or(image);
        if let Some(after) = crate::sys::strip_prefix_ci(unquoted, exe_name) {
            let after = after.strip_prefix('"').unwrap_or(after);
            if after.is_empty() || after.starts_with(' ') {
                return after.trim().to_string();
            }
        }
    }
    if let Some(rest) = c.strip_prefix('"') {
        match rest.find('"') {
            Some(end) => rest[end + 1..].trim().to_string(),
            None => String::new(),
        }
    } else {
        match c.find(' ') {
            Some(i) => c[i + 1..].trim().to_string(),
            None => String::new(),
        }
    }
}

pub fn expand_env(path: &str) -> String {
    if !path.contains('%') {
        return path.to_string();
    }
    let src = wide(path);
    let mut buf = vec![0u16; 4096];
    let n = unsafe { ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(&mut buf)) };
    if n == 0 || n as usize > buf.len() {
        return path.to_string();
    }
    crate::sys::from_wide(&buf)
}

fn shell_open(file: &str, args: Option<&str>) -> Result<(), String> {
    let verb = wide("open");
    let file_w = wide(file);
    let args_w = args.map(wide);
    let r = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file_w.as_ptr()),
            args_w.as_ref().map(|a| PCWSTR(a.as_ptr())).unwrap_or(PCWSTR::null()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if r.0 as usize > 32 { Ok(()) } else { Err("Windows could not open that".into()) }
}

pub fn open_registry_key(key: &str) -> Result<(), String> {
    let k = key.trim_start_matches('\\');
    let full = if let Some(rest) = k.strip_prefix("HKLM\\") {
        format!("HKEY_LOCAL_MACHINE\\{}", rest)
    } else if let Some(rest) = k.strip_prefix("HKU\\") {
        format!("HKEY_USERS\\{}", rest)
    } else if let Some(rest) = k.strip_prefix("HKCU\\") {
        format!("HKEY_CURRENT_USER\\{}", rest)
    } else if let Some(rest) = k.strip_prefix("HKCR\\") {
        format!("HKEY_CLASSES_ROOT\\{}", rest)
    } else if let Some(rest) = crate::sys::strip_prefix_ci(k, "REGISTRY\\MACHINE\\") {
        format!("HKEY_LOCAL_MACHINE\\{}", rest)
    } else if let Some(rest) = crate::sys::strip_prefix_ci(k, "REGISTRY\\USER\\") {
        format!("HKEY_USERS\\{}", rest)
    } else if k.starts_with("HKEY_") {
        k.to_string()
    } else {
        return Err("not a registry path the Registry Editor can open".into());
    };
    let value = wide(&format!("Computer\\{}", full));
    let sub = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit");
    let name = wide("LastKey");
    unsafe {
        let mut hkey = Default::default();
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
        .ok()
        .map_err(|e| format!("cannot prepare Registry Editor: {}", describe(&e)))?;
        let bytes = std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
        let r = RegSetValueExW(hkey, PCWSTR(name.as_ptr()), None, REG_SZ, Some(bytes));
        let _ = RegCloseKey(hkey);
        r.ok().map_err(|e| format!("cannot prepare Registry Editor: {}", describe(&e)))?;
    }
    shell_open("regedit.exe", Some("/m"))
}

pub fn file_properties(path: &str) -> Result<(), String> {
    let path = expand_env(path.trim().trim_matches('"'));
    if path.is_empty() || !std::path::Path::new(&path).exists() {
        return Err("that file does not exist".into());
    }
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::Builder::new()
        .name("keyhole-properties".into())
        .spawn(move || unsafe {
            use windows::Win32::UI::Shell::{SEE_MASK_INVOKEIDLIST, SHELLEXECUTEINFOW, ShellExecuteExW};
            use windows::Win32::UI::WindowsAndMessaging::{DispatchMessageW, EnumThreadWindows, MSG, MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW, QS_ALLINPUT, TranslateMessage};
            let _com = crate::sys::com::ComGuard::sta();
            let verb = wide("properties");
            let file = wide(&path);
            let mut info = SHELLEXECUTEINFOW {
                cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                fMask: SEE_MASK_INVOKEIDLIST,
                lpVerb: PCWSTR(verb.as_ptr()),
                lpFile: PCWSTR(file.as_ptr()),
                nShow: SW_SHOWNORMAL.0,
                ..Default::default()
            };
            if let Err(e) = ShellExecuteExW(&mut info) {
                let _ = tx.send(Err(format!("the shell would not open the properties sheet: {}", describe(&e))));
                return;
            }
            let _ = tx.send(Ok(()));
            unsafe extern "system" fn count(_: windows::Win32::Foundation::HWND, lp: windows::Win32::Foundation::LPARAM) -> windows::core::BOOL {
                unsafe { *(lp.0 as *mut u32) += 1 };
                windows::core::BOOL(1)
            }
            let tid = windows::Win32::System::Threading::GetCurrentThreadId();
            let started = std::time::Instant::now();
            let mut seen_window = false;
            let mut msg = MSG::default();
            loop {
                let mut n = 0u32;
                let _ = EnumThreadWindows(tid, Some(count), windows::Win32::Foundation::LPARAM(&mut n as *mut u32 as isize));
                if n > 0 {
                    seen_window = true;
                } else if seen_window || started.elapsed() > std::time::Duration::from_secs(20) {
                    break;
                }
                let _ = MsgWaitForMultipleObjects(None, false, 1000, QS_ALLINPUT);
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        })
        .map_err(|e| e.to_string())?;
    rx.recv().unwrap_or_else(|_| Err("the properties sheet could not be opened".into()))
}

pub fn write_dump(pid: u32, path: &str, full: bool) -> Result<(), String> {
    if pid == 0 || pid == 4 {
        return Err("refusing to dump a kernel process".into());
    }
    unsafe {
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, false, pid)
            .map_err(|e| open_error(&e))?;
        let wpath = wide(path);
        let file = CreateFileW(
            PCWSTR(wpath.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        let file = match file {
            Ok(f) => f,
            Err(e) => {
                let _ = CloseHandle(proc_handle);
                return Err(format!("could not create the dump file: {}", describe(&e)));
            }
        };
        let kind = if full {
            MiniDumpWithFullMemory
        } else {
            windows::Win32::System::Diagnostics::Debug::MiniDumpWithDataSegs
                | windows::Win32::System::Diagnostics::Debug::MiniDumpWithHandleData
                | windows::Win32::System::Diagnostics::Debug::MiniDumpWithThreadInfo
                | windows::Win32::System::Diagnostics::Debug::MiniDumpWithUnloadedModules
        };
        let r = MiniDumpWriteDump(proc_handle, pid, file, kind, None, None, None);
        let _ = CloseHandle(file);
        let _ = CloseHandle(proc_handle);
        if r.is_err() {
            let _ = std::fs::remove_file(path);
        }
        r.map_err(|e| format!("dump failed: {}", describe(&e)))
    }
}

pub fn reveal_in_explorer(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("nothing to show: the path is empty".into());
    }
    let path = expand_env(path).replace('"', "");
    let path = if path.len() > 3 { path.trim_end_matches('\\').to_string() } else { path };
    let verb = wide("open");
    let file = wide("explorer.exe");
    let args = wide(&format!("/select,\"{}\"", path));
    let r = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(args.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if r.0 as usize > 32 {
        Ok(())
    } else {
        Err("Explorer could not open that location".into())
    }
}

pub fn open_containing_folder(path: &str) -> Result<(), String> {
    let path = expand_env(path);
    let folder = match path.rfind('\\') {
        Some(i) => &path[..i],
        None => return Err("that path has no folder part".into()),
    };
    if folder.starts_with("\\\\") && folder.matches('\\').count() < 3 {
        return Err("that is the root of a share, which has no containing folder".into());
    }
    let folder = if folder.ends_with(':') { format!("{}\\", folder) } else { folder.to_string() };
    let verb = wide("open");
    let file = wide(&folder);
    let r = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if r.0 as usize > 32 {
        Ok(())
    } else {
        Err("Explorer could not open that location".into())
    }
}

fn describe(e: &windows::core::Error) -> String {
    crate::sys::winerr::describe(e)
}

fn open_error(e: &windows::core::Error) -> String {
    if crate::sys::winerr::code_of(e) == 87 {
        return "the process has already exited".into();
    }
    format!("could not open the process: {}", describe(e))
}
