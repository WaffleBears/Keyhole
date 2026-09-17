use super::com::ComGuard;
use super::reg;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::Win32::System::UpdateAgent::{IUpdate, IUpdateCollection, IUpdateSearcher, IUpdateService2, IUpdateServiceManager, IUpdateSession, ISystemInformation, SystemInformation, UpdateCollection, UpdateServiceManager, UpdateSession, orcAborted, orcFailed, orcInProgress, orcNotStarted, orcSucceeded, orcSucceededWithErrors, ssManagedServer, ssWindowsUpdate, uoInstallation, uoUninstallation};
use windows::core::Interface;
use windows::core::BSTR;

#[derive(Clone, Debug, Default)]
pub struct UpdateRow {
    pub time_ms: i64,
    pub title: String,
    pub kb: String,
    pub result: String,
    pub ok: bool,
    pub operation: String,
    pub hresult: i32,
    pub description: String,
    pub update_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct PendingRow {
    pub title: String,
    pub kb: String,
    pub severity: String,
    pub downloaded: bool,
    pub mandatory: bool,
    pub reboot: String,
    pub size: u64,
    pub description: String,
    pub update_id: String,
    pub revision: i32,
    pub eula_accepted: bool,
}

#[derive(Clone, Debug, Default)]
pub struct InstallReport {
    pub attempted: usize,
    pub installed: usize,
    pub failed: Vec<(String, String)>,
    pub reboot: bool,
}

impl InstallReport {
    pub fn text(&self) -> String {
        let mut s = match (self.installed, self.failed.len()) {
            (n, 0) => format!("Installed {}", plural_updates(n)),
            (0, f) => format!("None of the {} installed", plural_updates(f)),
            (n, f) => format!("Installed {}, {} failed", plural_updates(n), f),
        };
        if self.reboot {
            s.push_str(". A restart is needed to finish");
        }
        s
    }
}

fn plural_updates(n: usize) -> String {
    format!("{} update{}", n, if n == 1 { "" } else { "s" })
}

#[derive(Clone, Debug, Default)]
pub struct RebootReason {
    pub source: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct UpdatesData {
    pub policy_note: Option<String>,
    pub wsus: bool,
    pub history: Vec<UpdateRow>,
    pub pending: Option<Result<Vec<PendingRow>, String>>,
    pub reboot: Vec<RebootReason>,
    pub last_install_ms: i64,
    pub last_search_ms: i64,
    pub source: String,
    pub error: Option<String>,
}

pub const HISTORY_CAP: i32 = 2000;

pub fn ole_date_to_ms(d: f64) -> i64 {
    if d <= 0.0 {
        return 0;
    }
    ((d - 25569.0) * 86_400_000.0) as i64
}

pub fn kb_of(title: &str) -> String {
    let upper = title.to_uppercase();
    let mut out = Vec::new();
    let mut rest = upper.as_str();
    while let Some(i) = rest.find("KB") {
        let after = &rest[i + 2..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 5 && !out.contains(&format!("KB{}", digits)) {
            out.push(format!("KB{}", digits));
        }
        rest = &after[digits.len()..];
    }
    out.join(", ")
}

fn com_err(what: &str, e: &windows::core::Error) -> String {
    format!("{}: {}", what, super::winerr::describe(e))
}

fn session() -> Result<(ComGuard, IUpdateSession), String> {
    let com = ComGuard::mta();
    let session: IUpdateSession = unsafe { CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) }.map_err(|e| com_err("Windows Update Agent is not available", &e))?;
    Ok((com, session))
}

fn searcher() -> Result<(ComGuard, IUpdateSearcher), String> {
    let (com, session) = session()?;
    let searcher = unsafe { session.CreateUpdateSearcher() }.map_err(|e| com_err("update searcher", &e))?;
    Ok((com, searcher))
}

fn result_failure(code: windows::Win32::System::UpdateAgent::OperationResultCode, hr: i32) -> String {
    if hr != 0 {
        return wu_text(hr);
    }
    match code {
        x if x == orcAborted => "the installation was aborted".into(),
        x if x == orcNotStarted => "it was not started, usually because an earlier update in the batch needs a restart first".into(),
        x if x == orcInProgress => "it is still in progress".into(),
        _ => "it failed without an error code".into(),
    }
}

pub fn wu_error(code: u32) -> Option<&'static str> {
    Some(match code {
        0x80240016 => "another installation is already running on this machine",
        0x80240017 => "the update is not applicable to this machine",
        0x8024001E => "the Windows Update service stopped",
        0x80240020 => "the update needs an interactive user session",
        0x80240022 => "every update failed to install",
        0x80240024 => "there are no updates to install",
        0x80240028 => "the update cannot be installed because a restart is pending",
        0x8024002E => "Windows Update is disabled by policy on this machine",
        0x80240031 => "the downloaded file is not valid",
        0x8024402C | 0x80244022 | 0x8024401C | 0x80072EE2 | 0x80072EFD | 0x80072EE7 => "the update source could not be reached",
        0x80070005 => "Windows refused access",
        0x80070020 => "a file it needs is in use",
        0x800705B4 => "the installer timed out",
        0x80070422 => "the Windows Update service is disabled",
        0x80242007 => "the update handler is not in the expected state",
        0x80242014 => "the update needs a restart before it can be installed",
        0x80242016 => "the update is in an unexpected state after an earlier attempt",
        0x8024200B => "the installer for this update failed",
        _ => return None,
    })
}

fn wu_text(code: i32) -> String {
    let c = code as u32;
    match wu_error(c) {
        Some(t) => format!("{} (0x{:08X})", t, c),
        None => format!("error 0x{:08X}", c),
    }
}

fn find_pending<'a>(updates: &'a windows::Win32::System::UpdateAgent::IUpdateCollection, ids: &[(String, i32)]) -> Vec<IUpdate> {
    let mut out = Vec::new();
    let n = unsafe { updates.Count() }.unwrap_or(0);
    for i in 0..n {
        let Ok(u) = (unsafe { updates.get_Item(i) }) else { continue };
        let Ok(identity) = (unsafe { u.Identity() }) else { continue };
        let id = unsafe { identity.UpdateID() }.map(|b| b.to_string()).unwrap_or_default();
        let rev = unsafe { identity.RevisionNumber() }.unwrap_or(0);
        if ids.iter().any(|(wanted, wanted_rev)| wanted.eq_ignore_ascii_case(&id) && (*wanted_rev == 0 || *wanted_rev == rev)) {
            out.push(u);
        }
    }
    out
}

pub fn install(ids: &[(String, i32)]) -> Result<InstallReport, String> {
    use windows::Win32::Foundation::VARIANT_BOOL;
    if ids.is_empty() {
        return Err("nothing selected to install".into());
    }
    let (_com, session) = session()?;
    let searcher = unsafe { session.CreateUpdateSearcher() }.map_err(|e| com_err("update searcher", &e))?;
    let p = policy();
    unsafe {
        let _ = searcher.SetOnline(VARIANT_BOOL(-1));
        if p.wsus.is_some() {
            let _ = searcher.SetServerSelection(ssManagedServer);
        } else if !p.microsoft_update {
            let _ = searcher.SetServerSelection(ssWindowsUpdate);
        }
    }
    let result = unsafe { searcher.Search(&BSTR::from("IsInstalled=0 and IsHidden=0")) }.map_err(|e| format!("the update source could not be asked again: {}", wu_text(e.code().0)))?;
    let offered = unsafe { result.Updates() }.map_err(|e| com_err("results", &e))?;
    let chosen = find_pending(&offered, ids);
    if chosen.is_empty() {
        return Err("the selected updates are no longer offered by the update source".into());
    }
    let to_install: IUpdateCollection = unsafe { CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER) }.map_err(|e| com_err("update collection", &e))?;
    let to_download: IUpdateCollection = unsafe { CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER) }.map_err(|e| com_err("update collection", &e))?;
    let mut titles = Vec::new();
    let mut report = InstallReport { attempted: chosen.len(), ..Default::default() };
    for u in &chosen {
        let title = unsafe { u.Title() }.map(|b| b.to_string()).unwrap_or_default();
        if unsafe { u.EulaAccepted() }.map(|b| !b.as_bool()).unwrap_or(false)
            && let Err(e) = unsafe { u.AcceptEula() } {
                report.failed.push((title, format!("its license terms could not be accepted: {}", wu_text(e.code().0))));
                continue;
            }
        if unsafe { u.IsDownloaded() }.map(|b| !b.as_bool()).unwrap_or(true) {
            unsafe { to_download.Add(u) }.map_err(|e| com_err("download list", &e))?;
        }
        unsafe { to_install.Add(u) }.map_err(|e| com_err("install list", &e))?;
        titles.push(title);
    }
    if titles.is_empty() {
        return Ok(report);
    }
    if unsafe { to_download.Count() }.unwrap_or(0) > 0 {
        let downloader = unsafe { session.CreateUpdateDownloader() }.map_err(|e| com_err("downloader", &e))?;
        unsafe { downloader.SetUpdates(&to_download) }.map_err(|e| com_err("download list", &e))?;
        let dl = unsafe { downloader.Download() }.map_err(|e| format!("download failed: {}", wu_text(e.code().0)))?;
        let code = unsafe { dl.ResultCode() }.unwrap_or(orcFailed);
        if code != orcSucceeded && code != orcSucceededWithErrors {
            let hr = unsafe { dl.HResult() }.unwrap_or(0);
            return Err(format!("download failed: {}", wu_text(hr)));
        }
    }
    let installer = unsafe { session.CreateUpdateInstaller() }.map_err(|e| com_err("installer", &e))?;
    unsafe {
        if installer.IsBusy().map(|b| b.as_bool()).unwrap_or(false) {
            return Err("another installation is already running on this machine".into());
        }
        let _ = installer.SetAllowSourcePrompts(VARIANT_BOOL(0));
        installer.SetUpdates(&to_install).map_err(|e| com_err("install list", &e))?;
    }
    let res = unsafe { installer.Install() }.map_err(|e| format!("install failed: {}", wu_text(e.code().0)))?;
    report.reboot = unsafe { res.RebootRequired() }.map(|b| b.as_bool()).unwrap_or(false);
    for (i, title) in titles.iter().enumerate() {
        let Ok(r) = (unsafe { res.GetUpdateResult(i as i32) }) else { continue };
        let code = unsafe { r.ResultCode() }.unwrap_or(orcFailed);
        if code == orcSucceeded || code == orcSucceededWithErrors {
            report.installed += 1;
        } else {
            let hr = unsafe { r.HResult() }.unwrap_or(0);
            report.failed.push((title.clone(), result_failure(code, hr)));
        }
    }
    Ok(report)
}

pub fn reboot_reasons() -> Vec<RebootReason> {
    let mut out = Vec::new();
    if reg::open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending").is_some() {
        out.push(RebootReason { source: "Component servicing".into(), detail: "CBS has a pending reboot (HKLM\\...\\Component Based Servicing\\RebootPending exists)".into() });
    }
    if reg::open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired").is_some() {
        out.push(RebootReason { source: "Windows Update".into(), detail: "An installed update requires a restart".into() });
    }
    if reg::open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\PackagesPending").is_some() {
        out.push(RebootReason { source: "Component servicing".into(), detail: "Servicing packages are waiting to install at the next boot".into() });
    }
    if let Some(key) = reg::open(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager") {
        let renames = reg::values(&key).into_iter().filter(|(n, _, d)| n.starts_with("PendingFileRenameOperations") && d.len() > 2).count();
        if renames > 0 {
            out.push(RebootReason { source: "Session Manager".into(), detail: "Files are queued for rename or delete at the next boot (PendingFileRenameOperations)".into() });
        }
    }
    let active = reg::string_at(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "ComputerName");
    let next = reg::string_at(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", "ComputerName");
    if let (Some(a), Some(n)) = (active, next)
        && !a.eq_ignore_ascii_case(&n) {
            out.push(RebootReason { source: "Computer name".into(), detail: format!("Rename from {} to {} takes effect after a restart", a, n) });
        }
    if reg::open(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\PostRebootReporting").is_some() {
        out.push(RebootReason { source: "Windows Update".into(), detail: "Reporting after the reboot is pending for an update".into() });
    }
    if reg::string_at(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon", "JoinDomain").is_some() || reg::string_at(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Netlogon", "AvoidSpnSet").is_some() {
        out.push(RebootReason { source: "Domain join".into(), detail: "A domain join or leave is waiting for a restart".into() });
    }
    let wua = {
        let _com = ComGuard::mta();
        unsafe { CoCreateInstance::<_, ISystemInformation>(&SystemInformation, None, CLSCTX_INPROC_SERVER).and_then(|s| s.RebootRequired()) }.map(|b| b.as_bool()).unwrap_or(false)
    };
    if wua && !out.iter().any(|r| r.source == "Windows Update") {
        out.push(RebootReason { source: "Windows Update".into(), detail: "The Windows Update Agent reports a restart is required".into() });
    }
    out
}

fn result_text(code: windows::Win32::System::UpdateAgent::OperationResultCode) -> (&'static str, bool) {
    match code {
        x if x == orcSucceeded => ("Succeeded", true),
        x if x == orcSucceededWithErrors => ("Succeeded with errors", true),
        x if x == orcFailed => ("Failed", false),
        x if x == orcAborted => ("Aborted", false),
        x if x == orcInProgress => ("In progress", true),
        x if x == orcNotStarted => ("Not started", true),
        _ => ("Unknown", true),
    }
}

#[derive(Clone, Debug, Default)]
pub struct UpdatePolicy {
    pub wsus: Option<String>,
    pub wsus_status: Option<String>,
    pub target_group: Option<String>,
    pub internet_blocked: bool,
    pub microsoft_update: bool,
    pub au_mode: String,
    pub schedule: String,
    pub defer_quality_days: u32,
    pub defer_feature_days: u32,
    pub broken: Option<String>,
}

const POLICY: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
const AU: &str = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";
const MICROSOFT_UPDATE_SERVICE: &str = "7971f918-a847-4430-9279-4a52d1efe18d";

fn microsoft_update_opted_in() -> bool {
    let _com = ComGuard::mta();
    let manager: Result<IUpdateServiceManager, _> = unsafe { CoCreateInstance(&UpdateServiceManager, None, CLSCTX_INPROC_SERVER) };
    let Ok(manager) = manager else { return false };
    let Ok(services) = (unsafe { manager.Services() }) else { return false };
    let n = unsafe { services.Count() }.unwrap_or(0);
    for i in 0..n {
        let Ok(svc) = (unsafe { services.get_Item(i) }) else { continue };
        let id = unsafe { svc.ServiceID() }.map(|b| b.to_string().to_lowercase()).unwrap_or_default();
        if id != MICROSOFT_UPDATE_SERVICE {
            continue;
        }
        let registered = unsafe { svc.IsRegisteredWithAU() }.map(|b| b.as_bool()).unwrap_or(false);
        let default = svc.cast::<IUpdateService2>().ok().and_then(|s2| unsafe { s2.IsDefaultAUService() }.ok()).map(|b| b.as_bool()).unwrap_or(false);
        return registered || default;
    }
    false
}

pub fn policy() -> UpdatePolicy {
    let mut p = UpdatePolicy::default();
    let use_wsus = reg::dword_at(HKEY_LOCAL_MACHINE, AU, "UseWUServer") == Some(1);
    let server = reg::string_at(HKEY_LOCAL_MACHINE, POLICY, "WUServer").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    match (use_wsus, server) {
        (true, Some(server)) => p.wsus = Some(server),
        (true, None) => p.broken = Some("policy says use a WSUS server but WUServer is not set, so nothing can be reached".into()),
        (false, Some(server)) => p.broken = Some(format!("WUServer is set to {} but UseWUServer is off, so Windows Update is used instead", server)),
        (false, None) => {}
    }
    p.wsus_status = reg::string_at(HKEY_LOCAL_MACHINE, POLICY, "WUStatusServer").filter(|s| !s.trim().is_empty());
    if reg::dword_at(HKEY_LOCAL_MACHINE, POLICY, "TargetGroupEnabled") == Some(1) {
        p.target_group = reg::string_at(HKEY_LOCAL_MACHINE, POLICY, "TargetGroup").filter(|s| !s.trim().is_empty());
    }
    p.internet_blocked = reg::dword_at(HKEY_LOCAL_MACHINE, POLICY, "DoNotConnectToWindowsUpdateInternetLocations") == Some(1);
    p.defer_quality_days = if reg::dword_at(HKEY_LOCAL_MACHINE, POLICY, "DeferQualityUpdates") == Some(1) { reg::dword_at(HKEY_LOCAL_MACHINE, POLICY, "DeferQualityUpdatesPeriodInDays").unwrap_or(0) } else { 0 };
    p.defer_feature_days = if reg::dword_at(HKEY_LOCAL_MACHINE, POLICY, "DeferFeatureUpdates") == Some(1) { reg::dword_at(HKEY_LOCAL_MACHINE, POLICY, "DeferFeatureUpdatesPeriodInDays").unwrap_or(0) } else { 0 };
    if reg::dword_at(HKEY_LOCAL_MACHINE, AU, "NoAutoUpdate") == Some(1) {
        p.au_mode = "automatic updates disabled by policy".into();
    } else if let Some(opt) = reg::dword_at(HKEY_LOCAL_MACHINE, AU, "AUOptions") {
        p.au_mode = match opt {
            2 => "notify before download".into(),
            3 => "download, notify before install".into(),
            4 => "download and install on schedule".into(),
            5 => "local admin chooses".into(),
            7 => "download, notify to install and restart".into(),
            _ => String::new(),
        };
        if opt == 4 {
            let day = reg::dword_at(HKEY_LOCAL_MACHINE, AU, "ScheduledInstallDay").unwrap_or(0);
            let hour = reg::dword_at(HKEY_LOCAL_MACHINE, AU, "ScheduledInstallTime").unwrap_or(3);
            let day_name = match day { 0 => "every day", 1 => "Sunday", 2 => "Monday", 3 => "Tuesday", 4 => "Wednesday", 5 => "Thursday", 6 => "Friday", 7 => "Saturday", _ => "every day" };
            p.schedule = format!("{} at {:02}:00", day_name, hour);
        }
    }
    if p.wsus.is_none() {
        p.microsoft_update = microsoft_update_opted_in();
    }
    p
}

pub fn source_text(p: &UpdatePolicy) -> String {
    let mut s = match &p.wsus {
        Some(server) => format!("WSUS {}", server),
        None if p.microsoft_update => "Microsoft Update".to_string(),
        None => "Windows Update".to_string(),
    };
    let mut extras = Vec::new();
    if let Some(g) = &p.target_group {
        extras.push(format!("group {}", g));
    }
    if !p.au_mode.is_empty() {
        extras.push(if p.schedule.is_empty() { p.au_mode.clone() } else { format!("{} {}", p.au_mode, p.schedule) });
    }
    if p.defer_quality_days > 0 {
        extras.push(format!("quality updates deferred {} d", p.defer_quality_days));
    }
    if p.defer_feature_days > 0 {
        extras.push(format!("feature updates deferred {} d", p.defer_feature_days));
    }
    if p.internet_blocked {
        extras.push("internet update locations blocked".into());
    }
    if !extras.is_empty() {
        s.push_str(&format!(" ({})", extras.join(", ")));
    }
    s
}

pub fn history() -> UpdatesData {
    let mut data = UpdatesData::default();
    data.reboot = reboot_reasons();
    let policy = policy();
    data.source = source_text(&policy);
    data.policy_note = policy.broken.clone();
    data.wsus = policy.wsus.is_some();
    if let Some(t) = reg::string_at(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Detect", "LastSuccessTime") {
        data.last_search_ms = parse_wu_time(&t);
    }
    let (_com, searcher) = match searcher() {
        Ok(s) => s,
        Err(e) => {
            data.error = Some(e);
            return data;
        }
    };
    let total = unsafe { searcher.GetTotalHistoryCount() }.unwrap_or(0).min(HISTORY_CAP);
    if total > 0 {
        match unsafe { searcher.QueryHistory(0, total) } {
            Ok(list) => {
                let n = unsafe { list.Count() }.unwrap_or(0);
                for i in 0..n {
                    let Ok(e) = (unsafe { list.get_Item(i) }) else { continue };
                    let title = unsafe { e.Title() }.map(|b| b.to_string()).unwrap_or_default();
                    let (result, ok) = unsafe { e.ResultCode() }.map(result_text).unwrap_or(("Unknown", true));
                    let op = unsafe { e.Operation() }.map(|o| if o == uoInstallation { "Installation" } else if o == uoUninstallation { "Uninstallation" } else { "Other" }).unwrap_or("Other");
                    let row = UpdateRow {
                        time_ms: unsafe { e.Date() }.map(ole_date_to_ms).unwrap_or(0),
                        kb: kb_of(&title),
                        title,
                        result: result.to_string(),
                        ok,
                        operation: op.to_string(),
                        hresult: unsafe { e.HResult() }.unwrap_or(0),
                        description: unsafe { e.Description() }.map(|b| b.to_string()).unwrap_or_default(),
                        update_id: unsafe { e.UpdateIdentity().and_then(|i| i.UpdateID()) }.map(|b| b.to_string()).unwrap_or_default(),
                    };
                    data.history.push(row);
                }
            }
            Err(e) => data.error = Some(com_err("update history", &e)),
        }
    }
    data.history.sort_by(|a, b| b.time_ms.cmp(&a.time_ms));
    data.last_install_ms = data.history.iter().filter(|r| r.ok && r.operation == "Installation").map(|r| r.time_ms).max().unwrap_or(0);
    data
}

pub fn parse_wu_time(text: &str) -> i64 {
    let t = text.trim();
    let parts: Vec<i64> = t.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect();
    if parts.len() < 6 {
        return 0;
    }
    let (y, mo, d, h, mi, s) = (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
    let days = days_from_civil(y, mo, d);
    (days * 86_400 + h * 3600 + mi * 60 + s) * 1000
}

pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn search_pending() -> Result<Vec<PendingRow>, String> {
    let (_com, searcher) = searcher()?;
    let p = policy();
    unsafe {
        let _ = searcher.SetOnline(windows::Win32::Foundation::VARIANT_BOOL(-1));
        if p.wsus.is_some() {
            let _ = searcher.SetServerSelection(ssManagedServer);
        } else if !p.microsoft_update {
            let _ = searcher.SetServerSelection(ssWindowsUpdate);
        }
    }
    let criteria = BSTR::from("IsInstalled=0 and IsHidden=0");
    let result = unsafe { searcher.Search(&criteria) }.map_err(|e| {
        let code = e.code().0 as u32;
        match code {
            0x8024402C | 0x80244022 | 0x8024401C | 0x80072EE2 | 0x80072EFD | 0x80072EE7 => format!("{} could not be reached (0x{:08X}). {}", if p.wsus.is_some() { "the WSUS server" } else { "Windows Update" }, code, if p.wsus.is_some() { "Check that the WSUS service and its port answer from this machine" } else { "This is expected on an air gapped server" }),
            0x80240438 | 0x8024401F | 0x8024401B | 0x80244010 => format!("the update source refused the request (0x{:08X}){}", code, if p.wsus.is_some() { ". The WSUS server may not have this machine's client version or its SSL certificate is not trusted here" } else { "" }),
            0x80244007 | 0x80244008 | 0x8024400D | 0x8024400E => format!("the WSUS server returned a fault (0x{:08X}). Look at its SoftwareDistribution.log or WSUS console", code),
            _ => com_err("search failed", &e),
        }
    })?;
    let updates = unsafe { result.Updates() }.map_err(|e| com_err("results", &e))?;
    let n = unsafe { updates.Count() }.unwrap_or(0);
    let mut out = Vec::new();
    for i in 0..n {
        let Ok(u) = (unsafe { updates.get_Item(i) }) else { continue };
        let title = unsafe { u.Title() }.map(|b| b.to_string()).unwrap_or_default();
        let mut kb = Vec::new();
        if let Ok(ids) = unsafe { u.KBArticleIDs() } {
            let c = unsafe { ids.Count() }.unwrap_or(0);
            for k in 0..c {
                if let Ok(s) = unsafe { ids.get_Item(k) } {
                    kb.push(format!("KB{}", s));
                }
            }
        }
        let reboot = unsafe { u.InstallationBehavior().and_then(|b| b.RebootBehavior()) }.map(|r| match r.0 { 0 => "Never", 1 => "Always", 2 => "Can request", _ => "" }).unwrap_or("");
        let size = unsafe { u.MaxDownloadSize() }.map(|d| decimal_to_u64(&d)).unwrap_or(0);
        let (update_id, revision) = unsafe { u.Identity() }.map(|i| (unsafe { i.UpdateID() }.map(|b| b.to_string()).unwrap_or_default(), unsafe { i.RevisionNumber() }.unwrap_or(0))).unwrap_or_default();
        out.push(PendingRow {
            update_id,
            revision,
            eula_accepted: unsafe { u.EulaAccepted() }.map(|b| b.as_bool()).unwrap_or(true),
            kb: if kb.is_empty() { kb_of(&title) } else { kb.join(", ") },
            title,
            severity: unsafe { u.MsrcSeverity() }.map(|b| b.to_string()).unwrap_or_default(),
            downloaded: unsafe { u.IsDownloaded() }.map(|b| b.as_bool()).unwrap_or(false),
            mandatory: unsafe { u.IsMandatory() }.map(|b| b.as_bool()).unwrap_or(false),
            reboot: reboot.to_string(),
            size,
            description: unsafe { u.Description() }.map(|b| b.to_string()).unwrap_or_default(),
        });
    }
    Ok(out)
}

fn decimal_to_u64(d: &windows::Win32::Foundation::DECIMAL) -> u64 {
    let lo = unsafe { d.Anonymous2.Lo64 };
    let scale = unsafe { d.Anonymous1.Anonymous.scale } as u32;
    let mut v = lo;
    for _ in 0..scale {
        v /= 10;
    }
    v
}
