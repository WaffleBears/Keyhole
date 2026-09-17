use crate::sys::com::ComGuard;
use crate::sys::winerr;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IExecAction, IRegisteredTask, ITaskFolder, ITaskService, TASK_ACTION_EXEC, TASK_ENUM_HIDDEN, TASK_STATE,
    TASK_STATE_DISABLED, TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

#[derive(Clone, Debug, serde::Serialize)]
pub struct TaskRow {
    pub name: String,
    pub path: String,
    pub state: String,
    pub action: String,
    pub next: String,
    pub last: String,
    pub result: String,
    pub result_ok: bool,
    pub author: String,
    pub triggers: String,
    pub target: String,
    pub hidden: bool,
    pub user: String,
}

pub fn result_text(code: u32) -> (String, bool) {
    match code {
        0 => ("Success".into(), true),
        0x41300 => ("Ready".into(), true),
        0x41301 => ("Running".into(), true),
        0x41302 => ("Disabled".into(), true),
        0x41303 => ("Never run".into(), true),
        0x41304 => ("No more runs".into(), true),
        0x41305 => ("Not yet run".into(), true),
        0x41306 => ("Ended by user".into(), false),
        0x41307 => ("No valid triggers".into(), true),
        0x41308 => ("Event trigger".into(), true),
        0x41325 => ("Queued".into(), true),
        0x800710E0 => ("Skipped (idle)".into(), false),
        0x80070001 => ("Wrong function".into(), false),
        0x80070002 => ("File not found".into(), false),
        0x80070005 => ("Access denied".into(), false),
        0x8007010B => ("Directory not found".into(), false),
        0x80070420 => ("Service already running".into(), false),
        0x80070490 => ("Not found".into(), false),
        1 => ("Exit code 1".into(), false),
        c if c < 0x1000 => (format!("Exit code {}", c), false),
        c => (format!("0x{:08X}", c), false),
    }
}

fn trigger_text(t: windows::Win32::System::TaskScheduler::TASK_TRIGGER_TYPE2) -> &'static str {
    use windows::Win32::System::TaskScheduler::*;
    match t {
        TASK_TRIGGER_EVENT => "On event",
        TASK_TRIGGER_TIME => "One time",
        TASK_TRIGGER_DAILY => "Daily",
        TASK_TRIGGER_WEEKLY => "Weekly",
        TASK_TRIGGER_MONTHLY => "Monthly",
        TASK_TRIGGER_MONTHLYDOW => "Monthly",
        TASK_TRIGGER_IDLE => "On idle",
        TASK_TRIGGER_REGISTRATION => "On registration",
        TASK_TRIGGER_BOOT => "At startup",
        TASK_TRIGGER_LOGON => "At logon",
        TASK_TRIGGER_SESSION_STATE_CHANGE => "On session change",
        TASK_TRIGGER_CUSTOM_TRIGGER_01 => "Custom",
        _ => "Other",
    }
}

pub fn split_path(full_path: &str) -> (String, String) {
    match full_path.rfind('\\') {
        Some(0) => ("\\".to_string(), full_path[1..].to_string()),
        Some(i) => (full_path[..i].to_string(), full_path[i + 1..].to_string()),
        None => ("\\".to_string(), full_path.to_string()),
    }
}

struct Scheduler {
    service: ITaskService,
    _com: ComGuard,
}

fn connect() -> Result<Scheduler, String> {
    let com = ComGuard::mta();
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("the Task Scheduler service is not available ({})", winerr::describe(&e)))?;
        service
            .Connect(&VARIANT::default(), &VARIANT::default(), &VARIANT::default(), &VARIANT::default())
            .map_err(|e| format!("could not connect to the Task Scheduler: {}", winerr::describe(&e)))?;
        Ok(Scheduler { service, _com: com })
    }
}

fn folder_of(s: &Scheduler, folder: &str) -> Result<ITaskFolder, String> {
    unsafe {
        s.service
            .GetFolder(&BSTR::from(if folder.is_empty() { "\\" } else { folder }))
            .map_err(|e| format!("task folder: {}", task_err(e.code().0)))
    }
}

pub fn action(full_path: &str, act: &str) -> Result<(), String> {
    let (folder, name) = split_path(full_path);
    let s = connect()?;
    let f = folder_of(&s, &folder)?;
    unsafe {
        if act == "delete" {
            return f
                .DeleteTask(&BSTR::from(name.as_str()), 0)
                .map_err(|e| task_err(e.code().0));
        }
        let task = f
            .GetTask(&BSTR::from(name.as_str()))
            .map_err(|e| task_err(e.code().0))?;
        match act {
            "run" => task
                .Run(&VARIANT::default())
                .map(|_| ())
                .map_err(|e| task_err(e.code().0)),
            "enable" => task.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(-1)).map_err(|e| task_err(e.code().0)),
            "disable" => task.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(0)).map_err(|e| task_err(e.code().0)),
            "end" => task.Stop(0).map_err(|e| task_err(e.code().0)),
            other => Err(format!("unknown task action {}", other)),
        }
    }
}

pub fn xml(full_path: &str) -> Result<String, String> {
    let (folder, name) = split_path(full_path);
    let s = connect()?;
    let f = folder_of(&s, &folder)?;
    unsafe {
        let task = f.GetTask(&BSTR::from(name.as_str())).map_err(|e| task_err(e.code().0))?;
        task.Xml().map(|b| b.to_string()).map_err(|e| task_err(e.code().0))
    }
}

fn task_err(code: i32) -> String {
    match code as u32 {
        0x80070002 => "the task no longer exists".into(),
        c if c & 0xFFFF_0000 == 0x8007_0000 => winerr::text(c & 0xFFFF),
        c => winerr::text(c),
    }
}

fn state_text(s: TASK_STATE) -> &'static str {
    match s {
        TASK_STATE_DISABLED => "Disabled",
        TASK_STATE_QUEUED => "Queued",
        TASK_STATE_READY => "Ready",
        TASK_STATE_RUNNING => "Running",
        _ => "Unknown",
    }
}

pub fn list() -> Result<Vec<TaskRow>, String> {
    let mut out = Vec::new();
    let s = connect()?;
    let root = folder_of(&s, "\\")?;
    unsafe {
        walk(&root, &mut out, 0);
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

unsafe fn walk(folder: &ITaskFolder, out: &mut Vec<TaskRow>, depth: u32) {
    if depth > 12 || out.len() > 20_000 {
        return;
    }
    unsafe {
        if let Ok(tasks) = folder.GetTasks(TASK_ENUM_HIDDEN.0)
            && let Ok(count) = tasks.Count() {
                for i in 1..=count {
                    if let Ok(task) = tasks.get_Item(&VARIANT::from(i)) {
                        out.push(read_task(&task));
                    }
                }
            }
        if let Ok(folders) = folder.GetFolders(0)
            && let Ok(count) = folders.Count() {
                for i in 1..=count {
                    if let Ok(sub) = folders.get_Item(&VARIANT::from(i)) {
                        walk(&sub, out, depth + 1);
                    }
                }
            }
    }
}

unsafe fn read_task(task: &IRegisteredTask) -> TaskRow {
    unsafe {
        let name = task.Name().map(|b| b.to_string()).unwrap_or_default();
        let full = task.Path().map(|b| b.to_string()).unwrap_or_default();
        let folder = match full.rfind('\\') {
            Some(0) => "\\".to_string(),
            Some(i) => full[..i].to_string(),
            None => full.clone(),
        };
        let state = task.State().map(state_text).unwrap_or("Unknown").to_string();
        let next = task.NextRunTime().ok().map(fmt_date).unwrap_or_default();
        let last = task.LastRunTime().ok().map(fmt_date).unwrap_or_default();
        let (result, result_ok) = match task.LastTaskResult() {
            Ok(code) if last.is_empty() && code == 0 => (String::new(), true),
            Ok(code) => result_text(code as u32),
            Err(_) => (String::new(), true),
        };
        let (action, author, triggers, hidden, user) = read_definition(task);
        let target = if action.starts_with('(') { String::new() } else { crate::sys::actions::exe_from_command(&action) };
        TaskRow {
            name,
            path: folder,
            state,
            action,
            next,
            last,
            result,
            result_ok,
            author,
            triggers,
            target,
            hidden,
            user,
        }
    }
}

unsafe fn read_definition(task: &IRegisteredTask) -> (String, String, String, bool, String) {
    unsafe {
        let Ok(def) = task.Definition() else {
            return (String::new(), String::new(), String::new(), false, String::new());
        };
        let user = def
            .Principal()
            .ok()
            .map(|p| {
                let mut id = BSTR::default();
                let _ = p.UserId(&mut id);
                let mut group = BSTR::default();
                let _ = p.GroupId(&mut group);
                let who = if id.is_empty() { group.to_string() } else { id.to_string() };
                let who = if who.starts_with("S-1-") { super::accounts::name_of_sid_text(&who).unwrap_or(who) } else { who };
                let mut logon = windows::Win32::System::TaskScheduler::TASK_LOGON_TYPE::default();
                let _ = p.LogonType(&mut logon);
                let mut level = windows::Win32::System::TaskScheduler::TASK_RUNLEVEL_TYPE::default();
                let _ = p.RunLevel(&mut level);
                let mut s = who;
                if level.0 == 1 {
                    s.push_str(" (highest privileges)");
                }
                if logon.0 == 5 {
                    s.push_str(" (service account)");
                }
                s
            })
            .unwrap_or_default();
        let hidden = def
            .Settings()
            .ok()
            .map(|s| {
                let mut v = windows::Win32::Foundation::VARIANT_BOOL(0);
                s.Hidden(&mut v).is_ok() && v.as_bool()
            })
            .unwrap_or(false);
        let mut author = String::new();
        if let Ok(reg) = def.RegistrationInfo() {
            let mut b = BSTR::default();
            if reg.Author(&mut b).is_ok() {
                author = b.to_string();
            }
        }
        let mut triggers: Vec<&'static str> = Vec::new();
        if let Ok(list) = def.Triggers() {
            let mut n = 0i32;
            if list.Count(&mut n).is_ok() {
                for i in 1..=n {
                    if let Ok(t) = list.get_Item(i) {
                        let mut kind = windows::Win32::System::TaskScheduler::TASK_TRIGGER_TYPE2::default();
                        if t.Type(&mut kind).is_ok() {
                            let label = trigger_text(kind);
                            if !triggers.contains(&label) {
                                triggers.push(label);
                            }
                        }
                    }
                }
            }
        }
        let triggers = triggers.join(", ");
        let Ok(actions) = def.Actions() else {
            return (String::new(), author, triggers, hidden, user);
        };
        let mut count = 0i32;
        if actions.Count(&mut count).is_err() {
            return (String::new(), author, triggers, hidden, user);
        }
        let mut other = String::new();
        for i in 1..=count {
            if let Ok(action) = actions.get_Item(i) {
                let mut kind = TASK_ACTION_EXEC;
                let _ = action.Type(&mut kind);
                if kind == TASK_ACTION_EXEC {
                    if let Ok(exec) = action.cast::<IExecAction>() {
                        let mut pbuf = BSTR::default();
                        let _ = exec.Path(&mut pbuf);
                        let mut abuf = BSTR::default();
                        let _ = exec.Arguments(&mut abuf);
                        let path = pbuf.to_string();
                        let args = abuf.to_string();
                        let mut s = path;
                        if !args.trim().is_empty() {
                            s.push(' ');
                            s.push_str(&args);
                        }
                        if !s.trim().is_empty() {
                            return (s, author, triggers, hidden, user);
                        }
                    }
                } else if other.is_empty() {
                    other = match kind.0 {
                        5 => "(COM handler)".to_string(),
                        6 => "(send email)".to_string(),
                        7 => "(show message)".to_string(),
                        _ => "(other action)".to_string(),
                    };
                }
            }
        }
        (other, author, triggers, hidden, user)
    }
}

fn fmt_date(date: f64) -> String {
    if date <= 1.0 {
        return String::new();
    }
    let days = date.trunc() as i64;
    let frac = date.fract().abs();
    let secs_of_day = ((frac * 86400.0).round() as i64).min(86399);
    let z = days - 25569 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    if year < 2000 {
        return String::new();
    }
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", year, m, d, hh, mm)
}

#[derive(Clone, Default, Debug)]
pub struct NewTask {
    pub name: String,
    pub description: String,
    pub program: String,
    pub arguments: String,
    pub start_in: String,
    pub trigger: String,
    pub time: String,
    pub date: String,
    pub days: String,
    pub repeat: String,
    pub run_as: String,
    pub account: String,
    pub password: crate::api::Secret,
    pub highest: bool,
    pub enabled: bool,
}

pub const TRIGGERS: &[(&str, &str)] = &[
    ("daily", "Daily at a time"),
    ("weekly", "Weekly on chosen days"),
    ("once", "Once at a date and time"),
    ("logon", "At logon of any user"),
    ("boot", "At system startup"),
];

pub const REPEATS: &[(&str, &str)] = &[("", "Do not repeat"), ("PT5M", "Every 5 minutes"), ("PT15M", "Every 15 minutes"), ("PT30M", "Every 30 minutes"), ("PT1H", "Every hour"), ("PT4H", "Every 4 hours")];

pub const RUN_AS: &[(&str, &str)] = &[("system", "SYSTEM"), ("interactive", "Me, only while logged on"), ("account", "Another account (fill in below)"), ("localservice", "LOCAL SERVICE"), ("networkservice", "NETWORK SERVICE")];

fn local_now() -> (i32, u32, u32, u32, u32) {
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    (t.wYear as i32, t.wMonth as u32, t.wDay as u32, t.wHour as u32, t.wMinute as u32)
}

pub fn default_time() -> String {
    let (_, _, _, h, _) = local_now();
    format!("{:02}:00", (h + 1) % 24)
}

pub fn default_date() -> String {
    let (y, m, d, _, _) = local_now();
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn parse_time(s: &str) -> Result<(u32, u32), String> {
    let t = s.trim();
    let (h, m) = t.split_once(':').ok_or_else(|| format!("time {:?} must look like 14:30", t))?;
    let h: u32 = h.trim().parse().map_err(|_| format!("time {:?} must look like 14:30", t))?;
    let m: u32 = m.trim().parse().map_err(|_| format!("time {:?} must look like 14:30", t))?;
    if h > 23 || m > 59 {
        return Err(format!("time {:?} is out of range", t));
    }
    Ok((h, m))
}

fn parse_date(s: &str) -> Result<(i32, u32, u32), String> {
    let t = s.trim();
    let parts: Vec<&str> = t.split(['-', '/']).collect();
    let bad = || format!("date {:?} must look like 2026-09-16", t);
    if parts.len() != 3 {
        return Err(bad());
    }
    let y: i32 = parts[0].trim().parse().map_err(|_| bad())?;
    let m: u32 = parts[1].trim().parse().map_err(|_| bad())?;
    let d: u32 = parts[2].trim().parse().map_err(|_| bad())?;
    if !(2000..=2200).contains(&y) || m == 0 || m > 12 || d == 0 || d > 31 {
        return Err(bad());
    }
    Ok((y, m, d))
}

pub fn days_mask(days: &str) -> Result<i16, String> {
    let mut mask = 0i16;
    for word in days.split([',', ' ', ';']).filter(|w| !w.is_empty()) {
        let w: String = word.to_lowercase().chars().take(3).collect();
        let bit = match w.as_str() {
            "sun" => 1,
            "mon" => 2,
            "tue" => 4,
            "wed" => 8,
            "thu" => 16,
            "fri" => 32,
            "sat" => 64,
            _ => return Err(format!("{:?} is not a day of the week. Use names like Mon, Tue, Wed", word)),
        };
        mask |= bit;
    }
    if mask == 0 {
        return Err("pick at least one day of the week, for example Mon, Wed, Fri".into());
    }
    Ok(mask)
}

pub fn validate(t: &NewTask) -> Result<(), String> {
    let name = t.name.trim();
    if name.is_empty() || name.ends_with('\\') {
        return Err("give the task a name".into());
    }
    if name.chars().any(|c| matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|' | '/')) {
        return Err("the task name cannot contain : * ? \" < > | or /".into());
    }
    if t.program.trim().is_empty() {
        return Err("choose a program to run".into());
    }
    match t.trigger.as_str() {
        "daily" => {
            parse_time(&t.time)?;
        }
        "weekly" => {
            parse_time(&t.time)?;
            days_mask(&t.days)?;
        }
        "once" => {
            parse_time(&t.time)?;
            parse_date(&t.date)?;
        }
        "logon" | "boot" => {}
        other => return Err(format!("unknown trigger {:?}", other)),
    }
    if t.run_as == "account" && t.account.trim().is_empty() {
        return Err("enter the account the task should run as, for example DOMAIN\\user or .\\user".into());
    }
    Ok(())
}

fn start_boundary(t: &NewTask) -> Result<String, String> {
    let (y, mo, d) = if t.trigger == "once" {
        parse_date(&t.date)?
    } else {
        let (y, m, d, _, _) = local_now();
        (y, m, d)
    };
    let (h, mi) = if matches!(t.trigger.as_str(), "logon" | "boot") { (0, 0) } else { parse_time(&t.time)? };
    Ok(format!("{:04}-{:02}-{:02}T{:02}:{:02}:00", y, mo, d, h, mi))
}

fn ensure_folder(s: &Scheduler, folder: &str) -> Result<ITaskFolder, String> {
    if let Ok(f) = folder_of(s, folder) {
        return Ok(f);
    }
    let mut current = folder_of(s, "\\")?;
    for part in folder.split('\\').filter(|p| !p.is_empty()) {
        current = unsafe {
            match current.GetFolder(&BSTR::from(part)) {
                Ok(f) => f,
                Err(_) => current.CreateFolder(&BSTR::from(part), &VARIANT::default()).map_err(|e| format!("could not create task folder {}: {}", part, task_err(e.code().0)))?,
            }
        };
    }
    Ok(current)
}

pub fn create(t: &NewTask) -> Result<String, String> {
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::TaskScheduler::*;
    validate(t)?;
    let full = if t.name.starts_with('\\') { t.name.trim().to_string() } else { format!("\\{}", t.name.trim()) };
    let (folder, name) = split_path(&full);
    let s = connect()?;
    let f = ensure_folder(&s, &folder)?;
    let err = |what: &'static str| move |e: windows::core::Error| format!("{}: {}", what, task_err(e.code().0));
    unsafe {
        if f.GetTask(&BSTR::from(name.as_str())).is_ok() {
            return Err(format!("a task called {} already exists in {}", name, folder));
        }
        let def = s.service.NewTask(0).map_err(err("new task"))?;
        let info = def.RegistrationInfo().map_err(err("registration info"))?;
        let author = format!("{}\\{}", std::env::var("USERDOMAIN").unwrap_or_default(), std::env::var("USERNAME").unwrap_or_default());
        let _ = info.SetAuthor(&BSTR::from(author.as_str()));
        let _ = info.SetDescription(&BSTR::from(t.description.trim()));
        let settings = def.Settings().map_err(err("settings"))?;
        let _ = settings.SetEnabled(VARIANT_BOOL::from(t.enabled));
        let _ = settings.SetStartWhenAvailable(VARIANT_BOOL::from(true));
        let _ = settings.SetDisallowStartIfOnBatteries(VARIANT_BOOL::from(false));
        let _ = settings.SetStopIfGoingOnBatteries(VARIANT_BOOL::from(false));
        let _ = settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW);
        let _ = settings.SetExecutionTimeLimit(&BSTR::from("PT72H"));
        let principal = def.Principal().map_err(err("principal"))?;
        let _ = principal.SetRunLevel(if t.highest { TASK_RUNLEVEL_HIGHEST } else { TASK_RUNLEVEL_LUA });
        let (user, password, logon) = match t.run_as.as_str() {
            "system" => ("SYSTEM".to_string(), String::new(), TASK_LOGON_SERVICE_ACCOUNT),
            "localservice" => ("NT AUTHORITY\\LocalService".to_string(), String::new(), TASK_LOGON_SERVICE_ACCOUNT),
            "networkservice" => ("NT AUTHORITY\\NetworkService".to_string(), String::new(), TASK_LOGON_SERVICE_ACCOUNT),
            "account" if t.password.0.is_empty() => (super::accounts::canonical_account(&t.account), String::new(), TASK_LOGON_S4U),
            "account" => (super::accounts::canonical_account(&t.account), t.password.0.clone(), TASK_LOGON_PASSWORD),
            _ => (author.clone(), String::new(), TASK_LOGON_INTERACTIVE_TOKEN),
        };
        let _ = principal.SetLogonType(logon);
        let _ = principal.SetUserId(&BSTR::from(user.as_str()));
        let triggers = def.Triggers().map_err(err("triggers"))?;
        let boundary = BSTR::from(start_boundary(t)?.as_str());
        let trigger = match t.trigger.as_str() {
            "daily" => {
                let tr = triggers.Create(TASK_TRIGGER_DAILY).map_err(err("trigger"))?;
                let d: IDailyTrigger = tr.cast().map_err(err("trigger"))?;
                d.SetDaysInterval(1).map_err(err("trigger"))?;
                tr
            }
            "weekly" => {
                let tr = triggers.Create(TASK_TRIGGER_WEEKLY).map_err(err("trigger"))?;
                let w: IWeeklyTrigger = tr.cast().map_err(err("trigger"))?;
                w.SetWeeksInterval(1).map_err(err("trigger"))?;
                w.SetDaysOfWeek(days_mask(&t.days)?).map_err(err("trigger"))?;
                tr
            }
            "once" => triggers.Create(TASK_TRIGGER_TIME).map_err(err("trigger"))?,
            "logon" => triggers.Create(TASK_TRIGGER_LOGON).map_err(err("trigger"))?,
            _ => triggers.Create(TASK_TRIGGER_BOOT).map_err(err("trigger"))?,
        };
        trigger.SetStartBoundary(&boundary).map_err(err("trigger start"))?;
        let _ = trigger.SetEnabled(VARIANT_BOOL::from(true));
        if !t.repeat.is_empty() {
            let rep = trigger.Repetition().map_err(err("repetition"))?;
            rep.SetInterval(&BSTR::from(t.repeat.as_str())).map_err(err("repetition"))?;
            if matches!(t.trigger.as_str(), "daily" | "weekly" | "once") {
                let _ = rep.SetDuration(&BSTR::from("P1D"));
            }
        }
        let actions = def.Actions().map_err(err("actions"))?;
        let act = actions.Create(TASK_ACTION_EXEC).map_err(err("action"))?;
        let exec: IExecAction = act.cast().map_err(err("action"))?;
        exec.SetPath(&BSTR::from(t.program.trim())).map_err(err("program"))?;
        if !t.arguments.trim().is_empty() {
            exec.SetArguments(&BSTR::from(t.arguments.trim())).map_err(err("arguments"))?;
        }
        if !t.start_in.trim().is_empty() {
            exec.SetWorkingDirectory(&BSTR::from(t.start_in.trim())).map_err(err("start in"))?;
        }
        let user_v = if logon == TASK_LOGON_INTERACTIVE_TOKEN { VARIANT::default() } else { VARIANT::from(user.as_str()) };
        let pass_v = if password.is_empty() { VARIANT::default() } else { VARIANT::from(password.as_str()) };
        f.RegisterTaskDefinition(&BSTR::from(name.as_str()), &def, TASK_CREATE.0, &user_v, &pass_v, logon, &VARIANT::default()).map_err(|e| match e.code().0 as u32 {
            0x80070569 => "that account is not allowed to log on as a batch job. Use SYSTEM, run it only while logged on, or grant it that right".to_string(),
            0x8007052E => "the password is wrong for that account".to_string(),
            0x80070534 | 0x80070525 => format!("the account {} was not found", user),
            0x800700B7 => format!("a task called {} already exists", name),
            c => format!("could not register the task: {}", task_err(c as i32)),
        })?;
    }
    Ok(full)
}

pub fn remove_folder(path: &str) -> Result<(), String> {
    let (parent, name) = split_path(path);
    let s = connect()?;
    let f = folder_of(&s, &parent)?;
    unsafe { f.DeleteFolder(&BSTR::from(name.as_str()), 0).map_err(|e| task_err(e.code().0)) }
}

