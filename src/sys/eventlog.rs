use super::{filetime_to_unix_ms, from_wide, wide};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
use windows::Win32::Security::{PSID, SID_NAME_USE};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::LookupAccountSidW;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EVT_VARIANT, EvtClose, EvtCreateRenderContext, EvtExportLog, EvtExportLogChannelPath, EvtFormatMessage, EvtFormatMessageEvent, EvtFormatMessageTask, EvtNext, EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath,
    EvtQueryReverseDirection, EvtRender, EvtRenderContextSystem, EvtRenderEventValues, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents, EvtVarTypeFileTime, EvtVarTypeNull, EvtVarTypeSid, EvtVarTypeString, EvtVarTypeUInt16, EvtVarTypeUInt32, EvtVarTypeUInt64, EvtVarTypeByte, EvtVarTypeHexInt32,
    EvtVarTypeHexInt64, EvtVarTypeInt32, EvtVarTypeBoolean, EvtOpenChannelEnum, EvtNextChannelPath, EvtOpenChannelConfig, EvtGetChannelConfigProperty, EvtChannelConfigEnabled, EvtChannelConfigType, EvtChannelConfigClassicEventlog,
};
use windows::core::{PCWSTR, PWSTR};

pub const MAX_PER_CHANNEL: usize = 10_000;
pub const CORE_CHANNELS: &[&str] = &["System", "Application", "Setup"];
const AUDIT_FAILURE: u64 = 0x0010_0000_0000_0000;
const BATCH: usize = 256;

const SCM_SERVICE_EVENTS: &[u32] = &[7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7032, 7034, 7036, 7038, 7040, 7045];

#[derive(Clone, Debug, Default)]
pub struct EventRow {
    pub time_ms: i64,
    pub log: String,
    pub level: u8,
    pub source: String,
    pub id: u32,
    pub task: String,
    pub computer: String,
    pub user: String,
    pub first_line: String,
    pub message: String,
    pub record_id: u64,
    pub pid: Option<u32>,
    pub service: Option<String>,
}

pub struct QueryResult {
    pub rows: Vec<EventRow>,
    pub capped: bool,
}

pub fn level_name(level: u8) -> &'static str {
    match level {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 | 0 => "Information",
        5 => "Verbose",
        6 => "Audit failure",
        _ => "Other",
    }
}

fn err(prefix: &str, e: windows::core::Error) -> String {
    let code = e.code().0 as u32 & 0xFFFF;
    match code {
        5 => format!("{}: access denied", prefix),
        15000 | 15007 => format!("{}: the log does not exist", prefix),
        1722 | 1717 => format!("{}: the Windows Event Log service is not running", prefix),
        _ => format!("{}: {}", prefix, e.message().trim()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Levels {
    Errors,
    Information,
    AuditFailures,
    AuditSuccesses,
    All,
}

fn level_xpath(levels: Levels) -> &'static str {
    match levels {
        Levels::Errors => "(Level>=1 and Level<=3)",
        Levels::Information => "(Level=0 or Level>=4)",
        Levels::AuditFailures => "band(Keywords,4503599627370496)",
        Levels::AuditSuccesses => "band(Keywords,9007199254740992)",
        Levels::All => "(Level>=0)",
    }
}

fn window_xpath(window_ms: i64, levels: Levels) -> String {
    if window_ms <= 0 {
        format!("*[System[{}]]", level_xpath(levels))
    } else {
        format!("*[System[{} and TimeCreated[timediff(@SystemTime) <= {}]]]", level_xpath(levels), window_ms)
    }
}

static CHANNEL_CACHE: Mutex<Option<(Vec<String>, Instant)>> = Mutex::new(None);

pub fn all_channels() -> Vec<String> {
    if let Some((list, at)) = CHANNEL_CACHE.lock().as_ref()
        && at.elapsed() < Duration::from_secs(300) {
            return list.clone();
        }
    let list = enumerate_channels();
    *CHANNEL_CACHE.lock() = Some((list.clone(), Instant::now()));
    list
}

pub fn channel_exists(name: &str) -> bool {
    let w = wide(name);
    match unsafe { EvtOpenChannelConfig(None, PCWSTR(w.as_ptr()), 0) } {
        Ok(h) => {
            drop(Handle(h));
            true
        }
        Err(_) => false,
    }
}

fn enumerate_channels() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(e) = (unsafe { EvtOpenChannelEnum(None, 0) }) else { return out };
    let e = Handle(e);
    let mut buf = vec![0u16; 512];
    loop {
        let mut used = 0u32;
        match unsafe { EvtNextChannelPath(e.0, Some(&mut buf), &mut used) } {
            Ok(()) => {}
            Err(err) if err.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {
                buf.resize(used as usize + 16, 0);
                continue;
            }
            Err(_) => break,
        }
        let name = from_wide(&buf);
        if !name.is_empty() && !CORE_CHANNELS.iter().any(|c| c.eq_ignore_ascii_case(&name)) && name != "Security" && channel_wanted(&name) {
            out.push(name);
        }
    }
    out.sort_by_key(|n| n.to_lowercase());
    out
}

fn config_u32(config: EVT_HANDLE, id: windows::Win32::System::EventLog::EVT_CHANNEL_CONFIG_PROPERTY_ID) -> Option<u64> {
    let mut buf = vec![0u8; std::mem::size_of::<EVT_VARIANT>() + 64];
    let mut used = 0u32;
    unsafe { EvtGetChannelConfigProperty(config, id, 0, buf.len() as u32, Some(buf.as_mut_ptr() as *mut EVT_VARIANT), &mut used) }.ok()?;
    let v: EVT_VARIANT = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const EVT_VARIANT) };
    let ty = v.Type & 0x7F;
    unsafe {
        if ty == EvtVarTypeBoolean.0 as u32 {
            Some(if v.Anonymous.BooleanVal.as_bool() { 1 } else { 0 })
        } else if ty == EvtVarTypeUInt32.0 as u32 {
            Some(v.Anonymous.UInt32Val as u64)
        } else if ty == EvtVarTypeUInt64.0 as u32 {
            Some(v.Anonymous.UInt64Val)
        } else {
            None
        }
    }
}

fn channel_wanted(name: &str) -> bool {
    let lower = name.to_lowercase();
    if lower.ends_with("/analytic") || lower.ends_with("/debug") || lower.contains("/diagnostic") {
        return false;
    }
    let w = wide(name);
    let Ok(config) = (unsafe { EvtOpenChannelConfig(None, PCWSTR(w.as_ptr()), 0) }) else { return false };
    let config = Handle(config);
    if config_u32(config.0, EvtChannelConfigEnabled) != Some(1) {
        return false;
    }
    if config_u32(config.0, EvtChannelConfigClassicEventlog) == Some(1) {
        return true;
    }
    matches!(config_u32(config.0, EvtChannelConfigType), Some(0) | Some(1))
}

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

struct Formatter {
    system: Handle,
    publishers: HashMap<String, Option<EVT_HANDLE>>,
    sids: HashMap<String, String>,
}

unsafe impl Send for Formatter {}

impl Drop for Formatter {
    fn drop(&mut self) {
        for h in self.publishers.values().flatten() {
            unsafe {
                let _ = EvtClose(*h);
            }
        }
    }
}

impl Formatter {
    fn new() -> Result<Formatter, String> {
        let system = unsafe { EvtCreateRenderContext(None, EvtRenderContextSystem.0) }.map_err(|e| err("could not create the system render context", e))?;
        Ok(Formatter { system: Handle(system), publishers: HashMap::new(), sids: HashMap::new() })
    }

    fn publisher(&mut self, name: &str) -> Option<EVT_HANDLE> {
        if let Some(h) = self.publishers.get(name) {
            return *h;
        }
        let w = wide(name);
        let h = unsafe { EvtOpenPublisherMetadata(None, PCWSTR(w.as_ptr()), PCWSTR::null(), 0, 0) }.ok();
        self.publishers.insert(name.to_string(), h);
        h
    }

    fn render_values(&self, context: EVT_HANDLE, event: EVT_HANDLE) -> Option<(Vec<u8>, u32)> {
        let mut used = 0u32;
        let mut count = 0u32;
        let first = unsafe { EvtRender(Some(context), event, EvtRenderEventValues.0, 0, None, &mut used, &mut count) };
        if let Err(e) = &first
            && e.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() {
                return None;
            }
        let mut buf = vec![0u8; used.max(16) as usize];
        unsafe { EvtRender(Some(context), event, EvtRenderEventValues.0, buf.len() as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut count) }.ok()?;
        Some((buf, count))
    }

    fn message(&mut self, publisher: Option<EVT_HANDLE>, event: EVT_HANDLE, flags: u32) -> Option<String> {
        let rendered_anyway = |e: &windows::core::Error| matches!(e.code().0 as u32 & 0xFFFF, 15029..=15031);
        let mut used = 0u32;
        let first = unsafe { EvtFormatMessage(publisher, Some(event), 0, None, flags, None, &mut used) };
        if let Err(e) = &first
            && e.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() && !rendered_anyway(e) {
                return None;
            }
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; used as usize + 1];
        let second = unsafe { EvtFormatMessage(publisher, Some(event), 0, None, flags, Some(&mut buf), &mut used) };
        if let Err(e) = &second
            && !rendered_anyway(e) {
                return None;
            }
        let text = from_wide(&buf);
        if text.trim().is_empty() { None } else { Some(text) }
    }

    fn data_strings(&self, event: EVT_HANDLE) -> Vec<String> {
        match render_xml(event) {
            Some(xml) => data_elements(&xml),
            None => Vec::new(),
        }
    }

    fn sid_name(&mut self, sid: PSID) -> String {
        let mut text = PWSTR::null();
        let key = unsafe {
            if ConvertSidToStringSidW(sid, &mut text).is_err() {
                return String::new();
            }
            let s = text.to_string().unwrap_or_default();
            let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(text.0 as *mut _)));
            s
        };
        if let Some(v) = self.sids.get(&key) {
            return v.clone();
        }
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain_len = domain.len() as u32;
        let mut kind = SID_NAME_USE::default();
        let ok = unsafe { LookupAccountSidW(PCWSTR::null(), sid, Some(PWSTR(name.as_mut_ptr())), &mut name_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) }.is_ok();
        let value = if ok {
            let d = from_wide(&domain);
            let n = from_wide(&name);
            if d.is_empty() { n } else { format!("{}\\{}", d, n) }
        } else {
            key.clone()
        };
        self.sids.insert(key, value.clone());
        value
    }

    fn row(&mut self, event: EVT_HANDLE, channel: &str) -> Option<EventRow> {
        let (buf, count) = self.render_values(self.system.0, event)?;
        let vars = variants(&buf, count);
        let get = |i: usize| vars.get(i).cloned().unwrap_or(Var::Null);
        let source = match get(0) { Var::Str(s) => s, _ => String::new() };
        let id = match get(2) { Var::U64(n) => (n & 0xFFFF) as u32, _ => 0 };
        let mut level = match get(4) { Var::U64(0) => 4, Var::U64(n) => n as u8, _ => 4 };
        if channel.eq_ignore_ascii_case("Security")
            && let Var::U64(keywords) = get(7)
                && keywords & AUDIT_FAILURE != 0 {
                    level = 6;
                }
        let task_num = match get(5) { Var::U64(n) => n, _ => 0 };
        let time_ms = match get(8) { Var::Time(t) => filetime_to_unix_ms(t as i64), _ => 0 };
        let record_id = match get(9) { Var::U64(n) => n, _ => 0 };
        let pid = match get(12) { Var::U64(n) if n > 0 => Some(n as u32), _ => None };
        let log = match get(14) { Var::Str(s) if !s.is_empty() => s, _ => channel.to_string() };
        let computer = match get(15) { Var::Str(s) => s, _ => String::new() };
        let user = match get(16) { Var::Sid(p) => self.sid_name(PSID(p as *mut _)), _ => String::new() };
        let publisher = self.publisher(&source);
        let mut data: Option<Vec<String>> = None;
        let mut no_template = false;
        let message = match self.message(publisher, event, EvtFormatMessageEvent.0) {
            Some(m) => m,
            None => {
                no_template = true;
                let d = self.data_strings(event);
                let m = d.join(" ");
                data = Some(d);
                m
            }
        };
        let message = message.trim_end().to_string();
        let task = match self.message(publisher, event, EvtFormatMessageTask.0) {
            Some(t) => t,
            None if task_num > 0 => task_num.to_string(),
            None => String::new(),
        };
        let first_line = message.lines().next().unwrap_or("").trim().to_string();
        let first_line = if no_template && !first_line.is_empty() { format!("{}  (no message template)", first_line) } else if no_template { "(no message template)".to_string() } else { first_line };
        let service = if source == "Service Control Manager" && SCM_SERVICE_EVENTS.contains(&id) {
            let d = match data {
                Some(d) => d,
                None => self.data_strings(event),
            };
            d.first().cloned().filter(|s| !s.is_empty())
        } else {
            None
        };
        Some(EventRow { time_ms, log, level, source, id, task, computer, user, first_line, message, record_id, pid, service })
    }
}

#[derive(Clone)]
enum Var {
    Null,
    Str(String),
    U64(u64),
    Time(u64),
    Sid(usize),
}

fn variants(buf: &[u8], count: u32) -> Vec<Var> {
    let size = std::mem::size_of::<EVT_VARIANT>();
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        if (i + 1) * size > buf.len() {
            break;
        }
        let v: EVT_VARIANT = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(i * size) as *const EVT_VARIANT) };
        let ty = v.Type & 0x7F;
        let is_array = v.Type & 0x80 != 0;
        let var = unsafe {
            if ty == EvtVarTypeNull.0 as u32 {
                Var::Null
            } else if ty == EvtVarTypeString.0 as u32 {
                if is_array {
                    let ptr = v.Anonymous.StringArr;
                    let mut list = Vec::new();
                    for k in 0..v.Count as usize {
                        let p = *ptr.add(k);
                        if !p.is_null() {
                            list.push(p.to_string().unwrap_or_default());
                        }
                    }
                    Var::Str(list.join(" "))
                } else if v.Anonymous.StringVal.is_null() {
                    Var::Str(String::new())
                } else {
                    Var::Str(v.Anonymous.StringVal.to_string().unwrap_or_default())
                }
            } else if ty == EvtVarTypeUInt16.0 as u32 {
                Var::U64(v.Anonymous.UInt16Val as u64)
            } else if ty == EvtVarTypeUInt32.0 as u32 || ty == EvtVarTypeHexInt32.0 as u32 {
                Var::U64(v.Anonymous.UInt32Val as u64)
            } else if ty == EvtVarTypeInt32.0 as u32 {
                Var::U64(v.Anonymous.Int32Val.max(0) as u64)
            } else if ty == EvtVarTypeUInt64.0 as u32 || ty == EvtVarTypeHexInt64.0 as u32 {
                Var::U64(v.Anonymous.UInt64Val)
            } else if ty == EvtVarTypeByte.0 as u32 {
                Var::U64(v.Anonymous.ByteVal as u64)
            } else if ty == EvtVarTypeFileTime.0 as u32 {
                Var::Time(v.Anonymous.FileTimeVal)
            } else if ty == EvtVarTypeSid.0 as u32 {
                Var::Sid(v.Anonymous.SidVal.0 as usize)
            } else {
                Var::Null
            }
        };
        out.push(var);
    }
    out
}

pub fn query(channel: &str, window_ms: i64, levels: Levels, cap: usize) -> Result<QueryResult, String> {
    let mut fmt = Formatter::new()?;
    let (mut rows, capped) = query_with(&mut fmt, channel, &window_xpath(window_ms, levels), cap)?;
    rows.sort_by(|a, b| b.time_ms.cmp(&a.time_ms).then(b.record_id.cmp(&a.record_id)));
    Ok(QueryResult { rows, capped })
}

pub fn query_ids(channel: &str, window_ms: i64, wanted: &[(&str, u32)]) -> Result<Vec<EventRow>, String> {
    let mut fmt = Formatter::new()?;
    let clauses: Vec<String> = wanted.iter().map(|(p, id)| format!("(Provider[@Name='{}'] and EventID={})", p.replace('\'', "&apos;"), id)).collect();
    let xpath = format!("*[System[TimeCreated[timediff(@SystemTime) <= {}] and ({})]]", window_ms, clauses.join(" or "));
    let (mut rows, _) = query_with(&mut fmt, channel, &xpath, MAX_PER_CHANNEL)?;
    rows.sort_by(|a, b| b.time_ms.cmp(&a.time_ms));
    Ok(rows)
}

fn query_with(fmt: &mut Formatter, channel: &str, xpath: &str, cap: usize) -> Result<(Vec<EventRow>, bool), String> {
    let path = wide(channel);
    let q = wide(xpath);
    let handle = unsafe { EvtQuery(None, PCWSTR(path.as_ptr()), PCWSTR(q.as_ptr()), EvtQueryChannelPath.0 | EvtQueryReverseDirection.0) }.map_err(|e| err(&format!("{} log", channel), e))?;
    let handle = Handle(handle);
    let mut rows = Vec::new();
    let mut capped = false;
    let mut batch = vec![0isize; BATCH];
    loop {
        let mut returned = 0u32;
        let r = unsafe { EvtNext(handle.0, &mut batch, 5000, 0, &mut returned) };
        if let Err(e) = r {
            if e.code() == ERROR_NO_MORE_ITEMS.to_hresult() || returned == 0 {
                break;
            }
            return Err(err(&format!("{} log", channel), e));
        }
        for &h in batch.iter().take(returned as usize) {
            let ev = Handle(EVT_HANDLE(h));
            if rows.len() >= cap {
                capped = true;
                continue;
            }
            if let Some(row) = fmt.row(ev.0, channel) {
                rows.push(row);
            }
        }
        if capped || (returned as usize) < BATCH {
            break;
        }
    }
    Ok((rows, capped))
}

fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    let _ = unsafe { EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut count) };
    if used == 0 {
        return None;
    }
    let mut buf = vec![0u16; (used as usize / 2) + 2];
    unsafe { EvtRender(None, event, EvtRenderEventXml.0, (buf.len() * 2) as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut count) }.ok()?;
    Some(from_wide(&buf))
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&#13;", "").replace("&#10;", "\n").replace("&amp;", "&")
}

pub fn data_elements(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Data") {
        let after = &rest[i + 5..];
        if !after.starts_with(' ') && !after.starts_with('>') && !after.starts_with('/') {
            rest = after;
            continue;
        }
        let Some(close) = after.find('>') else { break };
        let tag = &after[..close];
        if tag.ends_with('/') {
            out.push(String::new());
            rest = &after[close + 1..];
            continue;
        }
        let body = &after[close + 1..];
        let Some(end) = body.find("</Data>") else { break };
        out.push(unescape_xml(body[..end].trim()));
        rest = &body[end + 7..];
    }
    out
}

pub fn xml(channel: &str, record_id: u64) -> Result<String, String> {
    let path = wide(channel);
    let q = wide(&format!("*[System[EventRecordID={}]]", record_id));
    let handle = Handle(unsafe { EvtQuery(None, PCWSTR(path.as_ptr()), PCWSTR(q.as_ptr()), EvtQueryChannelPath.0) }.map_err(|e| err(&format!("{} log", channel), e))?);
    let mut batch = [0isize; 1];
    let mut returned = 0u32;
    unsafe { EvtNext(handle.0, &mut batch, 5000, 0, &mut returned) }.map_err(|_| "the event is no longer in the log".to_string())?;
    if returned == 0 {
        return Err("the event is no longer in the log".into());
    }
    let ev = Handle(EVT_HANDLE(batch[0]));
    render_xml(ev.0).ok_or_else(|| "could not render the event".to_string())
}

pub fn export(channel: &str, window_ms: i64, information: bool, target: &Path) -> Result<(), String> {
    let path = wide(channel);
    let levels = if information { Levels::All } else if channel.eq_ignore_ascii_case("Security") { Levels::AuditFailures } else { Levels::Errors };
    let q = wide(&window_xpath(window_ms, levels));
    let file = wide(&target.to_string_lossy());
    if target.exists() {
        std::fs::remove_file(target).map_err(|e| format!("could not replace {}: {}", target.display(), e))?;
    }
    unsafe { EvtExportLog(None, PCWSTR(path.as_ptr()), PCWSTR(q.as_ptr()), PCWSTR(file.as_ptr()), EvtExportLogChannelPath.0) }.map_err(|e| err("export failed", e))
}

#[derive(Default)]
pub struct TailBuffer {
    pub rows: VecDeque<EventRow>,
    pub seq: u64,
    pub dropped: u64,
    pub errors: Vec<(String, String)>,
}

const TAIL_CAP: usize = 20_000;

struct TailContext {
    channel: String,
    fmt: Mutex<Formatter>,
    buffer: Arc<Mutex<TailBuffer>>,
}

pub struct Tail {
    handles: Vec<EVT_HANDLE>,
    contexts: Vec<Box<TailContext>>,
    pub channels: Vec<String>,
    pub buffer: Arc<Mutex<TailBuffer>>,
}

unsafe impl Send for Tail {}

unsafe extern "system" fn on_event(action: EVT_SUBSCRIBE_NOTIFY_ACTION, context: *const std::ffi::c_void, event: EVT_HANDLE) -> u32 {
    if context.is_null() {
        return 0;
    }
    let ctx = unsafe { &*(context as *const TailContext) };
    if action != EvtSubscribeActionDeliver {
        let code = event.0 as u32;
        let mut b = ctx.buffer.lock();
        if !b.errors.iter().any(|(c, _)| *c == ctx.channel) {
            b.errors.push((ctx.channel.clone(), format!("subscription error {}", code)));
        }
        return 0;
    }
    let row = ctx.fmt.lock().row(event, &ctx.channel);
    if let Some(row) = row {
        let mut b = ctx.buffer.lock();
        b.rows.push_back(row);
        b.seq += 1;
        while b.rows.len() > TAIL_CAP {
            b.rows.pop_front();
            b.dropped += 1;
        }
    }
    0
}

impl Tail {
    pub fn start(channels: &[&str]) -> Tail {
        let buffer = Arc::new(Mutex::new(TailBuffer::default()));
        let mut handles = Vec::new();
        let mut contexts = Vec::new();
        for ch in channels {
            let fmt = match Formatter::new() {
                Ok(f) => f,
                Err(e) => {
                    buffer.lock().errors.push((ch.to_string(), e));
                    continue;
                }
            };
            let ctx = Box::new(TailContext { channel: ch.to_string(), fmt: Mutex::new(fmt), buffer: buffer.clone() });
            let path = wide(ch);
            let q = wide(if ch.eq_ignore_ascii_case("Security") { "*[System[band(Keywords,4503599627370496)]]" } else { "*[System[Level>=0]]" });
            let ptr = &*ctx as *const TailContext as *const std::ffi::c_void;
            match unsafe { EvtSubscribe(None, None, PCWSTR(path.as_ptr()), PCWSTR(q.as_ptr()), None, Some(ptr), Some(on_event), EvtSubscribeToFutureEvents.0) } {
                Ok(h) => {
                    handles.push(h);
                    contexts.push(ctx);
                }
                Err(e) => buffer.lock().errors.push((ch.to_string(), err("live tail", e))),
            }
        }
        Tail { handles, contexts, channels: channels.iter().map(|c| c.to_string()).collect(), buffer }
    }

    pub fn since(&self, seq: u64) -> (Vec<EventRow>, u64, u64) {
        let b = self.buffer.lock();
        let n = b.seq.saturating_sub(seq).min(b.rows.len() as u64) as usize;
        let rows: Vec<EventRow> = b.rows.iter().rev().take(n).cloned().collect();
        (rows, b.seq, b.dropped)
    }

    pub fn errors(&self) -> Vec<(String, String)> {
        self.buffer.lock().errors.clone()
    }
}

static RETIRED: Mutex<Vec<(Instant, Vec<Box<TailContext>>)>> = Mutex::new(Vec::new());

impl Drop for Tail {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            unsafe {
                let _ = EvtClose(h);
            }
        }
        let mut retired = RETIRED.lock();
        retired.retain(|(at, _)| at.elapsed() < Duration::from_secs(30));
        retired.push((Instant::now(), std::mem::take(&mut self.contexts)));
    }
}
