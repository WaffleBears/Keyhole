use super::shares::{enum_all, enum_once, net_error};
use super::{pw, wide};
use windows::Win32::NetworkManagement::NetManagement::{FILTER_NORMAL_ACCOUNT, LOCALGROUP_MEMBERS_INFO_3, NetLocalGroupAddMembers, USER_INFO_1003, GROUP_USERS_INFO_0, LG_INCLUDE_INDIRECT, LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0, LOCALGROUP_MEMBERS_INFO_2, LOCALGROUP_USERS_INFO_0, NETSETUP_JOIN_STATUS, NetApiBufferFree, NetGetJoinInformation, NetGroupGetUsers, NetLocalGroupDelMembers, NetLocalGroupEnum, NetLocalGroupGetMembers, NetSetupDomainName, NetUserEnum, NetUserGetInfo, NetUserGetLocalGroups, NetUserSetInfo, UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_LOCKOUT, UF_PASSWD_CANT_CHANGE, UF_PASSWD_NOTREQD, USER_INFO_0, USER_INFO_1008, USER_INFO_4};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{PSID, SID_NAME_USE, SidTypeAlias, SidTypeDeletedAccount, SidTypeDomain, SidTypeGroup, SidTypeUser, SidTypeWellKnownGroup};
use windows::core::{PCWSTR, PWSTR};

#[derive(Clone, Debug, Default)]
pub struct UserRow {
    pub name: String,
    pub full_name: String,
    pub comment: String,
    pub sid: String,
    pub enabled: bool,
    pub locked: bool,
    pub password_never_expires: bool,
    pub password_required: bool,
    pub cannot_change_password: bool,
    pub password_age_days: u32,
    pub last_logon_ms: i64,
    pub logon_count: u32,
    pub admin: bool,
    pub groups: Vec<String>,
    pub profile_path: String,
    pub domain: bool,
}

#[derive(Clone, Debug, Default)]
pub struct GroupRow {
    pub name: String,
    pub comment: String,
    pub sid: String,
    pub members: usize,
}

#[derive(Clone, Debug, Default)]
pub struct MemberRow {
    pub group: String,
    pub member: String,
    pub kind: String,
    pub sid: String,
    pub local: bool,
    pub via: String,
}

#[derive(Clone, Debug, Default)]
pub struct AccountsData {
    pub users: Vec<UserRow>,
    pub groups: Vec<GroupRow>,
    pub members: Vec<MemberRow>,
    pub error: Option<String>,
    pub domain: Option<String>,
    pub machine_sid: String,
    pub notes: Vec<String>,
}

fn sid_text(sid: PSID) -> String {
    if sid.is_invalid() { String::new() } else { super::privilege::sid_text(sid) }
}

fn user_details(name: &str) -> Option<UserRow> {
    let w = wide(name);
    let mut buf: *mut u8 = std::ptr::null_mut();
    let rc = unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(w.as_ptr()), 4, &mut buf) };
    if rc != 0 || buf.is_null() {
        return None;
    }
    let u = unsafe { std::ptr::read(buf as *const USER_INFO_4) };
    let flags = u.usri4_flags.0;
    let row = UserRow {
        name: pw(u.usri4_name),
        full_name: pw(u.usri4_full_name),
        comment: pw(u.usri4_comment),
        sid: sid_text(u.usri4_user_sid),
        enabled: flags & UF_ACCOUNTDISABLE.0 == 0,
        locked: flags & UF_LOCKOUT.0 != 0,
        password_never_expires: flags & UF_DONT_EXPIRE_PASSWD.0 != 0,
        password_required: flags & UF_PASSWD_NOTREQD.0 == 0,
        cannot_change_password: flags & UF_PASSWD_CANT_CHANGE.0 != 0,
        password_age_days: u.usri4_password_age / 86_400,
        last_logon_ms: if u.usri4_last_logon > 0 { u.usri4_last_logon as i64 * 1000 } else { 0 },
        logon_count: u.usri4_num_logons,
        admin: false,
        groups: Vec::new(),
        profile_path: pw(u.usri4_profile),
        domain: false,
    };
    unsafe {
        NetApiBufferFree(Some(buf as *const _));
    }
    Some(row)
}

pub fn domain_name() -> Option<String> {
    let mut name = PWSTR::null();
    let mut status = NETSETUP_JOIN_STATUS::default();
    let rc = unsafe { NetGetJoinInformation(PCWSTR::null(), &mut name, &mut status) };
    if rc != 0 {
        return None;
    }
    let text = pw(name);
    unsafe {
        NetApiBufferFree(Some(name.0 as *const _));
    }
    if status == NetSetupDomainName && !text.is_empty() { Some(text) } else { None }
}

pub fn domain_controller(domain: &str) -> Option<String> {
    use windows::Win32::Networking::ActiveDirectory::{DOMAIN_CONTROLLER_INFOW, DS_RETURN_DNS_NAME, DsGetDcNameW};
    let d = wide(domain);
    let mut info: *mut DOMAIN_CONTROLLER_INFOW = std::ptr::null_mut();
    let rc = unsafe { DsGetDcNameW(PCWSTR::null(), PCWSTR(d.as_ptr()), None, PCWSTR::null(), DS_RETURN_DNS_NAME, &mut info) };
    if rc != 0 || info.is_null() {
        return None;
    }
    let name = pw(unsafe { (*info).DomainControllerName });
    unsafe {
        NetApiBufferFree(Some(info as *const _));
    }
    Some(name)
}

pub fn machine_sid() -> String {
    let computer = computer_name();
    let Some(found) = lookup_sid(&computer) else { return String::new() };
    if found.kind == SidTypeDomain {
        return found.sid;
    }
    found.sid.rsplit_once('-').map(|(prefix, _)| prefix.to_string()).unwrap_or_default()
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

fn builtin_group_name(sid: &str, fallback: &str) -> String {
    name_of_sid_text(sid).map(|n| n.rsplit('\\').next().unwrap_or(&n).to_string()).unwrap_or_else(|| fallback.to_string())
}

pub fn administrators_group() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| builtin_group_name("S-1-5-32-544", "Administrators"))
}

pub fn remote_desktop_group() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| builtin_group_name("S-1-5-32-555", "Remote Desktop Users"))
}

pub fn canonical_account(name: &str) -> String {
    let t = name.trim();
    if let Some(rest) = t.strip_prefix(".\\") {
        return format!("{}\\{}", computer_name(), rest.trim());
    }
    if let Some(rest) = t.strip_prefix("\\\\")
        && let Some((_, user)) = rest.split_once('\\') {
            return user.trim().to_string();
        }
    t.to_string()
}

pub fn is_local_prefix(prefix: &str) -> bool {
    let p = prefix.trim();
    p.is_empty() || p == "." || p.eq_ignore_ascii_case(&computer_name()) || p.eq_ignore_ascii_case("BUILTIN") || p.eq_ignore_ascii_case("NT AUTHORITY") || p.eq_ignore_ascii_case("NT SERVICE") || p.eq_ignore_ascii_case("Window Manager") || p.eq_ignore_ascii_case("Font Driver Host") || p.eq_ignore_ascii_case("IIS APPPOOL")
}

pub fn name_of_sid_text(sid_text: &str) -> Option<String> {
    use windows::Win32::Security::LookupAccountSidW;
    let w = wide(sid_text);
    let mut sid = PSID::default();
    unsafe { ConvertStringSidToSidW(PCWSTR(w.as_ptr()), &mut sid) }.ok()?;
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    let ok = unsafe { LookupAccountSidW(PCWSTR::null(), sid, Some(PWSTR(name.as_mut_ptr())), &mut name_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) }.is_ok();
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(sid.0)));
    }
    if !ok {
        return None;
    }
    let d = String::from_utf16_lossy(&domain[..domain_len as usize]);
    let n = String::from_utf16_lossy(&name[..name_len as usize]);
    Some(if d.is_empty() { n } else { format!("{}\\{}", d, n) })
}

pub struct FoundAccount {
    pub sid: String,
    pub kind: SID_NAME_USE,
    pub domain: String,
}

pub fn lookup_sid(name: &str) -> Option<FoundAccount> {
    use windows::Win32::Security::LookupAccountNameW;
    let w = wide(name);
    let mut sid = vec![0u8; 256];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    let ok = unsafe { LookupAccountNameW(PCWSTR::null(), PCWSTR(w.as_ptr()), Some(PSID(sid.as_mut_ptr() as *mut _)), &mut sid_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) }.is_ok();
    if !ok {
        return None;
    }
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Some(FoundAccount { sid: sid_text(PSID(sid.as_mut_ptr() as *mut _)), kind, domain })
}

pub fn is_domain_sid(sid: &str, machine_sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") && (machine_sid.is_empty() || !sid.starts_with(&format!("{}-", machine_sid)))
}

pub fn list() -> AccountsData {
    let mut data = AccountsData::default();
    let computer = computer_name().to_lowercase();
    data.machine_sid = machine_sid();
    data.domain = domain_name();
    let mut resume = 0u32;
    let users = enum_all(|buf, read, total| unsafe { NetUserEnum(PCWSTR::null(), 0, FILTER_NORMAL_ACCOUNT, buf, u32::MAX, read, total, Some(&mut resume)) }, |u: &USER_INFO_0| pw(u.usri0_name));
    match users {
        Ok(list) => {
            for name in list {
                match user_details(&name) {
                    Some(row) => data.users.push(row),
                    None => data.users.push(UserRow { name, enabled: true, password_required: true, ..Default::default() }),
                }
            }
        }
        Err(code) => {
            data.error = Some(net_error(code));
            return data;
        }
    }
    let mut resume_g = 0usize;
    let groups = enum_all(|buf, read, total| unsafe { NetLocalGroupEnum(PCWSTR::null(), 1, buf, u32::MAX, read, total, Some(&mut resume_g)) }, |g: &LOCALGROUP_INFO_1| (pw(g.lgrpi1_name), pw(g.lgrpi1_comment)));
    match groups {
        Ok(list) => {
            for (name, comment) in list {
                let mut resume_m = 0usize;
                let wname = wide(&name);
                let members = enum_all(|buf, read, total| unsafe { NetLocalGroupGetMembers(PCWSTR::null(), PCWSTR(wname.as_ptr()), 2, buf, u32::MAX, read, total, Some(&mut resume_m)) }, |m: &LOCALGROUP_MEMBERS_INFO_2| (pw(m.lgrmi2_domainandname), m.lgrmi2_sidusage, sid_text(m.lgrmi2_sid)));
                let mut count = 0usize;
                if let Ok(ms) = members {
                    for (member, usage, sid) in ms {
                        let kind = match usage {
                            x if x == SidTypeUser => "User",
                            x if x == SidTypeGroup => "Group",
                            x if x == SidTypeAlias => "Local group",
                            x if x == SidTypeWellKnownGroup => "Well-known",
                            x if x == SidTypeDeletedAccount => "Deleted",
                            _ => "Unknown",
                        };
                        let domain = member.split('\\').next().unwrap_or("").to_lowercase();
                        let local = !is_domain_sid(&sid, &data.machine_sid) || domain == computer;
                        data.members.push(MemberRow { group: name.clone(), member, kind: kind.into(), sid, local, via: String::new() });
                        count += 1;
                    }
                }
                let group_sid = lookup_group_sid(&name);
                data.groups.push(GroupRow { name, comment, sid: group_sid, members: count });
            }
        }
        Err(code) => data.error = Some(format!("groups: {}", net_error(code))),
    }
    for u in &mut data.users {
        let mine: Vec<String> = data.members.iter().filter(|m| m.local && m.member.split('\\').next_back().map(|n| n.eq_ignore_ascii_case(&u.name)).unwrap_or(false)).map(|m| m.group.clone()).collect();
        u.admin = mine.iter().any(|g| g.eq_ignore_ascii_case(administrators_group()));
        u.groups = mine;
    }
    data.users.sort_by_key(|a| a.name.to_lowercase());
    data.groups.sort_by_key(|a| a.name.to_lowercase());
    data
}

pub fn expand_group(dc: &str, group: &str) -> Result<Vec<(String, String, String)>, String> {
    let short = group.rsplit('\\').next().unwrap_or(group).to_string();
    let server = wide(&if dc.starts_with("\\\\") { dc.to_string() } else { format!("\\\\{}", dc) });
    let g = wide(&short);
    let mut resume = 0usize;
    let global = enum_all(|buf, read, total| unsafe { NetGroupGetUsers(PCWSTR(server.as_ptr()), PCWSTR(g.as_ptr()), 0, buf, u32::MAX, read, total, Some(&mut resume)) }, |u: &GROUP_USERS_INFO_0| pw(u.grui0_name));
    let domain_prefix = group.split('\\').next().filter(|_| group.contains('\\')).map(|d| format!("{}\\", d)).unwrap_or_default();
    match global {
        Ok(names) => Ok(names.into_iter().map(|n| (format!("{}{}", domain_prefix, n), "User".to_string(), String::new())).collect()),
        Err(2220) | Err(2221) => {
            let mut resume_m = 0usize;
            let members = enum_all(|buf, read, total| unsafe { NetLocalGroupGetMembers(PCWSTR(server.as_ptr()), PCWSTR(g.as_ptr()), 2, buf, u32::MAX, read, total, Some(&mut resume_m)) }, |m: &LOCALGROUP_MEMBERS_INFO_2| {
                let kind = if m.lgrmi2_sidusage == SidTypeUser { "User" } else if m.lgrmi2_sidusage == SidTypeGroup || m.lgrmi2_sidusage == SidTypeAlias { "Group" } else { "Well-known" };
                (pw(m.lgrmi2_domainandname), kind.to_string(), sid_text(m.lgrmi2_sid))
            });
            members.map_err(net_error)
        }
        Err(code) => Err(net_error(code)),
    }
}

pub fn expand_domain_groups(members: &[MemberRow], only_groups: &[&str], machine_sid: &str) -> (Vec<MemberRow>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let Some(domain) = domain_name() else { return (out, notes) };
    let Some(home_dc) = domain_controller(&domain) else {
        notes.push(format!("no domain controller for {} is reachable, so domain groups are not expanded", domain));
        return (out, notes);
    };
    let mut dcs: Vec<(String, Option<String>)> = vec![(domain.to_lowercase(), Some(home_dc.clone()))];
    let mut dc_for = |member: &str| -> Option<String> {
        let prefix = member.split('\\').next().filter(|_| member.contains('\\')).unwrap_or("").to_lowercase();
        if prefix.is_empty() || prefix == domain.to_lowercase() || domain.to_lowercase().starts_with(&format!("{}.", prefix)) {
            return Some(home_dc.clone());
        }
        if let Some((_, dc)) = dcs.iter().find(|(d, _)| *d == prefix) {
            return dc.clone();
        }
        let dc = domain_controller(&prefix);
        dcs.push((prefix, dc.clone()));
        dc
    };
    let mut queue: Vec<(MemberRow, usize)> = members.iter().filter(|m| only_groups.iter().any(|g| m.group.eq_ignore_ascii_case(g)) && !m.local && m.kind == "Group").map(|m| (m.clone(), 1)).collect();
    let mut seen: Vec<String> = Vec::new();
    while let Some((m, depth)) = queue.pop() {
        if depth > 3 || seen.contains(&m.member) || out.len() > 2000 {
            continue;
        }
        seen.push(m.member.clone());
        let Some(dc) = dc_for(&m.member) else {
            notes.push(format!("{}: no domain controller for its domain is reachable", m.member));
            continue;
        };
        match expand_group(&dc, &m.member) {
            Ok(list) => {
                for (name, kind, sid) in list {
                    let via = if m.via.is_empty() { m.member.clone() } else { format!("{} ← {}", m.via, m.member) };
                    let row = MemberRow { group: m.group.clone(), member: name, kind: kind.clone(), sid: sid.clone(), local: !is_domain_sid(&sid, machine_sid) && !sid.is_empty(), via };
                    if kind == "Group" {
                        queue.push((row.clone(), depth + 1));
                    }
                    out.push(row);
                }
            }
            Err(e) => notes.push(format!("{}: {}", m.member, e)),
        }
    }
    (out, notes)
}

pub fn lookup_account(name: &str) -> Result<UserRow, String> {
    let typed = canonical_account(name);
    if typed.is_empty() {
        return Err("type an account name".into());
    }
    let Some(found) = lookup_sid(&typed) else {
        return Err(if is_domain_joined() { format!("{} is not a known account here or in the domain. Use DOMAIN\\name and make sure a domain controller is reachable", typed) } else { format!("{} is not a local account, and this machine is not domain joined", typed) });
    };
    if found.kind != SidTypeUser {
        return Err(format!("{} is {}, not a user account. For a group use Expand domain group on its row", typed, match found.kind { k if k == SidTypeGroup => "a domain group", k if k == SidTypeAlias => "a local group", k if k == SidTypeDomain => "a domain", k if k == SidTypeWellKnownGroup => "a well-known group", _ => "not a user" }));
    }
    let short = typed.rsplit('\\').next().unwrap_or(&typed).split('@').next().unwrap_or(&typed).to_string();
    let local = !is_domain_sid(&found.sid, &machine_sid());
    let full = if found.domain.is_empty() { short.clone() } else { format!("{}\\{}", found.domain, short) };
    let query = if local { short.clone() } else { full.clone() };
    let mut row = UserRow { name: if local { short.clone() } else { full.clone() }, sid: found.sid.clone(), enabled: true, password_required: true, domain: !local, ..Default::default() };
    let w = wide(&query);
    let groups = enum_once(|buf, read, total| unsafe { NetUserGetLocalGroups(PCWSTR::null(), PCWSTR(w.as_ptr()), 0, LG_INCLUDE_INDIRECT, buf, u32::MAX, read, total) }, |g: &LOCALGROUP_USERS_INFO_0| pw(g.lgrui0_name));
    match groups {
        Ok(list) => {
            row.admin = list.iter().any(|g| g.eq_ignore_ascii_case(administrators_group()));
            row.groups = list;
        }
        Err(code) => return Err(net_error(code)),
    }
    if local {
        if let Some(details) = user_details(&short) {
            row = UserRow { admin: row.admin, groups: row.groups, ..details };
        }
        return Ok(row);
    }
    if let Some(domain) = domain_name() {
        let account_domain = if found.domain.is_empty() { domain.clone() } else { found.domain.clone() };
        if let Some(dc) = domain_controller(&account_domain).or_else(|| domain_controller(&domain)) {
            let server = wide(&dc);
            let short = wide(&short);
            let mut buf: *mut u8 = std::ptr::null_mut();
            let rc = unsafe { NetUserGetInfo(PCWSTR(server.as_ptr()), PCWSTR(short.as_ptr()), 4, &mut buf) };
            if rc == 0 && !buf.is_null() {
                let u = unsafe { &*(buf as *const USER_INFO_4) };
                let flags = u.usri4_flags.0;
                row.full_name = pw(u.usri4_full_name);
                row.comment = pw(u.usri4_comment);
                row.enabled = flags & UF_ACCOUNTDISABLE.0 == 0;
                row.locked = flags & UF_LOCKOUT.0 != 0;
                row.password_never_expires = flags & UF_DONT_EXPIRE_PASSWD.0 != 0;
                row.password_age_days = u.usri4_password_age / 86_400;
                row.last_logon_ms = if u.usri4_last_logon > 0 { u.usri4_last_logon as i64 * 1000 } else { 0 };
                row.logon_count = u.usri4_num_logons;
                unsafe {
                    NetApiBufferFree(Some(buf as *const _));
                }
            }
        }
    }
    Ok(row)
}

fn lookup_group_sid(name: &str) -> String {
    lookup_sid(name).map(|f| f.sid).unwrap_or_default()
}

fn set_flags(name: &str, change: impl Fn(u32) -> u32) -> Result<(), String> {
    let w = wide(name);
    let mut buf: *mut u8 = std::ptr::null_mut();
    let rc = unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(w.as_ptr()), 4, &mut buf) };
    if rc != 0 || buf.is_null() {
        return Err(net_error(rc));
    }
    let flags = unsafe { (*(buf as *const USER_INFO_4)).usri4_flags.0 };
    unsafe {
        NetApiBufferFree(Some(buf as *const _));
    }
    let info = USER_INFO_1008 { usri1008_flags: windows::Win32::NetworkManagement::NetManagement::USER_ACCOUNT_FLAGS(change(flags)) };
    let rc = unsafe { NetUserSetInfo(PCWSTR::null(), PCWSTR(w.as_ptr()), 1008, &info as *const _ as *const u8, None) };
    if rc == 0 { Ok(()) } else { Err(net_error(rc)) }
}

pub fn set_enabled(name: &str, enabled: bool) -> Result<(), String> {
    set_flags(name, |f| if enabled { f & !UF_ACCOUNTDISABLE.0 } else { f | UF_ACCOUNTDISABLE.0 })
}

pub fn unlock(name: &str) -> Result<(), String> {
    set_flags(name, |f| f & !UF_LOCKOUT.0)
}

pub fn add_member(group: &str, account: &str) -> Result<(), String> {
    let g = wide(group);
    let account = canonical_account(account);
    let account = account.as_str();
    if account.is_empty() {
        return Err("type an account name".into());
    }
    let mut a = wide(account);
    let entry = LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname: PWSTR(a.as_mut_ptr()) };
    let mut rc = unsafe { NetLocalGroupAddMembers(PCWSTR::null(), PCWSTR(g.as_ptr()), 3, &entry as *const _ as *const u8, 1) };
    if rc == 1387 {
        let sid_text = lookup_group_sid(account);
        if !sid_text.is_empty() {
            let s = wide(&sid_text);
            let mut sid = PSID::default();
            if unsafe { ConvertStringSidToSidW(PCWSTR(s.as_ptr()), &mut sid) }.is_ok() {
                let by_sid = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: sid };
                rc = unsafe { NetLocalGroupAddMembers(PCWSTR::null(), PCWSTR(g.as_ptr()), 0, &by_sid as *const _ as *const u8, 1) };
                unsafe {
                    let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(sid.0)));
                }
            }
        }
    }
    match rc {
        0 => Ok(()),
        1387 => Err(if is_domain_joined() { format!("{} is not an account Windows can find. For domain accounts use DOMAIN\\name and make sure a domain controller is reachable", account) } else { format!("{} is not a local account, and this machine is not domain joined", account) }),
        1378 => Err(format!("{} is already a member of {}", account, group)),
        other => Err(net_error(other)),
    }
}

pub fn is_domain_joined() -> bool {
    domain_name().is_some()
}

pub fn set_password(user: &str, password: &str) -> Result<(), String> {
    let u = wide(user);
    let mut p = super::SecretWide::new(password);
    let info = USER_INFO_1003 { usri1003_password: PWSTR(p.0.as_mut_ptr()) };
    let rc = unsafe { NetUserSetInfo(PCWSTR::null(), PCWSTR(u.as_ptr()), 1003, &info as *const _ as *const u8, None) };
    drop(p);
    match rc {
        0 => Ok(()),
        2245 => Err("the password does not meet the policy (length, complexity or history)".into()),
        2221 => Err("no such local user".into()),
        other => Err(net_error(other)),
    }
}

pub fn remove_member(group: &str, member_sid: &str) -> Result<(), String> {
    let g = wide(group);
    let s = wide(member_sid);
    let mut sid = PSID::default();
    unsafe { ConvertStringSidToSidW(PCWSTR(s.as_ptr()), &mut sid) }.map_err(|_| "the member's SID could not be parsed".to_string())?;
    let entry = LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: sid };
    let rc = unsafe { NetLocalGroupDelMembers(PCWSTR::null(), PCWSTR(g.as_ptr()), 0, &entry as *const _ as *const u8, 1) };
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(sid.0)));
    }
    if rc == 0 { Ok(()) } else { Err(net_error(rc)) }
}
