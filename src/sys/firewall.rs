use crate::sys::com::ComGuard;
use crate::sys::winerr;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VariantClear};
use windows::Win32::UI::Shell::SHLoadIndirectString;
use windows::core::{BSTR, Interface, PCWSTR};

#[derive(Clone, serde::Serialize)]
pub struct FirewallRow {
    pub name: String,
    pub display: String,
    pub description: String,
    pub group: String,
    pub direction: String,
    pub action: String,
    pub enabled: bool,
    pub protocol: String,
    pub local_ports: String,
    pub remote_ports: String,
    pub remote_addresses: String,
    pub program: String,
    pub service: String,
    pub profiles: String,
    pub keyhole: bool,
}

pub fn proto_name(p: i32) -> String {
    match p {
        6 => "TCP".into(),
        17 => "UDP".into(),
        1 => "ICMPv4".into(),
        58 => "ICMPv6".into(),
        256 => "Any".into(),
        other => other.to_string(),
    }
}

pub fn profiles_text(mask: i32) -> String {
    if mask == 0x7fffffff || mask == 0 {
        return "All".into();
    }
    let mut v = Vec::new();
    if mask & 1 != 0 { v.push("Domain"); }
    if mask & 2 != 0 { v.push("Private"); }
    if mask & 4 != 0 { v.push("Public"); }
    if v.is_empty() { "All".into() } else { v.join(", ") }
}

#[derive(Clone, Debug, Default)]
pub struct RuleKey {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub local_ports: String,
    pub remote_ports: String,
    pub remote_addresses: String,
    pub program: String,
    pub profiles: String,
}

impl RuleKey {
    fn matches(&self, r: &FirewallRow) -> bool {
        r.name == self.name
            && r.direction == self.direction
            && r.action == self.action
            && r.protocol == self.protocol
            && r.local_ports == self.local_ports
            && r.remote_ports == self.remote_ports
            && r.remote_addresses == self.remote_addresses
            && r.program.eq_ignore_ascii_case(&self.program)
            && r.profiles == self.profiles
    }
}

fn com_err(what: &str, e: &windows::core::Error) -> String {
    format!("{}: {}", what, winerr::describe(e))
}

struct Policy {
    rules: INetFwRules,
    _com: ComGuard,
}

fn open_policy() -> Result<Policy, String> {
    let com = ComGuard::mta();
    unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("the Windows Firewall service is not available ({})", winerr::describe(&e)))?;
        let rules = policy.Rules().map_err(|e| com_err("rules", &e))?;
        Ok(Policy { rules, _com: com })
    }
}

fn for_each_rule(rules: &INetFwRules, mut f: impl FnMut(INetFwRule) -> Result<bool, String>) -> Result<(), String> {
    unsafe {
        let unknown = rules._NewEnum().map_err(|e| com_err("enum", &e))?;
        let enumerator: IEnumVARIANT = unknown.cast().map_err(|e| com_err("cast", &e))?;
        loop {
            let mut fetched = 0u32;
            let mut var = [VARIANT::default()];
            if enumerator.Next(&mut var, &mut fetched).is_err() || fetched == 0 {
                break;
            }
            let disp = (*var[0].Anonymous.Anonymous).Anonymous.pdispVal.as_ref().cloned();
            let _ = VariantClear(&mut var[0]);
            let Some(rule) = disp.and_then(|d| d.cast::<INetFwRule>().ok()) else {
                continue;
            };
            if !f(rule)? {
                break;
            }
        }
        Ok(())
    }
}

pub fn set_enabled(key: &RuleKey, enabled: bool) -> Result<(), String> {
    let policy = open_policy()?;
    let mut changed = 0usize;
    for_each_rule(&policy.rules, |rule| unsafe {
        if key.matches(&read_rule(&rule)) {
            rule.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(if enabled { -1 } else { 0 }))
                .map_err(|e| com_err("could not change the rule", &e))?;
            changed += 1;
        }
        Ok(true)
    })?;
    if changed == 0 {
        return Err("that rule no longer exists".into());
    }
    Ok(())
}

pub fn delete_rule(key: &RuleKey) -> Result<(), String> {
    let policy = open_policy()?;
    let mut targets: Vec<INetFwRule> = Vec::new();
    let mut siblings = 0usize;
    for_each_rule(&policy.rules, |rule| unsafe {
        let row = read_rule(&rule);
        if row.name == key.name {
            if key.matches(&row) {
                targets.push(rule);
            } else {
                siblings += 1;
            }
        }
        Ok(true)
    })?;
    if targets.is_empty() {
        return Err("that rule no longer exists".into());
    }
    unsafe {
        if siblings == 0 {
            for i in 0..targets.len() {
                if let Err(e) = policy.rules.Remove(&BSTR::from(key.name.as_str())) {
                    if i == 0 {
                        return Err(com_err("could not delete rule", &e));
                    }
                    break;
                }
            }
            return Ok(());
        }
        for (i, rule) in targets.iter().enumerate() {
            let temp = format!("{} (keyhole delete {} {})", key.name, std::process::id(), i);
            rule.SetName(&BSTR::from(temp.as_str())).map_err(|e| com_err("could not single out the rule for deletion", &e))?;
            if let Err(e) = policy.rules.Remove(&BSTR::from(temp.as_str())) {
                let _ = rule.SetName(&BSTR::from(key.name.as_str()));
                return Err(com_err("could not delete rule", &e));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct NewRule {
    pub name: String,
    pub description: String,
    pub direction: String,
    pub action: String,
    pub protocol: String,
    pub local_ports: String,
    pub remote_ports: String,
    pub remote_addresses: String,
    pub program: String,
    pub profiles: String,
    pub enabled: bool,
}

pub fn parse_ports(field: &str, text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("any") || text == "*" {
        return Ok(String::new());
    }
    let mut parts = Vec::new();
    for raw in text.split(',') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        let ok = match part.split_once('-') {
            Some((a, b)) => {
                let a = a.trim().parse::<u32>().ok();
                let b = b.trim().parse::<u32>().ok();
                matches!((a, b), (Some(a), Some(b)) if a >= 1 && b <= 65535 && a <= b)
            }
            None => part.parse::<u32>().map(|n| (1..=65535).contains(&n)).unwrap_or(false),
        };
        if !ok {
            return Err(format!("{}: \"{}\" is not a port or range (1-65535)", field, part));
        }
        parts.push(part.replace(' ', ""));
    }
    Ok(parts.join(","))
}

pub fn profile_mask(text: &str) -> Result<i32, String> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("all") {
        return Ok(0x7fffffff);
    }
    let mut mask = 0;
    for part in text.split(',') {
        mask |= match part.trim().to_ascii_lowercase().as_str() {
            "domain" => 1,
            "private" => 2,
            "public" => 4,
            "" => 0,
            other => return Err(format!("unknown profile \"{}\"", other)),
        };
    }
    Ok(if mask == 7 || mask == 0 { 0x7fffffff } else { mask })
}

struct Prepared {
    name: String,
    direction: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIRECTION,
    action: windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION,
    protocol: i32,
    local_ports: String,
    remote_ports: String,
    remote_addresses: String,
    program: String,
    profiles: i32,
    description: String,
}

fn prepare(spec: &NewRule) -> Result<Prepared, String> {
    let name = spec.name.trim();
    if name.is_empty() {
        return Err("the rule needs a name".into());
    }
    if name.contains('|') {
        return Err("rule names cannot contain |".into());
    }
    let direction = match spec.direction.trim().to_ascii_lowercase().as_str() {
        "in" | "inbound" => NET_FW_RULE_DIR_IN,
        "out" | "outbound" => NET_FW_RULE_DIR_OUT,
        _ => return Err("direction must be inbound or outbound".into()),
    };
    let action = match spec.action.trim().to_ascii_lowercase().as_str() {
        "allow" => NET_FW_ACTION_ALLOW,
        "block" => NET_FW_ACTION_BLOCK,
        _ => return Err("action must be allow or block".into()),
    };
    let protocol = match spec.protocol.trim().to_ascii_lowercase().as_str() {
        "" | "any" => 256,
        "tcp" => 6,
        "udp" => 17,
        "icmpv4" | "icmp" => 1,
        "icmpv6" => 58,
        _ => return Err("protocol must be Any, TCP, UDP, ICMPv4 or ICMPv6".into()),
    };
    let local_ports = parse_ports("local ports", &spec.local_ports)?;
    let remote_ports = parse_ports("remote ports", &spec.remote_ports)?;
    if (!local_ports.is_empty() || !remote_ports.is_empty()) && protocol != 6 && protocol != 17 {
        return Err("ports only apply to TCP or UDP rules".into());
    }
    let program = crate::sys::actions::expand_env(spec.program.trim());
    if !program.is_empty() && !program.to_lowercase().ends_with(".exe") {
        return Err("program must be a path to an .exe".into());
    }
    let profiles = profile_mask(&spec.profiles)?;
    let remote_addresses = spec.remote_addresses.trim().replace(' ', "");
    let description = if spec.description.trim().is_empty() {
        "Created by Keyhole".to_string()
    } else {
        spec.description.trim().to_string()
    };
    Ok(Prepared { name: name.to_string(), direction, action, protocol, local_ports, remote_ports, remote_addresses, program, profiles, description })
}

pub fn validate(spec: &NewRule) -> Result<(), String> {
    prepare(spec).map(|_| ())
}

pub fn add_rule(spec: &NewRule) -> Result<(), String> {
    let Prepared { name, direction, action, protocol, local_ports, remote_ports, remote_addresses, program, profiles, description } = prepare(spec)?;
    let policy = open_policy()?;
    unsafe {
        let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| com_err("cannot create rule", &e))?;
        rule.SetName(&BSTR::from(name.as_str())).map_err(|e| com_err("name", &e))?;
        rule.SetDescription(&BSTR::from(description.as_str())).map_err(|e| com_err("description", &e))?;
        if !program.is_empty() {
            rule.SetApplicationName(&BSTR::from(program.as_str())).map_err(|e| com_err("program", &e))?;
        }
        rule.SetProtocol(protocol).map_err(|e| com_err("protocol", &e))?;
        if !local_ports.is_empty() {
            rule.SetLocalPorts(&BSTR::from(local_ports.as_str())).map_err(|e| com_err("local ports", &e))?;
        }
        if !remote_ports.is_empty() {
            rule.SetRemotePorts(&BSTR::from(remote_ports.as_str())).map_err(|e| com_err("remote ports", &e))?;
        }
        if !remote_addresses.is_empty() && !remote_addresses.eq_ignore_ascii_case("any") && remote_addresses != "*" {
            rule.SetRemoteAddresses(&BSTR::from(remote_addresses.as_str())).map_err(|e| {
                if winerr::code_of(&e) == 87 {
                    format!("remote addresses: Windows rejected \"{}\". Use IP addresses, ranges like 10.0.0.1-10.0.0.9 or CIDR blocks, separated by commas", remote_addresses)
                } else {
                    com_err("remote addresses", &e)
                }
            })?;
        }
        rule.SetDirection(direction).map_err(|e| com_err("direction", &e))?;
        rule.SetAction(action).map_err(|e| com_err("action", &e))?;
        rule.SetProfiles(profiles).map_err(|e| com_err("profiles", &e))?;
        rule.SetEnabled(windows::Win32::Foundation::VARIANT_BOOL(if spec.enabled { -1 } else { 0 }))
            .map_err(|e| com_err("enable", &e))?;
        policy.rules.Add(&rule).map_err(|e| com_err("could not add rule", &e))?;
        Ok(())
    }
}

static INDIRECT_CACHE: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashMap<String, String>>> = std::sync::OnceLock::new();

pub fn resolve_indirect(name: &str) -> String {
    if !name.starts_with('@') {
        return name.to_string();
    }
    let cache = INDIRECT_CACHE.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
    if let Some(hit) = cache.lock().get(name) {
        return hit.clone();
    }
    let resolved = resolve_indirect_uncached(name);
    let mut c = cache.lock();
    if c.len() > 20_000 {
        c.clear();
    }
    c.insert(name.to_string(), resolved.clone());
    resolved
}

fn resolve_indirect_uncached(name: &str) -> String {
    let src = crate::sys::wide(name);
    let mut buf = [0u16; 1024];
    let ok = unsafe {
        SHLoadIndirectString(PCWSTR(src.as_ptr()), &mut buf, None).is_ok()
    };
    if !ok {
        return package_label(name);
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
    let s = String::from_utf16_lossy(&buf[..len]);
    if s.is_empty() { package_label(name) } else { s }
}

fn package_label(name: &str) -> String {
    let inner = name.trim_start_matches("@{");
    let pkg = inner.split('?').next().unwrap_or(inner);
    let family = pkg.split('_').next().unwrap_or(pkg);
    if family.is_empty() { name.to_string() } else { format!("{} (app package)", family) }
}

#[derive(Clone, serde::Serialize)]
pub struct ProfileStatus {
    pub name: String,
    pub active: bool,
    pub enabled: bool,
    pub inbound: String,
    pub outbound: String,
    pub block_all_inbound: bool,
}

pub fn profiles() -> Result<Vec<ProfileStatus>, String> {
    use windows::Win32::NetworkManagement::WindowsFirewall::{NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
    let _com = ComGuard::mta();
    unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("the Windows Firewall service is not available ({})", winerr::describe(&e)))?;
        let current = policy.CurrentProfileTypes().unwrap_or(0);
        let action = |a: windows::core::Result<windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION>| match a {
            Ok(a) if a == NET_FW_ACTION_ALLOW => "Allow".to_string(),
            Ok(a) if a == NET_FW_ACTION_BLOCK => "Block".to_string(),
            _ => String::new(),
        };
        Ok([("Domain", NET_FW_PROFILE2_DOMAIN), ("Private", NET_FW_PROFILE2_PRIVATE), ("Public", NET_FW_PROFILE2_PUBLIC)]
            .into_iter()
            .map(|(name, kind)| ProfileStatus {
                name: name.to_string(),
                active: current & kind.0 != 0,
                enabled: policy.get_FirewallEnabled(kind).map(|b| b.as_bool()).unwrap_or(false),
                inbound: action(policy.get_DefaultInboundAction(kind)),
                outbound: action(policy.get_DefaultOutboundAction(kind)),
                block_all_inbound: policy.get_BlockAllInboundTraffic(kind).map(|b| b.as_bool()).unwrap_or(false),
            })
            .collect())
    }
}

pub fn list() -> Result<Vec<FirewallRow>, String> {
    let policy = open_policy()?;
    let mut out = Vec::new();
    for_each_rule(&policy.rules, |rule| {
        out.push(unsafe { read_rule(&rule) });
        Ok(out.len() < 20_000)
    })?;
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

unsafe fn read_rule(rule: &INetFwRule) -> FirewallRow {
    unsafe {
        let text = |r: windows::core::Result<BSTR>| r.map(|b| b.to_string()).unwrap_or_default();
        let name = text(rule.Name());
        let direction = match rule.Direction() {
            Ok(d) if d == NET_FW_RULE_DIR_IN => "Inbound",
            Ok(d) if d == NET_FW_RULE_DIR_OUT => "Outbound",
            _ => "",
        }
        .to_string();
        let action = match rule.Action() {
            Ok(a) if a.0 == 1 => "Allow",
            Ok(a) if a.0 == 0 => "Block",
            _ => "",
        }
        .to_string();
        let description = text(rule.Description());
        let keyhole = name.starts_with("Keyhole block:") || description.starts_with("Created by Keyhole");
        let any = |s: String| if s == "*" { String::new() } else { s };
        FirewallRow {
            display: resolve_indirect(&name),
            description: resolve_indirect(&description),
            group: resolve_indirect(&text(rule.Grouping())),
            direction,
            action,
            enabled: rule.Enabled().map(|b| b.as_bool()).unwrap_or(false),
            protocol: rule.Protocol().map(proto_name).unwrap_or_default(),
            local_ports: any(text(rule.LocalPorts())),
            remote_ports: any(text(rule.RemotePorts())),
            remote_addresses: any(text(rule.RemoteAddresses())),
            program: text(rule.ApplicationName()),
            service: text(rule.ServiceName()),
            profiles: rule.Profiles().map(profiles_text).unwrap_or_default(),
            keyhole,
            name,
        }
    }
}
