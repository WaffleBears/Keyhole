use super::{pw, wide};
use std::collections::HashMap;
use windows::Win32::NetworkManagement::Dns::{
    DNS_FREE_TYPE, DNS_QUERY_NO_WIRE_QUERY, DNS_QUERY_OPTIONS, DNS_RECORDA, DNS_RECORDW, DNS_TYPE, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME,
    DnsFree, DnsQuery_W,
};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetAdaptersInfo, GetInterfaceInfo, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_INFO, IP_INTERFACE_INFO, IpReleaseAddress, IpRenewAddress, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET};
use windows::core::PCWSTR;

#[derive(Clone, Debug, Default)]
pub struct AdapterRow {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub status: String,
    pub up: bool,
    pub mac: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateways: Vec<String>,
    pub dns: Vec<String>,
    pub suffix: String,
    pub dhcp: bool,
    pub dhcp_server: String,
    pub lease_obtained_ms: i64,
    pub lease_expires_ms: i64,
    pub mtu: u32,
    pub speed: u64,
    pub index: u32,
    pub luid: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RouteRow {
    pub destination: String,
    pub prefix: u8,
    pub next_hop: String,
    pub interface: String,
    pub metric: u32,
    pub protocol: String,
    pub origin: String,
    pub age_secs: u32,
    pub v6: bool,
    pub index: u32,
}

#[derive(Clone, Debug, Default)]
pub struct DnsRecord {
    pub name: String,
    pub kind: String,
    pub data: String,
    pub ttl: u32,
    pub source: String,
}

#[derive(Clone, Debug, Default)]
pub struct NetConfigData {
    pub adapters: Vec<AdapterRow>,
    pub routes: Vec<RouteRow>,
    pub dns: Vec<DnsRecord>,
    pub host: String,
    pub domain: String,
    pub dns_suffixes: Vec<String>,
    pub notes: Vec<String>,
}

fn sock_text(sa: *const SOCKADDR) -> String {
    unsafe {
        if sa.is_null() {
            return String::new();
        }
        match (*sa).sa_family {
            AF_INET => {
                let v4 = &*(sa as *const SOCKADDR_IN);
                let b = v4.sin_addr.S_un.S_addr.to_ne_bytes();
                format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
            }
            AF_INET6 => {
                let v6 = &*(sa as *const SOCKADDR_IN6);
                std::net::Ipv6Addr::from(v6.sin6_addr.u.Byte).to_string()
            }
            _ => String::new(),
        }
    }
}

pub fn inet_text(a: &SOCKADDR_INET) -> String {
    sock_text(a as *const SOCKADDR_INET as *const SOCKADDR)
}

pub fn kind_name(if_type: u32) -> &'static str {
    match if_type {
        6 => "Ethernet",
        71 => "Wi-Fi",
        24 => "Loopback",
        131 => "Tunnel",
        23 => "PPP",
        237 => "WiMAX",
        243 | 244 => "WWAN",
        _ => "Other",
    }
}

pub fn status_name(s: i32) -> &'static str {
    match s {
        1 => "Up",
        2 => "Down",
        3 => "Testing",
        5 => "Dormant",
        6 => "Not present",
        7 => "Lower layer down",
        _ => "Unknown",
    }
}

pub fn mac_text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("-")
}

fn leases() -> HashMap<u32, (i64, i64)> {
    let mut out = HashMap::new();
    unsafe {
        let mut size = 0u32;
        let _ = GetAdaptersInfo(None, &mut size);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize + 256];
        let mut rc = GetAdaptersInfo(Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO), &mut size);
        if rc == 111 && size as usize > buf.len() {
            buf.resize(size as usize + 256, 0);
            rc = GetAdaptersInfo(Some(buf.as_mut_ptr() as *mut IP_ADAPTER_INFO), &mut size);
        }
        if rc != 0 {
            return out;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_INFO;
        while !cur.is_null() {
            let a = &*cur;
            if a.DhcpEnabled != 0 {
                out.insert(a.Index, (a.LeaseObtained * 1000, a.LeaseExpires * 1000));
            }
            cur = a.Next;
        }
    }
    out
}

pub fn adapters() -> Vec<AdapterRow> {
    let mut out = Vec::new();
    let lease = leases();
    unsafe {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut size = 0u32;
        let _ = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, None, &mut size);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize + 1024];
        let mut rc = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut size);
        for _ in 0..3 {
            if rc != 111 {
                break;
            }
            buf = vec![0u8; size as usize + 1024];
            rc = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut size);
        }
        if rc != 0 {
            return out;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let sa = (*u).Address.lpSockaddr;
                let s = sock_text(sa);
                if !s.is_empty() {
                    let prefix = (*u).OnLinkPrefixLength;
                    let with = if prefix > 0 { format!("{}/{}", s, prefix) } else { s };
                    if (*sa).sa_family == AF_INET { ipv4.push(with) } else { ipv6.push(with) }
                }
                u = (*u).Next;
            }
            let mut gateways = Vec::new();
            let mut g = a.FirstGatewayAddress;
            while !g.is_null() {
                let s = sock_text((*g).Address.lpSockaddr);
                if !s.is_empty() {
                    gateways.push(s);
                }
                g = (*g).Next;
            }
            let mut dns = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                let s = sock_text((*d).Address.lpSockaddr);
                if !s.is_empty() {
                    dns.push(s);
                }
                d = (*d).Next;
            }
            let index = a.Anonymous1.Anonymous.IfIndex;
            let dhcp = a.Anonymous2.Flags & 0x4 != 0;
            let (lease_obtained_ms, lease_expires_ms) = lease.get(&index).copied().unwrap_or((0, 0));
            out.push(AdapterRow {
                name: pw(a.FriendlyName),
                description: pw(a.Description),
                kind: kind_name(a.IfType).to_string(),
                status: status_name(a.OperStatus.0).to_string(),
                up: a.OperStatus.0 == 1,
                mac: { let n = (a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len()); if n > 0 { mac_text(&a.PhysicalAddress[..n]) } else { String::new() } },
                ipv4,
                ipv6,
                gateways,
                dns,
                suffix: pw(a.DnsSuffix),
                dhcp,
                dhcp_server: if dhcp { sock_text(a.Dhcpv4Server.lpSockaddr) } else { String::new() },
                lease_obtained_ms,
                lease_expires_ms,
                mtu: if a.Mtu == u32::MAX { 0 } else { a.Mtu },
                speed: if a.TransmitLinkSpeed == u64::MAX { 0 } else { a.TransmitLinkSpeed },
                index,
                luid: a.Luid.Value,
            });
            cur = a.Next;
        }
    }
    out.sort_by(|x, y| (!x.up).cmp(&!y.up).then((x.kind == "Loopback").cmp(&(y.kind == "Loopback"))).then(x.ipv4.is_empty().cmp(&y.ipv4.is_empty())).then(x.name.to_lowercase().cmp(&y.name.to_lowercase())));
    out
}

pub fn protocol_name(p: i32) -> &'static str {
    match p {
        1 => "Other",
        2 => "Local",
        3 => "Static",
        4 => "ICMP",
        5 => "EGP",
        6 => "GGP",
        7 => "Hello",
        8 => "RIP",
        9 => "IS-IS",
        10 => "ES-IS",
        11 => "Cisco",
        12 => "BBN",
        13 => "OSPF",
        14 => "BGP",
        15 => "IDPR",
        16 => "EIGRP",
        17 => "DVMRP",
        18 => "RPL",
        19 => "DHCP",
        10002 => "Auto static",
        10006 | 10007 => "Static",
        _ => "Other",
    }
}

pub fn origin_name(o: i32) -> &'static str {
    match o {
        0 => "manual",
        1 => "well known",
        2 => "DHCP",
        3 => "router advertisement",
        4 => "6to4",
        _ => "",
    }
}

fn routes(names: &HashMap<u32, String>) -> Vec<RouteRow> {
    let mut out = Vec::new();
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_UNSPEC, &mut table).0 != 0 || table.is_null() {
            return out;
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for r in rows {
            let v6 = r.DestinationPrefix.Prefix.si_family == AF_INET6;
            let dest = inet_text(&r.DestinationPrefix.Prefix);
            let hop = inet_text(&r.NextHop);
            out.push(RouteRow {
                destination: dest,
                prefix: r.DestinationPrefix.PrefixLength,
                next_hop: if hop == "0.0.0.0" || hop == "::" { "on-link".into() } else { hop },
                interface: names.get(&r.InterfaceIndex).cloned().unwrap_or_else(|| format!("if {}", r.InterfaceIndex)),
                metric: r.Metric,
                protocol: protocol_name(r.Protocol.0).to_string(),
                origin: origin_name(r.Origin.0).to_string(),
                age_secs: r.Age,
                v6,
                index: r.InterfaceIndex,
            });
        }
        FreeMibTable(table as *const _);
    }
    out.sort_by(|a, b| a.v6.cmp(&b.v6).then(b.prefix.cmp(&a.prefix).reverse()).then(a.destination.cmp(&b.destination)).then(a.metric.cmp(&b.metric)));
    out
}

#[repr(C)]
struct DnsCacheEntry {
    next: *mut DnsCacheEntry,
    name: windows::core::PWSTR,
    kind: u16,
    data_length: u16,
    flags: u32,
}

#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsGetCacheDataTable(table: *mut *mut DnsCacheEntry) -> i32;
    fn DnsFlushResolverCache() -> i32;
}

pub fn type_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        28 => "AAAA".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        33 => "SRV".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        2 => "NS".into(),
        6 => "SOA".into(),
        other => format!("type {}", other),
    }
}

const CACHE_ENTRIES_TOO: u32 = 0x8000;

fn cached_records(name: &str, kind: DNS_TYPE, out: &mut Vec<DnsRecord>) {
    let w = wide(name);
    unsafe {
        let mut results: *mut DNS_RECORDA = std::ptr::null_mut();
        if DnsQuery_W(PCWSTR(w.as_ptr()), kind, DNS_QUERY_OPTIONS(DNS_QUERY_NO_WIRE_QUERY.0 | CACHE_ENTRIES_TOO), None, &mut results, None).0 != 0 || results.is_null() {
            return;
        }
        let mut cur = results as *const DNS_RECORDW;
        while !cur.is_null() {
            let r = &*cur;
            let owner = if r.pName.is_null() { name.to_string() } else { r.pName.to_string().unwrap_or_default() };
            let data = match r.wType {
                1 => {
                    let b = r.Data.A.IpAddress.to_ne_bytes();
                    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                }
                28 => std::net::Ipv6Addr::from(r.Data.AAAA.Ip6Address.IP6Byte).to_string(),
                5 | 12 | 2 => {
                    pw(r.Data.PTR.pNameHost)
                }
                33 => {
                    let s = &r.Data.SRV;
                    format!("{}:{} (priority {}, weight {})", pw(s.pNameTarget), s.wPort, s.wPriority, s.wWeight)
                }
                _ => String::new(),
            };
            if !data.is_empty() {
                out.push(DnsRecord { name: owner, kind: type_name(r.wType), data, ttl: r.dwTtl, source: "cache".into() });
            }
            cur = r.pNext;
        }
        DnsFree(Some(results as *const _), DNS_FREE_TYPE(1));
    }
}

pub fn dns_cache() -> Vec<DnsRecord> {
    let mut names: Vec<(String, u16)> = Vec::new();
    unsafe {
        let mut table: *mut DnsCacheEntry = std::ptr::null_mut();
        if DnsGetCacheDataTable(&mut table) == 0 || table.is_null() {
            return Vec::new();
        }
        let mut cur = table;
        while !cur.is_null() {
            let e = &*cur;
            let name = pw(e.name);
            if !name.is_empty() {
                names.push((name, e.kind));
            }
            let next = e.next;
            if !e.name.is_null() {
                DnsFree(Some(e.name.0 as *const _), DNS_FREE_TYPE(0));
            }
            DnsFree(Some(cur as *const _), DNS_FREE_TYPE(0));
            cur = next;
        }
    }
    names.sort();
    names.dedup();
    let mut out = Vec::new();
    for (name, kind) in names {
        let t = match kind {
            1 => DNS_TYPE_A,
            28 => DNS_TYPE_AAAA,
            5 => DNS_TYPE_CNAME,
            other => DNS_TYPE(other),
        };
        cached_records(&name, t, &mut out);
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.kind.cmp(&b.kind)));
    out.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name) && a.kind == b.kind && a.data == b.data);
    out
}

pub fn hosts_file() -> Vec<DnsRecord> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let path = format!(r"{}\System32\drivers\etc\hosts", root);
    let Ok(text) = std::fs::read_to_string(&path) else { return Vec::new() };
    hosts_file_text(&text)
}

pub fn hosts_file_text(text: &str) -> Vec<DnsRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else { continue };
        let kind = if addr.contains(':') { "AAAA" } else { "A" };
        for name in parts {
            out.push(DnsRecord { name: name.to_string(), kind: kind.into(), data: addr.to_string(), ttl: 0, source: "hosts".into() });
        }
    }
    out
}

pub fn dns_suffixes() -> Vec<String> {
    use super::reg;
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    let mut out = Vec::new();
    for sub in [r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"] {
        if let Some(list) = reg::string_at(HKEY_LOCAL_MACHINE, sub, "SearchList") {
            for s in list.split(',') {
                let s = s.trim();
                if !s.is_empty() && !out.iter().any(|o: &String| o.eq_ignore_ascii_case(s)) {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

pub fn list() -> NetConfigData {
    let adapters = adapters();
    let names: HashMap<u32, String> = adapters.iter().map(|a| (a.index, a.name.clone())).collect();
    let mut dns = dns_cache();
    dns.extend(hosts_file());
    let (host, domain) = super::sysinfo::host_and_domain();
    NetConfigData {
        routes: routes(&names),
        dns,
        host,
        domain,
        dns_suffixes: dns_suffixes(),
        notes: Vec::new(),
        adapters,
    }
}

pub fn flush_dns() -> Result<(), String> {
    unsafe {
        if DnsFlushResolverCache() != 0 { Ok(()) } else { Err("Windows refused to flush the resolver cache".into()) }
    }
}

pub fn renew_dhcp(index: u32) -> Result<(), String> {
    unsafe {
        let mut size = 0u32;
        let _ = GetInterfaceInfo(None, &mut size);
        if size == 0 {
            return Err("no IPv4 interfaces".into());
        }
        let mut buf = vec![0u8; size as usize + 64];
        if GetInterfaceInfo(Some(buf.as_mut_ptr() as *mut IP_INTERFACE_INFO), &mut size) != 0 {
            return Err("the interface table could not be read".into());
        }
        let info = &*(buf.as_ptr() as *const IP_INTERFACE_INFO);
        let maps = std::slice::from_raw_parts(info.Adapter.as_ptr(), info.NumAdapters.max(0) as usize);
        let Some(map) = maps.iter().find(|m| m.Index == index) else { return Err("that adapter has no IPv4 interface to renew".into()) };
        let rc = IpReleaseAddress(map);
        if rc != 0 {
            return Err(format!("release failed: {}", super::winerr::text(rc)));
        }
        let rc = IpRenewAddress(map);
        if rc != 0 {
            return Err(format!("renew failed: {}", super::winerr::text(rc)));
        }
        Ok(())
    }
}

pub struct PingResult {
    pub replies: Vec<u32>,
    pub sent: u32,
    pub last_error: String,
}

pub fn icmp_status(code: u32) -> &'static str {
    match code {
        0 => "reply",
        11002 => "destination network unreachable",
        11003 => "destination host unreachable",
        11004 => "destination protocol unreachable",
        11005 => "destination port unreachable",
        11010 => "request timed out",
        11013 => "TTL expired in transit",
        11050 => "general failure",
        _ => "no reply",
    }
}

pub fn ping(target: &str, count: u32, timeout_ms: u32) -> Result<PingResult, String> {
    let host = target.split('/').next().unwrap_or(target).trim();
    let addr: std::net::IpAddr = host.parse().map_err(|_| format!("{} is not an IP address. Keyhole pings addresses, not names, so nothing depends on DNS", host))?;
    let payload = [0x4bu8; 32];
    let mut out = PingResult { replies: Vec::new(), sent: 0, last_error: String::new() };
    unsafe {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let h = IcmpCreateFile().map_err(|e| format!("ICMP is not available: {}", e))?;
                let dest = u32::from_ne_bytes(v4.octets());
                let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8];
                for _ in 0..count {
                    out.sent += 1;
                    let n = IcmpSendEcho(h, dest, payload.as_ptr() as *const _, payload.len() as u16, None, reply.as_mut_ptr() as *mut _, reply.len() as u32, timeout_ms);
                    if n > 0 {
                        let r = &*(reply.as_ptr() as *const ICMP_ECHO_REPLY);
                        if r.Status == 0 {
                            out.replies.push(r.RoundTripTime);
                        } else {
                            out.last_error = icmp_status(r.Status).into();
                        }
                    } else {
                        out.last_error = icmp_status(windows::Win32::Foundation::GetLastError().0).into();
                    }
                }
                let _ = IcmpCloseHandle(h);
            }
            std::net::IpAddr::V6(v6) => {
                let h = Icmp6CreateFile().map_err(|e| format!("ICMPv6 is not available: {}", e))?;
                let mut src = SOCKADDR_IN6::default();
                src.sin6_family = AF_INET6;
                let mut dst = SOCKADDR_IN6::default();
                dst.sin6_family = AF_INET6;
                dst.sin6_addr.u.Byte = v6.octets();
                let mut reply = vec![0u8; std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + payload.len() + 8];
                for _ in 0..count {
                    out.sent += 1;
                    let n = Icmp6SendEcho2(h, None, None, None, &src, &dst, payload.as_ptr() as *const _, payload.len() as u16, None, reply.as_mut_ptr() as *mut _, reply.len() as u32, timeout_ms);
                    if n > 0 {
                        let r = &*(reply.as_ptr() as *const ICMPV6_ECHO_REPLY_LH);
                        if r.Status == 0 {
                            out.replies.push(r.RoundTripTime);
                        } else {
                            out.last_error = icmp_status(r.Status).into();
                        }
                    } else {
                        out.last_error = icmp_status(windows::Win32::Foundation::GetLastError().0).into();
                    }
                }
                let _ = IcmpCloseHandle(h);
            }
        }
    }
    Ok(out)
}

pub fn ping_text(target: &str, r: &PingResult) -> String {
    if r.replies.is_empty() {
        format!("{}: no reply to {} pings ({})", target, r.sent, if r.last_error.is_empty() { "timed out" } else { &r.last_error })
    } else {
        let min = r.replies.iter().min().copied().unwrap_or(0);
        let max = r.replies.iter().max().copied().unwrap_or(0);
        let lost = r.sent - r.replies.len() as u32;
        format!("{}: {} of {} pings replied, {} ms{}", target, r.replies.len(), r.sent, if min == max { min.to_string() } else { format!("{} to {}", min, max) }, if lost > 0 { format!(", {} lost", lost) } else { String::new() })
    }
}

pub fn adapter_summary(a: &AdapterRow) -> String {
    let mut s = format!("{}\n{}\n{}  ·  {}", a.name, a.description, a.kind, a.status);
    if !a.mac.is_empty() {
        s.push_str(&format!("\nMAC {}", a.mac));
    }
    if !a.ipv4.is_empty() {
        s.push_str(&format!("\nIPv4 {}", a.ipv4.join(", ")));
    }
    if !a.ipv6.is_empty() {
        s.push_str(&format!("\nIPv6 {}", a.ipv6.join(", ")));
    }
    if !a.gateways.is_empty() {
        s.push_str(&format!("\nGateway {}", a.gateways.join(", ")));
    }
    if !a.dns.is_empty() {
        s.push_str(&format!("\nDNS {}", a.dns.join(", ")));
    }
    if !a.suffix.is_empty() {
        s.push_str(&format!("\nDNS suffix {}", a.suffix));
    }
    if a.dhcp {
        s.push_str(&format!("\nDHCP from {}", if a.dhcp_server.is_empty() { "an unknown server".to_string() } else { a.dhcp_server.clone() }));
        if a.lease_obtained_ms > 0 {
            s.push_str(&format!("\nLease obtained {}, expires {}", super::local_time_text(a.lease_obtained_ms), super::local_time_text(a.lease_expires_ms)));
        }
    } else if !a.ipv4.is_empty() {
        s.push_str("\nStatic IPv4 configuration");
    }
    if a.mtu > 0 {
        s.push_str(&format!("\nMTU {}", a.mtu));
    }
    if a.speed > 0 {
        s.push_str(&format!("\nLink speed {}", speed_text(a.speed)));
    }
    s
}

pub fn ip_sort_key(ip: &str) -> String {
    match ip.split('/').next().unwrap_or("").parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => format!("a{:010}", u32::from(v4)),
        Ok(std::net::IpAddr::V6(v6)) => format!("b{:032x}", u128::from(v6)),
        Err(_) => format!("c{}", ip),
    }
}

pub fn speed_text(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        let g = bps as f64 / 1e9;
        if (g - g.round()).abs() < 0.05 { format!("{} Gbps", g.round() as u64) } else { format!("{:.1} Gbps", g) }
    } else if bps >= 1_000_000 {
        format!("{} Mbps", bps / 1_000_000)
    } else if bps > 0 {
        format!("{} kbps", bps / 1000)
    } else {
        String::new()
    }
}
