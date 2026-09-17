use crate::model::EndpointRow;
use std::ffi::c_void;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

fn tcp_state(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn port(be: u32) -> u16 {
    u16::from_be((be & 0xFFFF) as u16)
}

fn v4(addr: u32) -> String {
    Ipv4Addr::from(addr.to_ne_bytes()).to_string()
}

fn v6(addr: &[u8; 16], scope: u32) -> String {
    let ip = Ipv6Addr::from(*addr);
    if scope != 0 && (ip.segments()[0] & 0xffc0) == 0xfe80 {
        format!("{}%{}", ip, scope)
    } else {
        ip.to_string()
    }
}

pub fn close_tcp(local: &str, remote: &str) -> Result<(), String> {
    use std::net::SocketAddrV4;
    use windows::Win32::NetworkManagement::IpHelper::{MIB_TCPROW_LH, MIB_TCPROW_LH_0, SetTcpEntry};
    let l: SocketAddrV4 = local.parse().map_err(|_| "IPv6 connections cannot be closed here".to_string())?;
    let r: SocketAddrV4 = remote.parse().map_err(|_| "IPv6 connections cannot be closed here".to_string())?;
    let mut row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { dwState: 12 },
        dwLocalAddr: u32::from_ne_bytes(l.ip().octets()),
        dwLocalPort: (l.port() as u32).to_be() >> 16,
        dwRemoteAddr: u32::from_ne_bytes(r.ip().octets()),
        dwRemotePort: (r.port() as u32).to_be() >> 16,
    };
    let rc = unsafe { SetTcpEntry(&mut row as *mut _ as *mut _) };
    match rc {
        0 => Ok(()),
        5 => Err("Windows refused to close the connection".into()),
        317 => Err("the connection is no longer established".into()),
        other => Err(format!("could not close the connection (Windows error {})", other)),
    }
}

pub fn endpoints() -> Vec<EndpointRow> {
    let mut out = Vec::new();
    collect_tcp4(&mut out);
    collect_tcp6(&mut out);
    collect_udp4(&mut out);
    collect_udp6(&mut out);
    out
}

type DnsCache = parking_lot::Mutex<HashMap<String, (String, std::time::Instant)>>;
static DNS_CACHE: std::sync::OnceLock<DnsCache> = std::sync::OnceLock::new();
static DNS_QUEUE: std::sync::OnceLock<Vec<parking_lot::Mutex<std::sync::mpsc::Sender<String>>>> = std::sync::OnceLock::new();
const DNS_WORKERS: usize = 4;
static DNS_PENDING: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
const DNS_NEGATIVE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

fn dns_cache() -> &'static DnsCache {
    DNS_CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn ip_of(endpoint: &str) -> String {
    let host_port = endpoint.trim();
    host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port).to_string()
}

fn cached_host(ip: &str) -> Option<String> {
    let cache = dns_cache().lock();
    let (hit, at) = cache.get(ip)?;
    if !hit.is_empty() || at.elapsed() < DNS_NEGATIVE_TTL { Some(hit.clone()) } else { None }
}

fn dns_queue(ip: &str) -> &'static parking_lot::Mutex<std::sync::mpsc::Sender<String>> {
    let queues = DNS_QUEUE.get_or_init(|| {
        (0..DNS_WORKERS)
            .map(|_| {
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                std::thread::Builder::new()
                    .name("keyhole-dns".into())
                    .spawn(move || {
                        while let Ok(endpoint) = rx.recv() {
                            let _ = reverse_dns(&endpoint);
                            if let Some(p) = DNS_PENDING.get() {
                                p.lock().remove(&ip_of(&endpoint));
                            }
                        }
                    })
                    .ok();
                parking_lot::Mutex::new(tx)
            })
            .collect()
    });
    let mut hash = 0usize;
    for b in ip.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as usize);
    }
    &queues[hash % queues.len()]
}

pub fn reverse_dns_cached(endpoint: &str) -> String {
    let ip = ip_of(endpoint);
    if let Some(hit) = cached_host(&ip) {
        return hit;
    }
    let pending = DNS_PENDING.get_or_init(|| parking_lot::Mutex::new(std::collections::HashSet::new()));
    let mut guard = pending.lock();
    if guard.len() < 2000 && guard.insert(ip.clone()) {
        let _ = dns_queue(&ip).lock().send(endpoint.to_string());
    }
    String::new()
}

pub fn reverse_dns(endpoint: &str) -> String {
    use std::net::{SocketAddr, ToSocketAddrs};
    use windows::Win32::Networking::WinSock::{
        NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, getnameinfo, socklen_t,
    };

    static WINSOCK: std::sync::Once = std::sync::Once::new();
    let cache = dns_cache();
    WINSOCK.call_once(|| unsafe {
        let mut data = windows::Win32::Networking::WinSock::WSADATA::default();
        let _ = windows::Win32::Networking::WinSock::WSAStartup(0x0202, &mut data);
    });

    let host_port = endpoint.trim();
    let ip_only = ip_of(host_port);
    if let Some(hit) = cached_host(&ip_only) {
        return hit;
    }
    let addr: SocketAddr = match host_port.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => return String::new(),
    };

    let mut name = [0u8; 256];
    let ok = unsafe {
        match addr {
            SocketAddr::V4(v4) => {
                let mut sa = SOCKADDR_IN::default();
                sa.sin_family = windows::Win32::Networking::WinSock::AF_INET;
                sa.sin_port = v4.port().to_be();
                sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.ip().octets());
                getnameinfo(
                    &sa as *const _ as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut name),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
            SocketAddr::V6(v6) => {
                let mut sa = SOCKADDR_IN6::default();
                sa.sin6_family = windows::Win32::Networking::WinSock::AF_INET6;
                sa.sin6_port = v6.port().to_be();
                sa.Anonymous.sin6_scope_id = v6.scope_id();
                sa.sin6_addr.u.Byte = v6.ip().octets();
                getnameinfo(
                    &sa as *const _ as *const SOCKADDR,
                    socklen_t(std::mem::size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut name),
                    None,
                    NI_NAMEREQD as i32,
                )
            }
        }
    };

    let resolved = if ok != 0 {
        String::new()
    } else {
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let s = String::from_utf8_lossy(&name[..end]).into_owned();
        if s == ip_only { String::new() } else { s }
    };
    if cache.lock().len() < 20_000 {
        cache.lock().insert(ip_only, (resolved.clone(), std::time::Instant::now()));
    }
    resolved
}

fn fetch(f: impl Fn(*mut c_void, *mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0u32;
    f(std::ptr::null_mut(), &mut size);
    if size == 0 {
        return None;
    }
    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize + 4096];
        let mut cap = buf.len() as u32;
        match f(buf.as_mut_ptr() as *mut c_void, &mut cap) {
            0 => return Some(buf),
            122 => size = cap.max(size + 4096),
            _ => return None,
        }
    }
    None
}

fn collect_tcp4(out: &mut Vec<EndpointRow>) {
    let buf = fetch(|p, s| unsafe {
        GetExtendedTcpTable(
            Some(p),
            s,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    });
    let Some(buf) = buf else { return };
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::ptr::addr_of!(table.table) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..table.dwNumEntries as usize {
            let r = &*rows.add(i);
            out.push(EndpointRow {
                pid: r.dwOwningPid,
                process: String::new(),
                proto: "TCP".into(),
                local: format!("{}:{}", v4(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: if r.dwState == 2 {
                    String::new()
                } else {
                    format!("{}:{}", v4(r.dwRemoteAddr), port(r.dwRemotePort))
                },
                remote_host: String::new(),
                state: tcp_state(r.dwState).into(),
            });
        }
    }
}

fn collect_tcp6(out: &mut Vec<EndpointRow>) {
    let buf = fetch(|p, s| unsafe {
        GetExtendedTcpTable(
            Some(p),
            s,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    });
    let Some(buf) = buf else { return };
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::ptr::addr_of!(table.table) as *const MIB_TCP6ROW_OWNER_PID;
        for i in 0..table.dwNumEntries as usize {
            let r = &*rows.add(i);
            out.push(EndpointRow {
                pid: r.dwOwningPid,
                process: String::new(),
                proto: "TCPv6".into(),
                local: format!("[{}]:{}", v6(&r.ucLocalAddr, r.dwLocalScopeId), port(r.dwLocalPort)),
                remote: if r.dwState == 2 {
                    String::new()
                } else {
                    format!("[{}]:{}", v6(&r.ucRemoteAddr, r.dwRemoteScopeId), port(r.dwRemotePort))
                },
                remote_host: String::new(),
                state: tcp_state(r.dwState).into(),
            });
        }
    }
}

fn collect_udp4(out: &mut Vec<EndpointRow>) {
    let buf = fetch(|p, s| unsafe {
        GetExtendedUdpTable(Some(p), s, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)
    });
    let Some(buf) = buf else { return };
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::ptr::addr_of!(table.table) as *const MIB_UDPROW_OWNER_PID;
        for i in 0..table.dwNumEntries as usize {
            let r = &*rows.add(i);
            out.push(EndpointRow {
                pid: r.dwOwningPid,
                process: String::new(),
                proto: "UDP".into(),
                local: format!("{}:{}", v4(r.dwLocalAddr), port(r.dwLocalPort)),
                remote: String::new(),
                remote_host: String::new(),
                state: String::new(),
            });
        }
    }
}

fn collect_udp6(out: &mut Vec<EndpointRow>) {
    let buf = fetch(|p, s| unsafe {
        GetExtendedUdpTable(
            Some(p),
            s,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    });
    let Some(buf) = buf else { return };
    unsafe {
        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let rows = std::ptr::addr_of!(table.table) as *const MIB_UDP6ROW_OWNER_PID;
        for i in 0..table.dwNumEntries as usize {
            let r = &*rows.add(i);
            out.push(EndpointRow {
                pid: r.dwOwningPid,
                process: String::new(),
                proto: "UDPv6".into(),
                local: format!("[{}]:{}", v6(&r.ucLocalAddr, r.dwLocalScopeId), port(r.dwLocalPort)),
                remote: String::new(),
                remote_host: String::new(),
                state: String::new(),
            });
        }
    }
}
