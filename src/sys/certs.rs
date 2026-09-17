use super::{filetime_to_unix_ms, from_wide, reg, wide};
use std::path::Path;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Networking::HttpServer::{
    HTTP_INITIALIZE_CONFIG, HTTP_SERVICE_CONFIG_ID, HTTP_SERVICE_CONFIG_SSL_QUERY, HTTP_SERVICE_CONFIG_SSL_SET, HTTP_SERVICE_CONFIG_SSL_SNI_QUERY,
    HTTP_SERVICE_CONFIG_SSL_SNI_SET, HTTPAPI_VERSION, HttpInitialize, HttpQueryServiceConfiguration, HttpServiceConfigQueryNext, HttpServiceConfigSSLCertInfo,
    HttpServiceConfigSslSniCertInfo, HttpTerminate,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};
use windows::Win32::Security::Cryptography::{
    CERT_ALT_NAME_INFO, CERT_CONTEXT, CERT_FRIENDLY_NAME_PROP_ID, CERT_HASH_PROP_ID, CERT_KEY_PROV_INFO_PROP_ID,
    CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_NAME_VALUE,
    CERT_OPEN_STORE_FLAGS, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_TEMPLATE_EXT, CRYPT_DECODE_ALLOC_FLAG, CTL_USAGE, CertCloseStore,
    CertEnumCertificatesInStore, CertFindExtension, CertGetCertificateContextProperty,
    CertGetEnhancedKeyUsage, CertGetNameStringW, CertGetPublicKeyLength, CertOpenStore, CryptDecodeObjectEx,
    HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ALTERNATE_NAME, X509_ASN_ENCODING, X509_CERTIFICATE_TEMPLATE,
    X509_OBJECT_IDENTIFIER, X509_UNICODE_ANY_STRING, szOID_CERTIFICATE_TEMPLATE, szOID_ENROLL_CERTTYPE_EXTENSION, szOID_SUBJECT_ALT_NAME2,
};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::core::PCSTR;

#[derive(Clone, Debug, Default)]
pub struct CertRow {
    pub store: String,
    pub store_id: String,
    pub subject: String,
    pub friendly: String,
    pub issuer: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
    pub thumbprint: String,
    pub serial: String,
    pub has_private_key: bool,
    pub self_signed: bool,
    pub key_algorithm: String,
    pub key_bits: u32,
    pub eku: Vec<String>,
    pub sans: Vec<String>,
    pub template: String,
    pub bindings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CertsData {
    pub rows: Vec<CertRow>,
    pub notes: Vec<String>,
}

pub const STORES: &[(&str, &str)] = &[
    ("My", "Personal"),
    ("WebHosting", "Web Hosting"),
    ("Remote Desktop", "Remote Desktop"),
    ("Root", "Trusted Root"),
    ("AuthRoot", "Third-Party Root"),
    ("CA", "Intermediate CA"),
    ("TrustedPublisher", "Trusted Publishers"),
    ("TrustedPeople", "Trusted People"),
    ("Disallowed", "Untrusted"),
];

pub const SEGMENTS: &[(&str, &str, &[&str])] = &[
    ("personal", "Personal", &["My", "WebHosting", "Remote Desktop"]),
    ("roots", "Trusted roots", &["Root", "AuthRoot"]),
    ("ca", "Intermediate", &["CA"]),
    ("trust", "Publishers & people", &["TrustedPublisher", "TrustedPeople"]),
    ("untrusted", "Untrusted", &["Disallowed"]),
];

pub fn segment_of(store_id: &str) -> &'static str {
    SEGMENTS.iter().find(|(_, _, ids)| ids.contains(&store_id)).map(|(id, _, _)| *id).unwrap_or("personal")
}

pub fn store_label(store_id: &str) -> &'static str {
    STORES.iter().find(|(id, _)| *id == store_id).map(|(_, l)| *l).unwrap_or("Personal")
}

const ENCODING: windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE =
    windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);

struct Store(HCERTSTORE);

impl Drop for Store {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

fn open_store(name: &str) -> Option<Store> {
    let w = wide(name);
    unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            ENCODING,
            None,
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0),
            Some(w.as_ptr() as *const _),
        )
        .ok()
        .filter(|h| !h.0.is_null())
        .map(Store)
    }
}

fn open_store_writable(name: &str) -> Result<Store, String> {
    let w = wide(name);
    unsafe {
        CertOpenStore(CERT_STORE_PROV_SYSTEM_W, ENCODING, None, CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE), Some(w.as_ptr() as *const _))
            .ok()
            .filter(|h| !h.0.is_null())
            .map(Store)
            .ok_or_else(|| format!("could not open the machine {} store for writing", store_label(name)))
    }
}

fn for_each_cert(store: &Store, mut f: impl FnMut(*const CERT_CONTEXT)) {
    unsafe {
        let mut ctx = CertEnumCertificatesInStore(store.0, None);
        while !ctx.is_null() {
            f(ctx);
            ctx = CertEnumCertificatesInStore(store.0, Some(ctx));
        }
    }
}

fn name_string(ctx: *const CERT_CONTEXT, flags: u32) -> String {
    unsafe {
        let n = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None);
        if n <= 1 {
            return String::new();
        }
        let mut buf = vec![0u16; n as usize];
        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, Some(&mut buf));
        from_wide(&buf)
    }
}

fn property(ctx: *const CERT_CONTEXT, id: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut size = 0u32;
        CertGetCertificateContextProperty(ctx, id, None, &mut size).ok()?;
        let mut buf = vec![0u8; size as usize];
        CertGetCertificateContextProperty(ctx, id, Some(buf.as_mut_ptr() as *mut _), &mut size).ok()?;
        buf.truncate(size as usize);
        Some(buf)
    }
}

fn has_property(ctx: *const CERT_CONTEXT, id: u32) -> bool {
    unsafe {
        let mut size = 0u32;
        CertGetCertificateContextProperty(ctx, id, None, &mut size).is_ok() && size > 0
    }
}

pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

pub fn eku_name(oid: &str) -> String {
    match oid {
        "1.3.6.1.5.5.7.3.1" => "Server Authentication",
        "1.3.6.1.5.5.7.3.2" => "Client Authentication",
        "1.3.6.1.5.5.7.3.3" => "Code Signing",
        "1.3.6.1.5.5.7.3.4" => "Secure Email",
        "1.3.6.1.5.5.7.3.8" => "Time Stamping",
        "1.3.6.1.5.5.7.3.9" => "OCSP Signing",
        "1.3.6.1.4.1.311.54.1.2" => "Remote Desktop Authentication",
        "1.3.6.1.4.1.311.20.2.2" => "Smart Card Logon",
        "1.3.6.1.4.1.311.10.3.4" => "Encrypting File System",
        "1.3.6.1.4.1.311.10.3.12" => "Document Signing",
        "1.3.6.1.4.1.311.10.3.2" => "Microsoft Time Stamping",
        "1.3.6.1.4.1.311.20.2.1" => "Certificate Request Agent",
        "1.3.6.1.4.1.311.21.5" => "Private Key Archival",
        "1.3.6.1.4.1.311.21.6" => "Key Recovery Agent",
        "1.3.6.1.4.1.311.10.3.1" => "Microsoft Trust List Signing",
        "1.3.6.1.4.1.311.10.3.13" => "Lifetime Signing",
        "1.3.6.1.4.1.311.80.1" => "Document Encryption",
        "1.3.6.1.5.5.8.2.2" => "IP Security IKE Intermediate",
        "1.3.6.1.5.5.7.3.5" => "IP Security End System",
        "1.3.6.1.5.5.7.3.6" => "IP Security Tunnel",
        "1.3.6.1.5.5.7.3.7" => "IP Security User",
        "1.3.6.1.4.1.311.10.3.11" => "Key Recovery",
        "1.3.6.1.4.1.311.10.6.2" => "License Server Verification",
        "1.3.6.1.4.1.311.61.1.1" => "Kernel Mode Code Signing",
        "1.3.6.1.4.1.311.10.3.5" => "Windows Hardware Driver Verification",
        "1.3.6.1.4.1.311.76.6.1" => "Windows Update",
        "1.3.6.1.4.1.311.10.3.24" => "Protected Process Verification",
        "2.5.29.37.0" => "Any Purpose",
        "1.3.6.1.4.1.311.20.1" => "Certificate Trust List Signing",
        "2.16.840.1.113730.4.1" => "Netscape Server Gated Crypto",
        "1.3.6.1.4.1.311.10.3.3" => "Server Gated Cryptography",
        "1.3.6.1.5.2.3.5" => "KDC Authentication",
        "1.3.6.1.4.1.311.10.3.6" => "Windows System Component Verification",
        _ => oid,
    }
    .to_string()
}

fn eku_list(ctx: *const CERT_CONTEXT) -> Vec<String> {
    unsafe {
        let mut size = 0u32;
        if CertGetEnhancedKeyUsage(ctx, 0, None, &mut size).is_err() || size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        if CertGetEnhancedKeyUsage(ctx, 0, Some(buf.as_mut_ptr() as *mut CTL_USAGE), &mut size).is_err() {
            return Vec::new();
        }
        let usage = &*(buf.as_ptr() as *const CTL_USAGE);
        (0..usage.cUsageIdentifier as usize)
            .filter_map(|i| {
                let p = *usage.rgpszUsageIdentifier.add(i);
                if p.is_null() { None } else { Some(eku_name(&p.to_string().unwrap_or_default())) }
            })
            .collect()
    }
}

struct Decoded(*mut core::ffi::c_void);

impl Drop for Decoded {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

fn decode(kind: PCSTR, data: &[u8]) -> Option<Decoded> {
    unsafe {
        let mut out: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size = 0u32;
        CryptDecodeObjectEx(ENCODING, kind, data, CRYPT_DECODE_ALLOC_FLAG, None, Some(&mut out as *mut _ as *mut _), &mut size).ok()?;
        if out.is_null() { None } else { Some(Decoded(out)) }
    }
}

fn extension(info: &windows::Win32::Security::Cryptography::CERT_INFO, oid: PCSTR) -> Option<&[u8]> {
    unsafe {
        if info.cExtension == 0 || info.rgExtension.is_null() {
            return None;
        }
        let exts = std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize);
        let e = CertFindExtension(oid, exts);
        if e.is_null() {
            return None;
        }
        let v = &(*e).Value;
        if v.pbData.is_null() || v.cbData == 0 { None } else { Some(std::slice::from_raw_parts(v.pbData, v.cbData as usize)) }
    }
}

fn sans_of(info: &windows::Win32::Security::Cryptography::CERT_INFO) -> Vec<String> {
    let Some(raw) = extension(info, szOID_SUBJECT_ALT_NAME2) else { return Vec::new() };
    let Some(d) = decode(X509_ALTERNATE_NAME, raw) else { return Vec::new() };
    unsafe {
        let alt = &*(d.0 as *const CERT_ALT_NAME_INFO);
        (0..alt.cAltEntry as usize)
            .filter_map(|i| {
                let e = &*alt.rgAltEntry.add(i);
                match e.dwAltNameChoice {
                    2 => Some(format!("email:{}", e.Anonymous.pwszRfc822Name.to_string().unwrap_or_default())),
                    3 => Some(e.Anonymous.pwszDNSName.to_string().unwrap_or_default()),
                    7 => Some(e.Anonymous.pwszURL.to_string().unwrap_or_default()),
                    8 => {
                        let b = e.Anonymous.IPAddress;
                        let bytes = std::slice::from_raw_parts(b.pbData, b.cbData as usize);
                        Some(match bytes.len() {
                            4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
                            16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap_or([0; 16])).to_string(),
                            _ => hex_upper(bytes),
                        })
                    }
                    1 => {
                        let o = &*e.Anonymous.pOtherName;
                        let oid = o.pszObjId.to_string().unwrap_or_default();
                        let value = std::slice::from_raw_parts(o.Value.pbData, o.Value.cbData as usize);
                        let text = decode(PCSTR(X509_UNICODE_ANY_STRING as usize as *const u8), value)
                            .map(|dd| {
                                let nv = &*(dd.0 as *const CERT_NAME_VALUE);
                                let w = std::slice::from_raw_parts(nv.Value.pbData as *const u16, nv.Value.cbData as usize / 2);
                                from_wide(w)
                            })
                            .unwrap_or_default();
                        match oid.as_str() {
                            "1.3.6.1.4.1.311.20.2.3" => Some(format!("upn:{}", text)),
                            _ if !text.is_empty() => Some(format!("{}:{}", oid, text)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            })
            .filter(|s| !s.is_empty())
            .collect()
    }
}

fn template_of(info: &windows::Win32::Security::Cryptography::CERT_INFO) -> String {
    if let Some(raw) = extension(info, szOID_ENROLL_CERTTYPE_EXTENSION)
        && let Some(d) = decode(PCSTR(X509_UNICODE_ANY_STRING as usize as *const u8), raw) {
            unsafe {
                let nv = &*(d.0 as *const CERT_NAME_VALUE);
                let w = std::slice::from_raw_parts(nv.Value.pbData as *const u16, nv.Value.cbData as usize / 2);
                let s = from_wide(w);
                if !s.is_empty() {
                    return s;
                }
            }
        }
    if let Some(raw) = extension(info, szOID_CERTIFICATE_TEMPLATE)
        && let Some(d) = decode(X509_CERTIFICATE_TEMPLATE, raw) {
            unsafe {
                let t = &*(d.0 as *const CERT_TEMPLATE_EXT);
                let oid = t.pszObjId.to_string().unwrap_or_default();
                if !oid.is_empty() {
                    return format!("{} v{}.{}", oid, t.dwMajorVersion, t.dwMinorVersion);
                }
            }
        }
    String::new()
}

fn key_algorithm(info: &windows::Win32::Security::Cryptography::CERT_INFO) -> (String, u32) {
    unsafe {
        let oid = info.SubjectPublicKeyInfo.Algorithm.pszObjId.to_string().unwrap_or_default();
        let bits = CertGetPublicKeyLength(ENCODING, &info.SubjectPublicKeyInfo);
        let name = match oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            "1.2.840.10045.2.1" => {
                let p = &info.SubjectPublicKeyInfo.Algorithm.Parameters;
                let curve = if p.pbData.is_null() || p.cbData == 0 {
                    String::new()
                } else {
                    let params = std::slice::from_raw_parts(p.pbData, p.cbData as usize);
                    match decode(X509_OBJECT_IDENTIFIER, params) {
                        Some(d) => {
                            let s = (*(d.0 as *const PCSTR)).to_string().unwrap_or_default();
                            match s.as_str() {
                                "1.2.840.10045.3.1.7" => "P-256".to_string(),
                                "1.3.132.0.34" => "P-384".to_string(),
                                "1.3.132.0.35" => "P-521".to_string(),
                                _ => s,
                            }
                        }
                        None => String::new(),
                    }
                };
                if curve.is_empty() { "ECC".to_string() } else { format!("ECC {}", curve) }
            }
            "1.2.840.10040.4.1" => "DSA".to_string(),
            "1.3.101.112" => "Ed25519".to_string(),
            _ => oid,
        };
        (name, bits)
    }
}

fn row_of(store_id: &str, ctx: *const CERT_CONTEXT) -> CertRow {
    let store = store_label(store_id);
    unsafe {
        let info = &*(*ctx).pCertInfo;
        let subject_blob = std::slice::from_raw_parts(info.Subject.pbData, info.Subject.cbData as usize);
        let issuer_blob = std::slice::from_raw_parts(info.Issuer.pbData, info.Issuer.cbData as usize);
        let serial = std::slice::from_raw_parts(info.SerialNumber.pbData, info.SerialNumber.cbData as usize);
        let (key_algorithm, key_bits) = key_algorithm(info);
        let friendly = property(ctx, CERT_FRIENDLY_NAME_PROP_ID)
            .map(|b| from_wide(&b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()))
            .unwrap_or_default();
        CertRow {
            store: store.to_string(),
            store_id: store_id.to_string(),
            subject: name_string(ctx, 0),
            friendly,
            issuer: name_string(ctx, CERT_NAME_ISSUER_FLAG),
            not_before_ms: filetime_to_unix_ms(((info.NotBefore.dwHighDateTime as i64) << 32) | info.NotBefore.dwLowDateTime as i64),
            not_after_ms: filetime_to_unix_ms(((info.NotAfter.dwHighDateTime as i64) << 32) | info.NotAfter.dwLowDateTime as i64),
            thumbprint: property(ctx, CERT_HASH_PROP_ID).map(|b| hex_upper(&b)).unwrap_or_default(),
            serial: hex_upper(&serial.iter().rev().copied().collect::<Vec<_>>()),
            has_private_key: has_property(ctx, CERT_KEY_PROV_INFO_PROP_ID) || has_property(ctx, CERT_NCRYPT_KEY_HANDLE_PROP_ID),
            self_signed: subject_blob == issuer_blob,
            key_algorithm,
            key_bits,
            eku: eku_list(ctx),
            sans: sans_of(info),
            template: template_of(info),
            bindings: Vec::new(),
        }
    }
}

pub struct Binding {
    pub label: String,
    pub thumbprint: String,
}

fn sockaddr_text(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> String {
    unsafe {
        if sa.is_null() {
            return String::new();
        }
        match (*sa).sa_family {
            AF_INET => {
                let v4 = &*(sa as *const SOCKADDR_IN);
                let ip = std::net::Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr));
                format!("{}:{}", ip, u16::from_be(v4.sin_port))
            }
            AF_INET6 => {
                let v6 = &*(sa as *const SOCKADDR_IN6);
                let ip = std::net::Ipv6Addr::from(v6.sin6_addr.u.Byte);
                format!("[{}]:{}", ip, u16::from_be(v6.sin6_port))
            }
            other => format!("family {}", other.0),
        }
    }
}

unsafe fn query_bindings<Q: Default>(id: HTTP_SERVICE_CONFIG_ID, prepare: impl Fn(&mut Q, u32), read: impl Fn(&[u8]) -> Binding) -> Result<Vec<Binding>, u32> {
    let mut out = Vec::new();
    let mut token = 0u32;
    loop {
        let mut query = Q::default();
        prepare(&mut query, token);
        let mut needed = 0u32;
        let rc = unsafe { HttpQueryServiceConfiguration(Some(HANDLE::default()), id, Some(&query as *const _ as *const _), std::mem::size_of::<Q>() as u32, None, 0, Some(&mut needed), None) };
        if rc == ERROR_NO_MORE_ITEMS.0 {
            break;
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 || needed == 0 {
            if out.is_empty() && rc != 0 {
                return Err(rc);
            }
            break;
        }
        let mut buf = vec![0u8; needed as usize];
        let rc = unsafe { HttpQueryServiceConfiguration(Some(HANDLE::default()), id, Some(&query as *const _ as *const _), std::mem::size_of::<Q>() as u32, Some(buf.as_mut_ptr() as *mut _), needed, Some(&mut needed), None) };
        if rc != 0 {
            break;
        }
        out.push(read(&buf));
        token += 1;
    }
    Ok(out)
}

fn hash_text(param: &windows::Win32::Networking::HttpServer::HTTP_SERVICE_CONFIG_SSL_PARAM) -> String {
    if param.pSslHash.is_null() || param.SslHashLength == 0 {
        String::new()
    } else {
        hex_upper(unsafe { std::slice::from_raw_parts(param.pSslHash as *const u8, param.SslHashLength as usize) })
    }
}

pub fn http_bindings() -> (Vec<Binding>, Option<String>) {
    unsafe {
        let version = HTTPAPI_VERSION { HttpApiMajorVersion: 1, HttpApiMinorVersion: 0 };
        let rc = HttpInitialize(version, HTTP_INITIALIZE_CONFIG, None);
        if rc != 0 {
            return (Vec::new(), Some(format!("HTTP.sys bindings could not be read (HttpInitialize error {})", rc)));
        }
        let ip = query_bindings::<HTTP_SERVICE_CONFIG_SSL_QUERY>(
            HttpServiceConfigSSLCertInfo,
            |q, token| {
                q.QueryDesc = HttpServiceConfigQueryNext;
                q.dwToken = token;
            },
            |buf| {
                let set = &*(buf.as_ptr() as *const HTTP_SERVICE_CONFIG_SSL_SET);
                Binding { label: format!("HTTPS {}", sockaddr_text(set.KeyDesc.pIpPort)), thumbprint: hash_text(&set.ParamDesc) }
            },
        );
        let sni = query_bindings::<HTTP_SERVICE_CONFIG_SSL_SNI_QUERY>(
            HttpServiceConfigSslSniCertInfo,
            |q, token| {
                q.QueryDesc = HttpServiceConfigQueryNext;
                q.dwToken = token;
            },
            |buf| {
                let set = &*(buf.as_ptr() as *const HTTP_SERVICE_CONFIG_SSL_SNI_SET);
                let port = u16::from_be((*(&set.KeyDesc.IpPort as *const _ as *const SOCKADDR_IN)).sin_port);
                let host = super::pw(set.KeyDesc.Host);
                Binding { label: format!("HTTPS {}:{}", if host.is_empty() { "*".to_string() } else { host }, port), thumbprint: hash_text(&set.ParamDesc) }
            },
        );
        let _ = HttpTerminate(HTTP_INITIALIZE_CONFIG, None);
        match (ip, sni) {
            (Ok(mut a), Ok(b)) => {
                a.extend(b);
                (a, None)
            }
            (Ok(a), Err(rc)) => (a, Some(format!("HTTP.sys host name bindings could not be read (error {})", rc))),
            (Err(rc), Ok(b)) => (b, Some(format!("HTTP.sys bindings could not be read (error {})", rc))),
            (Err(rc), Err(_)) => (Vec::new(), Some(format!("HTTP.sys bindings could not be read (error {})", rc))),
        }
    }
}

pub fn rdp_hash() -> Option<String> {
    let key = reg::open(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")?;
    let (kind, data) = reg::raw(&key, "SSLCertificateSHA1Hash")?;
    if kind == reg::REG_BINARY && data.len() == 20 {
        Some(hex_upper(&data))
    } else {
        None
    }
}

pub fn list() -> CertsData {
    let mut data = CertsData::default();
    for (name, _) in STORES {
        let Some(store) = open_store(name) else { continue };
        for_each_cert(&store, |ctx| data.rows.push(row_of(name, ctx)));
    }
    let (bindings, note) = http_bindings();
    if let Some(n) = note {
        data.notes.push(n);
    }
    for b in &bindings {
        let mut hit = false;
        for r in data.rows.iter_mut().filter(|r| !b.thumbprint.is_empty() && r.thumbprint == b.thumbprint) {
            r.bindings.push(b.label.clone());
            hit = true;
        }
        if !hit {
            data.notes.push(format!("{} is bound to {} which is not in the machine stores Keyhole reads", b.label, if b.thumbprint.is_empty() { "an empty hash".to_string() } else { b.thumbprint.clone() }));
        }
    }
    let rdp = rdp_hash();
    let rdp_target: Option<usize> = match &rdp {
        Some(h) => data.rows.iter().position(|r| &r.thumbprint == h),
        None => data.rows.iter().position(|r| r.store_id == "Remote Desktop" && r.self_signed),
    };
    if let Some(i) = rdp_target {
        data.rows[i].bindings.push("Remote Desktop".to_string());
    }
    for r in &mut data.rows {
        r.bindings.sort();
        r.bindings.dedup();
    }
    data.rows.sort_by(|a, b| a.not_after_ms.cmp(&b.not_after_ms).then_with(|| a.subject.cmp(&b.subject)));
    data
}

pub fn find_encoded(thumbprint: &str) -> Option<Vec<u8>> {
    let want = thumbprint.to_uppercase();
    for (name, _) in STORES {
        let Some(store) = open_store(name) else { continue };
        let mut found = None;
        for_each_cert(&store, |ctx| {
            if found.is_none() && property(ctx, CERT_HASH_PROP_ID).map(|b| hex_upper(&b) == want).unwrap_or(false) {
                unsafe {
                    found = Some(std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize).to_vec());
                }
            }
        });
        if found.is_some() {
            return found;
        }
    }
    None
}

pub fn export_cer(thumbprint: &str, path: &Path) -> Result<(), String> {
    let der = find_encoded(thumbprint).ok_or_else(|| format!("No certificate with thumbprint {} in the machine stores", thumbprint))?;
    std::fs::write(path, der).map_err(|e| format!("Could not write {}: {}", path.display(), e))
}

pub fn summary(r: &CertRow) -> String {
    let mut s = format!("Subject: {}\nIssuer: {}\nValid: {} to {}\nThumbprint: {}\nSerial: {}\nStore: {}\nKey: {}", r.subject, r.issuer, super::local_time_text(r.not_before_ms), super::local_time_text(r.not_after_ms), r.thumbprint, r.serial, r.store, if r.has_private_key { format!("{} {} bits, private key present", r.key_algorithm, r.key_bits) } else { format!("{} {} bits, no private key", r.key_algorithm, r.key_bits) });
    if !r.friendly.is_empty() {
        s.push_str(&format!("\nFriendly name: {}", r.friendly));
    }
    if !r.eku.is_empty() {
        s.push_str(&format!("\nEnhanced key usage: {}", r.eku.join(", ")));
    }
    if !r.sans.is_empty() {
        s.push_str(&format!("\nSubject alternative names: {}", r.sans.join(", ")));
    }
    if !r.template.is_empty() {
        s.push_str(&format!("\nTemplate: {}", r.template));
    }
    if !r.bindings.is_empty() {
        s.push_str(&format!("\nBound to: {}", r.bindings.join(", ")));
    }
    if r.self_signed {
        s.push_str("\nSelf-signed");
    }
    s
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ImportReport {
    pub store: String,
    pub added: Vec<String>,
    pub skipped: Vec<String>,
}

impl ImportReport {
    pub fn text(&self) -> String {
        match (self.added.len(), self.skipped.len()) {
            (0, 0) => format!("Nothing to import into {}", self.store),
            (1, 0) => format!("Imported {} into {}", self.added[0], self.store),
            (n, 0) => format!("Imported {} certificates into {}", n, self.store),
            (0, s) => format!("{} already in {}", if s == 1 { self.skipped[0].clone() } else { format!("All {} certificates were", s) }, self.store),
            (n, s) => format!("Imported {} into {}, {} already there", n, self.store, s),
        }
    }
}

fn crypt_err(e: &windows::core::Error) -> String {
    match e.code().0 as u32 {
        0x80070056 | 0x80092007 => "the password is wrong".into(),
        0x80092009 => "the file is not a certificate, PKCS #7 bundle or PFX".into(),
        0x8009000B => "the key could not be decrypted with that password".into(),
        0x80092005 => "the certificate already exists in that store".into(),
        _ => super::winerr::describe(e),
    }
}

pub fn import_file(path: &Path, store_id: &str, password: &str, exportable: bool) -> Result<ImportReport, String> {
    use windows::Win32::Security::Cryptography::{
        CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED, CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT,
        CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE, CERT_QUERY_CONTENT_TYPE_FLAGS, CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE, CERT_STORE_ADD_NEW,
        CRYPT_EXPORTABLE, CRYPT_INTEGER_BLOB, CRYPT_KEY_FLAGS, CRYPT_MACHINE_KEYSET, CertAddCertificateContextToStore, CertFreeCertificateContext, CryptQueryObject,
        PFXImportCertStore, PFXIsPFXBlob, PKCS12_INCLUDE_EXTENDED_PROPERTIES,
    };
    use windows::core::PCWSTR;
    if !STORES.iter().any(|(id, _)| *id == store_id) {
        return Err(format!("unknown certificate store {}", store_id));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {}: {}", path.display(), e))?;
    if bytes.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    let dest = open_store_writable(store_id)?;
    let mut report = ImportReport { store: store_label(store_id).to_string(), ..Default::default() };
    let mut add = |ctx: *const CERT_CONTEXT| {
        let name = name_string(ctx, 0);
        let name = if name.is_empty() { property(ctx, CERT_HASH_PROP_ID).map(|b| hex_upper(&b)).unwrap_or_default() } else { name };
        match unsafe { CertAddCertificateContextToStore(Some(dest.0), ctx, CERT_STORE_ADD_NEW, None) } {
            Ok(()) => report.added.push(name),
            Err(e) if e.code().0 as u32 == 0x80092005 => report.skipped.push(name),
            Err(e) => return Err(format!("could not add {}: {}", name, crypt_err(&e))),
        }
        Ok(())
    };
    unsafe {
        let blob = CRYPT_INTEGER_BLOB { cbData: bytes.len() as u32, pbData: bytes.as_ptr() as *mut u8 };
        if PFXIsPFXBlob(&blob).as_bool() {
            let pw = super::SecretWide::new(password);
            let mut flags = CRYPT_KEY_FLAGS(CRYPT_MACHINE_KEYSET.0 | PKCS12_INCLUDE_EXTENDED_PROPERTIES.0);
            if exportable {
                flags = CRYPT_KEY_FLAGS(flags.0 | CRYPT_EXPORTABLE.0);
            }
            let imported = PFXImportCertStore(&blob, PCWSTR(pw.0.as_ptr()), flags);
            drop(pw);
            let source = imported.map_err(|e| format!("could not open the PFX: {}", crypt_err(&e)))?;
            let source = Store(source);
            let mut failure = None;
            for_each_cert(&source, |ctx| {
                if failure.is_none()
                    && let Err(e) = add(ctx) {
                        failure = Some(e);
                    }
            });
            if let Some(e) = failure {
                return Err(e);
            }
            return Ok(report);
        }
        let w = wide(&path.to_string_lossy());
        let mut hstore = HCERTSTORE::default();
        let mut hmsg: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut context: *mut std::ffi::c_void = std::ptr::null_mut();
        let expected = CERT_QUERY_CONTENT_TYPE_FLAGS(
            CERT_QUERY_CONTENT_FLAG_CERT.0 | CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE.0 | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT.0 | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED.0 | CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED.0,
        );
        CryptQueryObject(CERT_QUERY_OBJECT_FILE, w.as_ptr() as *const _, expected, CERT_QUERY_FORMAT_FLAG_ALL, 0, None, None, None, Some(&mut hstore), Some(&mut hmsg), Some(&mut context))
            .map_err(|e| format!("{} is not a certificate Keyhole can import ({}). Use a .cer, .crt, .pem, .p7b, .sst or .pfx file", path.display(), crypt_err(&e)))?;
        if !hmsg.is_null() {
            let _ = windows::Win32::Security::Cryptography::CryptMsgClose(Some(hmsg));
        }
        let mut failure = None;
        let source = if hstore.0.is_null() { None } else { Some(Store(hstore)) };
        if !context.is_null() {
            let ctx = context as *const CERT_CONTEXT;
            failure = add(ctx).err();
            let _ = CertFreeCertificateContext(Some(ctx));
        } else if let Some(source) = &source {
            for_each_cert(source, |ctx| {
                if failure.is_none()
                    && let Err(e) = add(ctx) {
                        failure = Some(e);
                    }
            });
        } else {
            return Err(format!("{} holds no certificates", path.display()));
        }
        if let Some(e) = failure {
            return Err(e);
        }
    }
    Ok(report)
}

fn hash_bytes(thumbprint: &str) -> Result<Vec<u8>, String> {
    let clean: String = thumbprint.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 40 {
        return Err(format!("{} is not a SHA-1 thumbprint", thumbprint));
    }
    (0..40).step_by(2).map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| format!("{} is not a SHA-1 thumbprint", thumbprint))).collect()
}

pub fn remove(thumbprint: &str, store_id: &str) -> Result<(), String> {
    use windows::Win32::Security::Cryptography::{CERT_FIND_HASH, CRYPT_INTEGER_BLOB, CertDeleteCertificateFromStore, CertFindCertificateInStore};
    let hash = hash_bytes(thumbprint)?;
    let store = open_store_writable(store_id)?;
    unsafe {
        let blob = CRYPT_INTEGER_BLOB { cbData: hash.len() as u32, pbData: hash.as_ptr() as *mut u8 };
        let ctx = CertFindCertificateInStore(store.0, ENCODING, 0, CERT_FIND_HASH, Some(&blob as *const _ as *const _), None);
        if ctx.is_null() {
            return Err(format!("no certificate with thumbprint {} in the {} store", thumbprint, store_label(store_id)));
        }
        CertDeleteCertificateFromStore(ctx).map_err(|e| format!("could not remove the certificate: {}", crypt_err(&e)))
    }
}
