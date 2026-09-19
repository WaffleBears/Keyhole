use crate::sys::wide;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::{
    WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
};
use windows::core::PCWSTR;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Unchecked,
    Signed,
    Unsigned,
    Expired,
    Untrusted,
    Error,
}

impl Trust {
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Unchecked => "unchecked",
            Trust::Signed => "signed",
            Trust::Unsigned => "unsigned",
            Trust::Expired => "expired",
            Trust::Untrusted => "untrusted",
            Trust::Error => "error",
        }
    }
}

pub struct SignatureCache {
    map: Mutex<HashMap<String, Trust>>,
}

impl Default for SignatureCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureCache {
    pub fn new() -> Self {
        SignatureCache {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn peek(&self, path: &str) -> Option<Trust> {
        if path.is_empty() {
            return Some(Trust::Unchecked);
        }
        self.map.lock().get(&path.to_lowercase()).copied()
    }

    pub fn get(&self, path: &str) -> Trust {
        if path.is_empty() {
            return Trust::Unchecked;
        }
        let key = path.to_lowercase();
        if let Some(t) = self.map.lock().get(&key) {
            return *t;
        }
        let t = verify_trust(path);
        self.map.lock().insert(key, t);
        t
    }

    pub fn warm(&self, paths: &[String]) {
        let pending: Vec<String> = {
            let cache = self.map.lock();
            let mut seen = std::collections::HashSet::new();
            paths
                .iter()
                .filter(|p| !p.is_empty())
                .filter(|p| {
                    let k = p.to_lowercase();
                    seen.insert(k.clone()) && !cache.contains_key(&k)
                })
                .cloned()
                .collect()
        };
        if pending.is_empty() {
            return;
        }
        let workers = 8usize.min(pending.len());
        let chunk = pending.len().div_ceil(workers);
        std::thread::scope(|scope| {
            for part in pending.chunks(chunk) {
                scope.spawn(move || {
                    let mut local = Vec::with_capacity(part.len());
                    for p in part {
                        local.push((p.to_lowercase(), verify_trust(p)));
                    }
                    let mut cache = self.map.lock();
                    for (k, t) in local {
                        cache.insert(k, t);
                    }
                });
            }
        });
    }
}

fn verify_trust(path: &str) -> Trust {
    let embedded = verify_embedded(path);
    if embedded == Trust::Signed {
        return Trust::Signed;
    }
    if embedded == Trust::Unsigned
        && let Some(t) = verify_catalog(path) {
            return t;
        }
    embedded
}

fn verify_catalog(path: &str) -> Option<Trust> {
    verify_catalog_with(path, "SHA256").or_else(|| verify_catalog_with(path, "SHA1"))
}

fn verify_catalog_with(path: &str, algorithm: &str) -> Option<Trust> {
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::Foundation::CloseHandle;

    let wpath = wide(path);
    unsafe {
        let file = CreateFileW(
            PCWSTR(wpath.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()?;

        let mut hcatadmin = 0isize;
        let algo = wide(algorithm);
        if CryptCATAdminAcquireContext2(&mut hcatadmin, None, PCWSTR(algo.as_ptr()), None, None).is_err() {
            let _ = CloseHandle(file);
            return None;
        }

        let mut hash_len = 0u32;
        let _ = CryptCATAdminCalcHashFromFileHandle2(hcatadmin, file, &mut hash_len, None, None);
        if hash_len == 0 {
            let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
            let _ = CloseHandle(file);
            return None;
        }
        let mut hash = vec![0u8; hash_len as usize];
        if CryptCATAdminCalcHashFromFileHandle2(hcatadmin, file, &mut hash_len, Some(hash.as_mut_ptr()), None).is_err() {
            let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
            let _ = CloseHandle(file);
            return None;
        }
        let _ = CloseHandle(file);

        let member_tag: String = hash.iter().map(|b| format!("{:02X}", b)).collect();
        let mut result = None;
        let mut prev: isize = 0;
        for _ in 0..8 {
            let hcatinfo = CryptCATAdminEnumCatalogFromHash(hcatadmin, &hash, None, if prev == 0 { None } else { Some(&mut prev as *mut isize) });
            if hcatinfo == 0 {
                prev = 0;
                break;
            }
            let mut info = CATALOG_INFO {
                cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                ..Default::default()
            };
            if CryptCATCatalogInfoFromContext(hcatinfo, &mut info, 0).is_ok() {
                let cat_path = crate::sys::from_wide(&info.wszCatalogFile);
                result = verify_catalog_member(path, &cat_path, &member_tag);
            }
            prev = hcatinfo;
            if result.is_some() {
                break;
            }
        }
        if prev != 0 {
            let _ = CryptCATAdminReleaseCatalogContext(hcatadmin, prev, 0);
        }
        let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
        result
    }
}

fn verify_catalog_member(file: &str, catalog: &str, member_tag: &str) -> Option<Trust> {
    use windows::Win32::Security::WinTrust::WINTRUST_CATALOG_INFO;
    let wfile = wide(file);
    let wcat = wide(catalog);
    let wtag = wide(member_tag);
    let mut cat = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: PCWSTR(wcat.as_ptr()),
        pcwszMemberFilePath: PCWSTR(wfile.as_ptr()),
        pcwszMemberTag: PCWSTR(wtag.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: windows::Win32::Security::WinTrust::WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 { pCatalog: &mut cat },
        dwStateAction: WTD_STATEACTION_VERIFY,
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut c_void)
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut c_void);
    }
    match status {
        0 => Some(Trust::Signed),
        _ => None,
    }
}

fn verify_embedded(path: &str) -> Trust {
    let wpath = wide(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    match status as u32 {
        0 => Trust::Signed,
        0x800B0100 | 0x800B0003 => Trust::Unsigned,
        0x800B0101 => Trust::Expired,
        0x80092003 | 0x80070002 | 0x80070003 | 0x80070005 | 0x80070020 | 0x8007007B => Trust::Error,
        _ => Trust::Untrusted,
    }
}
