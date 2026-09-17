use crate::sys::{from_wide, wide};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::core::PCWSTR;

#[derive(Clone, Default)]
pub struct VersionInfo {
    pub version: String,
    pub company: String,
    pub description: String,
    pub product: String,
}

pub struct VersionCache {
    map: Mutex<HashMap<String, VersionInfo>>,
}

impl Default for VersionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionCache {
    pub fn new() -> Self {
        VersionCache { map: Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, path: &str) -> VersionInfo {
        if path.is_empty() {
            return VersionInfo::default();
        }
        let key = path.to_lowercase();
        if let Some(v) = self.map.lock().get(&key) {
            return v.clone();
        }
        let v = read(path);
        let mut map = self.map.lock();
        if map.len() > 50_000 {
            map.clear();
        }
        map.insert(key, v.clone());
        v
    }
}

pub fn read(path: &str) -> VersionInfo {
    if path.is_empty() {
        return VersionInfo::default();
    }
    let wpath = wide(path);
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wpath.as_ptr()), None) };
    if size == 0 {
        return VersionInfo::default();
    }
    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        GetFileVersionInfoW(PCWSTR(wpath.as_ptr()), None, size, buf.as_mut_ptr() as *mut c_void)
    }
    .is_ok();
    if !ok {
        return VersionInfo::default();
    }

    let mut codepages: Vec<String> = Vec::new();
    unsafe {
        let mut lang_ptr: *mut c_void = std::ptr::null_mut();
        let mut lang_len = 0u32;
        let lang_query = wide("\\VarFileInfo\\Translation");
        if VerQueryValueW(buf.as_ptr() as *const c_void, PCWSTR(lang_query.as_ptr()), &mut lang_ptr, &mut lang_len).as_bool()
            && lang_len >= 4
            && !lang_ptr.is_null()
        {
            let pairs = lang_len as usize / 4;
            for i in 0..pairs {
                let lang = *((lang_ptr as *const u16).add(i * 2));
                let cp = *((lang_ptr as *const u16).add(i * 2 + 1));
                codepages.push(format!("{:04x}{:04x}", lang, cp));
            }
        }
    }
    for fallback in ["040904b0", "040904e4", "00000000", "04090000"] {
        if !codepages.iter().any(|c| c == fallback) {
            codepages.push(fallback.to_string());
        }
    }

    let field = |name: &str| -> String {
        for cp in &codepages {
            let v = query_string(&buf, cp, name);
            if !v.trim().is_empty() {
                return v.trim().to_string();
            }
        }
        String::new()
    };
    VersionInfo {
        version: field("FileVersion"),
        company: field("CompanyName"),
        description: field("FileDescription"),
        product: field("ProductName"),
    }
}

fn query_string(buf: &[u8], codepage: &str, field: &str) -> String {
    let query = wide(&format!("\\StringFileInfo\\{}\\{}", codepage, field));
    let mut ptr: *mut c_void = std::ptr::null_mut();
    let mut len = 0u32;
    unsafe {
        if VerQueryValueW(buf.as_ptr() as *const c_void, PCWSTR(query.as_ptr()), &mut ptr, &mut len).as_bool()
            && len > 0
            && !ptr.is_null()
        {
            let slice = std::slice::from_raw_parts(ptr as *const u16, len as usize);
            return from_wide(slice);
        }
    }
    String::new()
}
