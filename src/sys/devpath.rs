use super::{from_wide, strip_prefix_ci, wide};
use parking_lot::RwLock;
use std::sync::Arc;
use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
use windows::core::PCWSTR;

pub struct DeviceMap {
    entries: Vec<(String, String)>,
}

impl DeviceMap {
    pub fn build() -> Self {
        let mut entries: Vec<(String, String)> = Vec::new();
        unsafe {
            let mut buf = vec![0u16; 1024];
            let len = GetLogicalDriveStringsW(Some(&mut buf));
            if len > 0 && len as usize <= buf.len() {
                let mut start = 0usize;
                for i in 0..len as usize {
                    if buf[i] == 0 {
                        if i > start {
                            let drive = from_wide(&buf[start..i]);
                            let letter: String =
                                drive.trim_end_matches('\\').to_string();
                            let mut target = vec![0u16; 2048];
                            let wl = wide(&letter);
                            let n = QueryDosDeviceW(PCWSTR(wl.as_ptr()), Some(&mut target));
                            if n > 0 {
                                let dev = from_wide(&target);
                                if !dev.is_empty() {
                                    entries.push((dev, letter));
                                }
                            }
                        }
                        start = i + 1;
                    }
                }
            }
        }
        entries.push(("\\Device\\Mup".to_string(), "\\".to_string()));
        entries.push(("\\Device\\LanmanRedirector".to_string(), "\\".to_string()));
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        DeviceMap { entries }
    }

    pub fn translate(&self, nt_path: &str) -> String {
        if nt_path.is_empty() {
            return String::new();
        }
        for (dev, dos) in &self.entries {
            if let Some(rest) = strip_prefix_ci(nt_path, dev)
                && (rest.is_empty() || rest.starts_with('\\'))
            {
                if dos == "\\" {
                    return unc_from_redirector(rest.trim_start_matches('\\'));
                }
                return format!("{}{}", dos, rest);
            }
        }
        if let Some(rest) = strip_prefix_ci(nt_path, "\\??\\") {
            return rest.to_string();
        }
        if let Some(rest) = strip_prefix_ci(nt_path, "\\SystemRoot") {
            return format!("{}{}", super::system_root(), rest);
        }
        nt_path.to_string()
    }
}

#[derive(Clone)]
pub struct SharedDeviceMap(Arc<RwLock<Arc<DeviceMap>>>);

impl Default for SharedDeviceMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedDeviceMap {
    pub fn new() -> Self {
        SharedDeviceMap(Arc::new(RwLock::new(Arc::new(DeviceMap::build()))))
    }

    pub fn get(&self) -> Arc<DeviceMap> {
        self.0.read().clone()
    }

    pub fn refresh(&self) {
        let fresh = Arc::new(DeviceMap::build());
        *self.0.write() = fresh;
    }
}

pub fn unc_from_redirector(rest: &str) -> String {
    let mut body = rest;
    if let Some(after) = body.strip_prefix(';') {
        let mut segs = after.splitn(2, '\\');
        let _provider = segs.next();
        body = segs.next().unwrap_or("");
        if let Some(mapped) = body.strip_prefix(';') {
            let mut parts = mapped.splitn(2, '\\');
            let tag = parts.next().unwrap_or("");
            let remainder = parts.next().unwrap_or("");
            let letter = tag.get(..2).filter(|l| l.as_bytes()[1] == b':' && l.as_bytes()[0].is_ascii_alphabetic());
            if let Some(letter) = letter {
                let mut server_share = remainder.splitn(3, '\\');
                let _server = server_share.next();
                let _share = server_share.next();
                let tail = server_share.next().unwrap_or("");
                return format!("{}\\{}", letter.to_uppercase(), tail);
            }
            body = remainder;
        }
    }
    format!("\\\\{}", body)
}
