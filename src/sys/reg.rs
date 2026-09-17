use super::{from_wide, wide};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW,
    RegOpenKeyExW, RegQueryValueExW,
};
use windows::Win32::Foundation::ERROR_MORE_DATA;
use windows::core::{PCWSTR, PWSTR};

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;

pub struct Key(pub HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

pub fn open(root: HKEY, sub: &str) -> Option<Key> {
    open_with(root, sub, KEY_READ)
}

pub fn open_with(root: HKEY, sub: &str, sam: REG_SAM_FLAGS) -> Option<Key> {
    let wsub = wide(sub);
    let mut key = HKEY::default();
    unsafe {
        if RegOpenKeyExW(root, PCWSTR(wsub.as_ptr()), Some(0), sam, &mut key).is_ok() {
            Some(Key(key))
        } else {
            None
        }
    }
}

pub fn raw(key: &Key, name: &str) -> Option<(u32, Vec<u8>)> {
    let wv = wide(name);
    unsafe {
        let mut size = 0u32;
        let mut kind = REG_VALUE_TYPE(0);
        if RegQueryValueExW(key.0, PCWSTR(wv.as_ptr()), None, Some(&mut kind), None, Some(&mut size)).is_err() {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if size > 0
            && RegQueryValueExW(key.0, PCWSTR(wv.as_ptr()), None, Some(&mut kind), Some(buf.as_mut_ptr()), Some(&mut size)).is_err()
        {
            return None;
        }
        buf.truncate(size as usize);
        Some((kind.0, buf))
    }
}

pub fn decode_string(kind: u32, data: &[u8]) -> Option<String> {
    match kind {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            let words: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            if kind == REG_MULTI_SZ {
                let parts: Vec<String> = words
                    .split(|&c| c == 0)
                    .filter(|p| !p.is_empty())
                    .map(String::from_utf16_lossy)
                    .collect();
                Some(parts.join(";"))
            } else {
                Some(from_wide(&words))
            }
        }
        REG_DWORD if data.len() >= 4 => Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string()),
        _ => None,
    }
}

pub fn string(key: &Key, name: &str) -> Option<String> {
    let (kind, data) = raw(key, name)?;
    if kind != REG_SZ && kind != REG_EXPAND_SZ {
        return None;
    }
    let s = decode_string(kind, &data)?;
    if s.trim().is_empty() { None } else { Some(s) }
}

pub fn dword(key: &Key, name: &str) -> Option<u32> {
    let (kind, data) = raw(key, name)?;
    if kind == REG_DWORD && data.len() >= 4 {
        Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    } else {
        None
    }
}

pub fn string_at(root: HKEY, sub: &str, name: &str) -> Option<String> {
    string(&open(root, sub)?, name)
}

pub fn dword_at(root: HKEY, sub: &str, name: &str) -> Option<u32> {
    dword(&open(root, sub)?, name)
}

pub fn subkeys(key: &Key) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0u32;
    loop {
        let mut buf = vec![0u16; 512];
        let mut len = buf.len() as u32;
        let r = unsafe {
            RegEnumKeyExW(key.0, index, Some(PWSTR(buf.as_mut_ptr())), &mut len, None, None, None, None)
        };
        if r.is_err() {
            break;
        }
        index += 1;
        out.push(from_wide(&buf[..len as usize]));
    }
    out
}

pub fn values(key: &Key) -> Vec<(String, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut index = 0u32;
    let mut capacity = 65536usize;
    loop {
        let mut name = vec![0u16; 16384];
        let mut name_len = name.len() as u32;
        let mut kind = 0u32;
        let mut data = vec![0u8; capacity];
        let mut data_len = data.len() as u32;
        let r = unsafe {
            RegEnumValueW(
                key.0,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if r == ERROR_MORE_DATA && capacity < 64 << 20 {
            capacity = (data_len as usize + 1024).max(capacity * 2);
            continue;
        }
        if r.is_err() {
            break;
        }
        index += 1;
        data.truncate(data_len as usize);
        out.push((from_wide(&name[..name_len as usize]), kind, data));
    }
    out
}
