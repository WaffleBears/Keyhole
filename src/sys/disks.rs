use crate::sys::wide;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::c_void;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetLogicalDrives, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
    STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY, StorageDeviceProperty, VOLUME_DISK_EXTENTS,
};
use windows::core::PCWSTR;

#[derive(Clone, Default, serde::Serialize)]
pub struct DiskInfo {
    pub number: u32,
    pub model: String,
    pub bus: String,
    pub letters: Vec<String>,
    pub size: u64,
    pub removable: bool,
}

static CACHE: Mutex<Option<(HashMap<u32, DiskInfo>, Instant)>> = Mutex::new(None);
const TTL: Duration = Duration::from_secs(60);

pub fn map() -> HashMap<u32, DiskInfo> {
    let mut cache = CACHE.lock();
    if let Some((m, at)) = cache.as_ref()
        && at.elapsed() < TTL {
            return m.clone();
        }
    let fresh = build();
    *cache = Some((fresh.clone(), Instant::now()));
    fresh
}

fn open_raw(path: &str) -> Option<HANDLE> {
    let w = wide(path);
    unsafe {
        for access in [windows::Win32::Foundation::GENERIC_READ.0, 0u32] {
            if let Ok(h) = CreateFileW(PCWSTR(w.as_ptr()), access, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, Default::default(), None) {
                return Some(h);
            }
        }
        None
    }
}

fn bus_name(t: i32) -> &'static str {
    match t {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        4 => "IEEE 1394",
        5 => "SSA",
        6 => "Fibre Channel",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD",
        13 => "MMC",
        14 => "Virtual",
        15 => "File-backed virtual",
        16 => "Storage Spaces",
        17 => "NVMe",
        18 => "SCM",
        19 => "UFS",
        _ => "",
    }
}

fn describe(number: u32) -> Option<DiskInfo> {
    let h = open_raw(&format!("\\\\.\\PhysicalDrive{}", number))?;
    let mut info = DiskInfo { number, ..Default::default() };
    unsafe {
        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut buf = vec![0u8; 4096];
        let mut returned = 0u32;
        let ok = DeviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const c_void),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            Some(&mut returned),
            None,
        )
        .is_ok();
        if ok && returned as usize >= std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            let d = &*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR);
            let text_at = |off: u32| -> String {
                if off == 0 || off as usize >= buf.len() {
                    return String::new();
                }
                let bytes = &buf[off as usize..];
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..end]).trim().to_string()
            };
            let vendor = text_at(d.VendorIdOffset);
            let product = text_at(d.ProductIdOffset);
            info.model = format!("{} {}", vendor, product).split_whitespace().collect::<Vec<_>>().join(" ");
            info.bus = bus_name(d.BusType.0).to_string();
            info.removable = d.RemovableMedia;
        }
        let mut len = [0u8; 8];
        let mut got = 0u32;
        if DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, None, 0, Some(len.as_mut_ptr() as *mut c_void), 8, Some(&mut got), None).is_ok() {
            info.size = u64::from_le_bytes(len);
        }
        let _ = CloseHandle(h);
    }
    if info.model.is_empty() {
        info.model = format!("Disk {}", number);
    }
    Some(info)
}

fn build() -> HashMap<u32, DiskInfo> {
    let mut out: HashMap<u32, DiskInfo> = HashMap::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = format!("{}:", (b'A' + i as u8) as char);
        let root = wide(&format!("{}\\", letter));
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
        if drive_type != 3 && drive_type != 2 {
            continue;
        }
        let Some(h) = open_raw(&format!("\\\\.\\{}", letter)) else { continue };
        let mut buf = vec![0u8; 4096];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 0, Some(buf.as_mut_ptr() as *mut c_void), buf.len() as u32, Some(&mut returned), None).is_ok()
        };
        unsafe {
            let _ = CloseHandle(h);
        }
        if !ok {
            continue;
        }
        if (returned as usize) < std::mem::size_of::<VOLUME_DISK_EXTENTS>() {
            continue;
        }
        let extents = unsafe { &*(buf.as_ptr() as *const VOLUME_DISK_EXTENTS) };
        let room = (returned as usize - 8) / std::mem::size_of::<windows::Win32::System::Ioctl::DISK_EXTENT>();
        let count = (extents.NumberOfDiskExtents as usize).min(room);
        let first = std::ptr::addr_of!(extents.Extents) as *const windows::Win32::System::Ioctl::DISK_EXTENT;
        for e in 0..count.min(32) {
            let ext = unsafe { &*first.add(e) };
            let n = ext.DiskNumber;
            let entry = out.entry(n).or_insert_with(|| describe(n).unwrap_or(DiskInfo { number: n, model: format!("Disk {}", n), ..Default::default() }));
            if !entry.letters.contains(&letter) {
                entry.letters.push(letter.clone());
            }
        }
    }
    for n in 0..16u32 {
        if !out.contains_key(&n)
            && let Some(d) = describe(n) {
                out.insert(n, d);
            }
    }
    for d in out.values_mut() {
        d.letters.sort();
    }
    out
}

pub fn label(info: &DiskInfo) -> String {
    let mut s = format!("Disk {}", info.number);
    if !info.model.is_empty() && info.model != s {
        s.push_str(&format!(" · {}", info.model));
    }
    s
}

pub fn detail(info: &DiskInfo) -> String {
    let mut parts = Vec::new();
    if !info.letters.is_empty() {
        parts.push(info.letters.join(", "));
    }
    if !info.bus.is_empty() {
        parts.push(info.bus.to_string());
    }
    if info.size > 0 {
        parts.push(fmt_bytes(info.size));
    }
    if info.removable {
        parts.push("removable".into());
    }
    parts.join(" · ")
}

pub fn fmt_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i > 0 && v < 10.0 { format!("{:.1} {}", v, units[i]) } else { format!("{:.0} {}", v, units[i]) }
}
