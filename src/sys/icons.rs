use crate::sys::wide;
use parking_lot::Mutex;
use std::collections::HashMap;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC,
    GetDIBits, GetObjectW, ReleaseDC,
};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::UI::Shell::{
    SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW,
};
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};
use windows::core::PCWSTR;

pub struct IconCache {
    by_path: Mutex<HashMap<String, u32>>,
    data: Mutex<Vec<Vec<u8>>>,
}

impl Default for IconCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IconCache {
    pub fn new() -> Self {
        let generic = extract_png("application.exe", true).unwrap_or_default();
        IconCache {
            by_path: Mutex::new(HashMap::new()),
            data: Mutex::new(vec![Vec::new(), generic]),
        }
    }

    fn generic_id(&self) -> u32 {
        let mut data = self.data.lock();
        if data[1].is_empty() {
            data[1] = extract_png("application.exe", true).unwrap_or_default();
        }
        if data[1].is_empty() { 0 } else { 1 }
    }

    pub fn id_for(&self, path: &str) -> u32 {
        if path.is_empty() || !super::local_path(path) {
            return self.generic_id();
        }
        let key = path.to_lowercase();
        if let Some(id) = self.by_path.lock().get(&key) {
            return *id;
        }
        let encoded = extract_png(path, false).unwrap_or_default();
        let mut by_path = self.by_path.lock();
        if let Some(id) = by_path.get(&key) {
            return *id;
        }
        let id = if encoded.is_empty() {
            self.generic_id()
        } else {
            let mut data = self.data.lock();
            data.push(encoded);
            (data.len() - 1) as u32
        };
        by_path.insert(key, id);
        id
    }

    pub fn take_new(&self, since: usize) -> (Vec<(u32, Vec<u8>)>, usize) {
        let data = self.data.lock();
        let mut out = Vec::new();
        for i in since.max(1)..data.len() {
            if !data[i].is_empty() {
                out.push((i as u32, data[i].clone()));
            }
        }
        (out, data.len())
    }

    pub fn len(&self) -> usize {
        self.data.lock().len()
    }
}

fn extract_png(path: &str, by_attributes: bool) -> Option<Vec<u8>> {
    unsafe {
        let wpath = wide(path);
        let mut info = SHFILEINFOW::default();
        let flags = if by_attributes {
            SHGFI_ICON | SHGFI_LARGEICON | SHGFI_USEFILEATTRIBUTES
        } else {
            SHGFI_ICON | SHGFI_LARGEICON
        };
        let r = SHGetFileInfoW(
            PCWSTR(wpath.as_ptr()),
            if by_attributes { FILE_ATTRIBUTE_NORMAL } else { Default::default() },
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            flags,
        );
        if r == 0 || info.hIcon.is_invalid() {
            return None;
        }
        let png = icon_to_png(info.hIcon);
        let _ = DestroyIcon(info.hIcon);
        png
    }
}

fn icon_to_png(icon: HICON) -> Option<Vec<u8>> {
    unsafe {
        let mut ii = ICONINFO::default();
        if GetIconInfo(icon, &mut ii).is_err() {
            return None;
        }
        let color = ii.hbmColor;
        if color.is_invalid() {
            if !ii.hbmMask.is_invalid() {
                let _ = DeleteObject(ii.hbmMask.into());
            }
            return None;
        }

        let mut bm = BITMAP::default();
        let got = GetObjectW(
            color.into(),
            std::mem::size_of::<BITMAP>() as i32,
            Some(&mut bm as *mut BITMAP as *mut _),
        );
        let (w, h) = if got == 0 || bm.bmWidth <= 0 || bm.bmHeight == 0 { (32i32, 32i32) } else { (bm.bmWidth.clamp(8, 256), bm.bmHeight.abs().clamp(8, 256)) };
        let hdc = GetDC(Some(HWND::default()));
        let header = |height: i32| BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        };
        let mut bmi = BITMAPINFO::default();
        bmi.bmiHeader = header(h);
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        let scanned = GetDIBits(hdc, color, 0, h as u32, Some(pixels.as_mut_ptr() as *mut _), &mut bmi, DIB_RGB_COLORS);
        let mut mask: Option<Vec<u8>> = None;
        if scanned != 0 && !ii.hbmMask.is_invalid() {
            let mut mbmi = BITMAPINFO::default();
            mbmi.bmiHeader = header(h);
            let mut mp = vec![0u8; (w * h * 4) as usize];
            if GetDIBits(hdc, ii.hbmMask, 0, h as u32, Some(mp.as_mut_ptr() as *mut _), &mut mbmi, DIB_RGB_COLORS) != 0 {
                mask = Some(mp);
            }
        }
        ReleaseDC(Some(HWND::default()), hdc);
        let _ = DeleteObject(ii.hbmColor.into());
        if !ii.hbmMask.is_invalid() {
            let _ = DeleteObject(ii.hbmMask.into());
        }
        if scanned == 0 {
            return None;
        }

        let mut opaque = false;
        for px in pixels.as_chunks_mut::<4>().0 {
            px.swap(0, 2);
            if px[3] != 0 {
                opaque = true;
            }
        }
        if !opaque {
            match mask {
                Some(m) => {
                    for (px, mp) in pixels.as_chunks_mut::<4>().0.iter_mut().zip(m.as_chunks::<4>().0) {
                        px[3] = if mp[0] == 0 && mp[1] == 0 && mp[2] == 0 { 255 } else { 0 };
                    }
                }
                None => {
                    for px in pixels.as_chunks_mut::<4>().0 {
                        px[3] = 255;
                    }
                }
            }
        }
        let size = w;
        let pixels = if w == h { pixels } else {
            let side = w.min(h);
            let mut square = Vec::with_capacity((side * side * 4) as usize);
            for row in 0..side {
                let start = (row * w * 4) as usize;
                square.extend_from_slice(&pixels[start..start + (side * 4) as usize]);
            }
            square
        };
        let size = if w == h { size } else { w.min(h) };

        let mut out = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut out, size as u32, size as u32);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().ok()?;
            writer.write_image_data(&pixels).ok()?;
        }
        Some(out)
    }
}
