use crate::sys::{from_wide, wide};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Controls::Dialogs::{GetOpenFileNameW, GetSaveFileNameW, OFN_FILEMUSTEXIST, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW};
use windows::core::{PCWSTR, PWSTR};

fn filter_for(ext: &str) -> Vec<u16> {
    let text = match ext {
        "csv" => "CSV file\0*.csv\0All files\0*.*\0\0",
        "txt" => "Text file\0*.txt\0All files\0*.*\0\0",
        "dmp" => "Memory dump\0*.dmp;*.mdmp;*.hdmp\0All files\0*.*\0\0",
        "json" => "JSON file\0*.json\0All files\0*.*\0\0",
        "cert" => "Certificates\0*.cer;*.crt;*.pem;*.der;*.p7b;*.p7c;*.sst;*.pfx;*.p12\0PFX with private key\0*.pfx;*.p12\0All files\0*.*\0\0",
        _ => "All files\0*.*\0\0",
    };
    text.encode_utf16().collect()
}

pub fn save_file(owner: isize, default_name: &str, ext: &str) -> Option<String> {
    let mut file = vec![0u16; 1024];
    let name = wide(default_name);
    let n = name.len().min(file.len() - 1);
    file[..n].copy_from_slice(&name[..n]);
    let filter = filter_for(ext);
    let ext_w = wide(ext);
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: HWND(owner as *mut std::ffi::c_void),
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrDefExt: PCWSTR(ext_w.as_ptr()),
        Flags: OFN_OVERWRITEPROMPT,
        ..Default::default()
    };
    let ok = unsafe { GetSaveFileNameW(&mut ofn) };
    if ok.as_bool() { Some(from_wide(&file)) } else { None }
}

pub fn open_file(owner: isize) -> Option<String> {
    open_file_titled(owner, "Pick a file to find what is holding it open", "")
}

pub fn open_file_titled(owner: isize, title: &str, ext: &str) -> Option<String> {
    let mut file = vec![0u16; 1024];
    let filter = filter_for(ext);
    let title = wide(title);
    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: HWND(owner as *mut std::ffi::c_void),
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
        ..Default::default()
    };
    let ok = unsafe { GetOpenFileNameW(&mut ofn) };
    if ok.as_bool() { Some(from_wide(&file)) } else { None }
}

pub fn set_clipboard(text: &str) -> Result<(), String> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows::Win32::Foundation::GlobalFree;
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    let data = wide(text);
    unsafe {
        OpenClipboard(None).map_err(|e| crate::sys::winerr::describe(&e))?;
        let result = (|| {
            EmptyClipboard().map_err(|e| crate::sys::winerr::describe(&e))?;
            let bytes = data.len() * 2;
            let mem = GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(|e| crate::sys::winerr::describe(&e))?;
            let ptr = GlobalLock(mem) as *mut u16;
            if ptr.is_null() {
                let _ = GlobalFree(Some(mem));
                return Err("could not lock clipboard memory".into());
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            let _ = GlobalUnlock(mem);
            if let Err(e) = SetClipboardData(13, Some(HANDLE(mem.0))) {
                let _ = GlobalFree(Some(mem));
                return Err(crate::sys::winerr::describe(&e));
            }
            Ok(())
        })();
        let _ = CloseClipboard();
        result
    }
}

pub fn pick_folder(owner: isize, title: &str) -> Option<String> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
    use windows::Win32::UI::Shell::{FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS, FileOpenDialog, IFileOpenDialog, SIGDN_FILESYSPATH};
    let _com = crate::sys::com::ComGuard::sta();
    let title_w = wide(title);
    unsafe {
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let options = dialog.GetOptions().unwrap_or_default();
        let _ = dialog.SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
        let _ = dialog.SetTitle(PCWSTR(title_w.as_ptr()));
        dialog.Show(Some(HWND(owner as *mut std::ffi::c_void))).ok()?;
        let item = dialog.GetResult().ok()?;
        let name = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let text = name.to_string().ok()?;
        CoTaskMemFree(Some(name.0 as *const std::ffi::c_void));
        Some(text)
    }
}
