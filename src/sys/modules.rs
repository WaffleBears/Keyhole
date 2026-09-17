use crate::model::ModuleRow;
use crate::sys::from_wide;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

pub fn list(pid: u32) -> Result<Vec<ModuleRow>, String> {
    if pid == 0 || pid == 4 {
        return Err("kernel process".into());
    }
    let h: HANDLE = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    }
    .map_err(|_| "cannot open process for module list".to_string())?;

    let mut needed = 0u32;
    let mut mods: Vec<HMODULE> = vec![HMODULE::default(); 1024];
    loop {
        let bytes = (mods.len() * std::mem::size_of::<HMODULE>()) as u32;
        let ok = unsafe {
            EnumProcessModulesEx(h, mods.as_mut_ptr(), bytes, &mut needed, LIST_MODULES_ALL)
        }
        .is_ok();
        if !ok {
            unsafe {
                let _ = CloseHandle(h);
            }
            return Err("module enumeration refused".into());
        }
        let count = needed as usize / std::mem::size_of::<HMODULE>();
        if count <= mods.len() {
            mods.truncate(count);
            break;
        }
        mods.resize(count + 64, HMODULE::default());
    }

    let mut out = Vec::with_capacity(mods.len());
    let mut name_buf = vec![0u16; 32768];
    for m in mods {
        let len = unsafe { GetModuleFileNameExW(Some(h), Some(m), &mut name_buf) };
        if len == 0 {
            continue;
        }
        let path = from_wide(&name_buf[..len as usize]);
        let mut info = MODULEINFO::default();
        let sized = unsafe {
            GetModuleInformation(
                h,
                m,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        }
        .is_ok();
        let name = path
            .rsplit('\\')
            .next()
            .unwrap_or(&path)
            .to_string();
        out.push(ModuleRow {
            name,
            path,
            base: info.lpBaseOfDll as u64,
            size: if sized { info.SizeOfImage as u64 } else { 0 },
            version: String::new(),
            company: String::new(),
        });
    }
    unsafe {
        let _ = CloseHandle(h);
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    Ok(out)
}

