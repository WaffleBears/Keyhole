use std::cell::RefCell;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Shell::{DefSubclassProc, DragAcceptFiles, DragFinish, DragQueryFileW, HDROP, RemoveWindowSubclass, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::{ChangeWindowMessageFilterEx, MSGFLT_ALLOW, WM_DROPFILES, WM_NCDESTROY};

thread_local! {
    static HANDLER: RefCell<Option<Box<dyn Fn(String)>>> = const { RefCell::new(None) };
}
const WM_COPYGLOBALDATA: u32 = 0x0049;

pub fn install(hwnd: isize, on_drop: impl Fn(String) + 'static) {
    if hwnd == 0 {
        return;
    }
    HANDLER.with(|h| *h.borrow_mut() = Some(Box::new(on_drop)));
    let hwnd = HWND(hwnd as *mut std::ffi::c_void);
    unsafe {
        let _ = ChangeWindowMessageFilterEx(hwnd, WM_DROPFILES, MSGFLT_ALLOW, None);
        let _ = ChangeWindowMessageFilterEx(hwnd, WM_COPYGLOBALDATA, MSGFLT_ALLOW, None);
        DragAcceptFiles(hwnd, true);
        let _ = SetWindowSubclass(hwnd, Some(subclass_proc), 1, 0);
    }
}

unsafe extern "system" fn subclass_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM, _id: usize, _data: usize) -> LRESULT {
    unsafe {
        if msg == WM_NCDESTROY {
            let _ = RemoveWindowSubclass(hwnd, Some(subclass_proc), 1);
        }
        if msg == WM_DROPFILES {
            let drop = HDROP(wparam.0 as *mut std::ffi::c_void);
            let count = DragQueryFileW(drop, 0xFFFF_FFFF, None);
            if count > 0 {
                let mut buf = [0u16; 1024];
                let len = DragQueryFileW(drop, 0, Some(&mut buf));
                if len > 0 {
                    let path = String::from_utf16_lossy(&buf[..len as usize]);
                    let _ = slint::invoke_from_event_loop(move || {
                        HANDLER.with(|h| {
                            if let Some(cb) = h.borrow().as_ref() {
                                cb(path.clone());
                            }
                        });
                    });
                }
            }
            DragFinish(drop);
            return LRESULT(0);
        }
        DefSubclassProc(hwnd, msg, wparam, lparam)
    }
}
