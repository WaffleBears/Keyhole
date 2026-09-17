use windows::Win32::System::Com::{COINIT, COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};

static MTA_KEEPER: std::sync::Once = std::sync::Once::new();

fn keep_mta_alive() {
    MTA_KEEPER.call_once(|| {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let spawned = std::thread::Builder::new()
            .name("keyhole-com-mta".into())
            .spawn(move || {
                let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
                let _ = tx.send(());
                loop {
                    std::thread::park();
                }
            })
            .is_ok();
        if spawned {
            let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
        }
    });
}

pub struct ComGuard {
    owned: bool,
}

impl ComGuard {
    pub fn new(model: COINIT) -> ComGuard {
        keep_mta_alive();
        let hr = unsafe { CoInitializeEx(None, model) };
        ComGuard { owned: hr.is_ok() }
    }

    pub fn mta() -> ComGuard {
        ComGuard::new(COINIT_MULTITHREADED)
    }

    pub fn sta() -> ComGuard {
        ComGuard::new(COINIT_APARTMENTTHREADED)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owned {
            unsafe { CoUninitialize() };
        }
    }
}
