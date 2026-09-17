#![windows_subsystem = "windows"]

slint::include_modules!();

mod gui;

use keyhole::state::App;
use keyhole::sys::{privilege, wide};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW};
use windows::core::PCWSTR;

fn main() {
    install_panic_log();
    let args: Vec<String> = std::env::args().collect();

    if !privilege::is_elevated() {
        warn_box("Keyhole must run as administrator to inspect every process, handle and kernel trace.\n\nRight-click keyhole.exe and choose Run as administrator, or start it from an elevated prompt.");
        return;
    }

    let software = args.iter().any(|a| a == "--software-render") || std::env::var("KEYHOLE_RENDERER").map(|v| v == "software").unwrap_or(false);
    if select_renderer(software).is_err() && !software {
        relaunch_with_software_renderer(&args);
        return;
    }

    let app = App::new();
    app.refresh_tree();
    if let Err(e) = app.activity.start() {
        eprintln!("activity tracing unavailable: {}", e);
    }
    if let Err(e) = gui::run(app.clone()) {
        app.activity.stop();
        if software {
            warn_box(&format!("Keyhole could not open its window.\n\n{}", e));
        } else {
            relaunch_with_software_renderer(&args);
        }
    }
}

fn select_renderer(software: bool) -> Result<(), slint::PlatformError> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name(if software { "software".into() } else { "skia".into() })
        .select()
}

fn relaunch_with_software_renderer(args: &[String]) {
    let Ok(exe) = std::env::current_exe() else { return };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args.iter().skip(1).filter(|a| *a != "--software-render"));
    cmd.arg("--software-render");
    let _ = cmd.spawn();
}

fn warn_box(message: &str) {
    let text = wide(message);
    let title = wide("Keyhole");
    unsafe {
        MessageBoxW(None, PCWSTR(text.as_ptr()), PCWSTR(title.as_ptr()), MB_OK | MB_ICONWARNING);
    }
}

fn install_panic_log() {
    std::panic::set_hook(Box::new(|info| {
        let text = format!("{}\n{}\n", info, std::backtrace::Backtrace::force_capture());
        if let Some(base) = std::env::var_os("LOCALAPPDATA") {
            let dir = std::path::PathBuf::from(base).join("Keyhole");
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join("crash.log"), text);
        }
    }));
}
