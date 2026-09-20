pub mod activity;
pub mod columns;
pub mod detail;
pub mod dialogs;
pub mod dragdrop;
pub mod dumpview;
pub mod export;
pub mod finder;
pub mod format;
pub mod kinds;
pub mod lists;
pub mod menus;
pub mod resources;
pub mod rows;
pub mod settings;
pub mod system;
pub mod tree;

use crate::{MainWindow, Tips, Ui};
use detail::load_detail;
use keyhole::api::{self, Action};
use keyhole::state::App;
use settings::Settings;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tree::apply_tree;

pub struct Ctx {
    pub app: Arc<App>,
    pub window: MainWindow,
    pub settings: RefCell<Settings>,
    pub st: RefCell<State>,
}

pub type Shared = Rc<Ctx>;

#[derive(Default)]
pub struct State {
    pub mode: String,
    pub ticks: u64,
    pub tree: tree::TreeState,
    pub lists: lists::ListState,
    pub activity: activity::ActivityState,
    pub resources: resources::ResourcesState,
    pub finder: finder::FinderState,
    pub dump: dumpview::DumpState,
    pub menu_actions: HashMap<String, Box<dyn FnOnce(&Shared)>>,
    pub dialog: Option<dialogs::DialogState>,
    pub toast_seq: i32,
    pub tip_timer: Option<slint::Timer>,
    pub tip_hide: Option<slint::Timer>,
    pub net_filter_timer: Option<slint::Timer>,
    pub tree_filter_timer: Option<slint::Timer>,
    pub detail_timer: Option<slint::Timer>,
    pub icons: HashMap<u32, slint::Image>,
    pub icon_count: usize,
    pub icons_pending: bool,
    pub user: String,
    pub last_menu_rect: (f32, f32),
}

thread_local! {
    static PENDING: RefCell<HashMap<u64, Box<dyn FnOnce(Option<Box<dyn Any>>)>>> = RefCell::new(HashMap::new());
    static TICK: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
}
static NEXT_JOB: AtomicU64 = AtomicU64::new(1);
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn spawn<T, W, D>(ctx: &Shared, work: W, done: D)
where
    T: Send + 'static,
    W: FnOnce(&App) -> T + Send + 'static,
    D: FnOnce(&Shared, T) + 'static,
{
    let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    let ctx2 = ctx.clone();
    PENDING.with(|p| {
        p.borrow_mut().insert(
            id,
            Box::new(move |v: Option<Box<dyn Any>>| match v {
                Some(v) => {
                    if let Ok(v) = v.downcast::<T>() {
                        done(&ctx2, *v);
                    }
                }
                None => {
                    {
                        let mut st = ctx2.st.borrow_mut();
                        st.lists.inflight = false;
                        st.lists.updates_installing = false;
                        st.resources.busy = false;
                        st.activity.busy = false;
                        st.tree.live_busy = false;
                    }
                    let u = ui(&ctx2);
                    u.set_list_loading(false);
                    u.set_detail_loading(false);
                    u.set_finder_loading(false);
                    u.set_dump_loading(false);
                    bad(&ctx2, "That failed unexpectedly inside Keyhole. Details are in %LOCALAPPDATA%\\Keyhole\\crash.log");
                }
            }),
        );
    });
    let app = ctx.app.clone();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&app)));
        let _ = slint::invoke_from_event_loop(move || {
            let cb = PENDING.with(|p| p.borrow_mut().remove(&id));
            if let Some(cb) = cb {
                match result {
                    Ok(v) => cb(Some(Box::new(v))),
                    Err(_) => cb(None),
                }
            }
        });
    });
}

pub fn ui(ctx: &Shared) -> Ui<'_> {
    ctx.window.global::<Ui>()
}

pub fn ss(s: &str) -> SharedString {
    SharedString::from(s)
}

pub fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

pub fn strings(items: &[String]) -> ModelRc<SharedString> {
    model(items.iter().map(|s| ss(s)).collect())
}

pub fn toast(ctx: &Shared, text: &str, kind: i32) {
    let id = {
        let mut st = ctx.st.borrow_mut();
        st.toast_seq += 1;
        st.toast_seq
    };
    let u = ui(ctx);
    let mut items: Vec<crate::Toast> = u.get_toasts().iter().collect();
    items.push(crate::Toast { id, text: ss(text), kind });
    u.set_toasts(model(items));
    let ctx2 = ctx.clone();
    slint::Timer::single_shot(std::time::Duration::from_millis(3600), move || {
        let u = ui(&ctx2);
        let items: Vec<crate::Toast> = u.get_toasts().iter().filter(|t| t.id != id).collect();
        u.set_toasts(model(items));
    });
}

pub fn good(ctx: &Shared, text: &str) {
    toast(ctx, text, 1);
}

pub fn bad(ctx: &Shared, text: &str) {
    toast(ctx, text, 2);
}

pub fn copy_text(ctx: &Shared, text: &str) {
    if text.is_empty() {
        return;
    }
    match keyhole::sys::dialogs::set_clipboard(text) {
        Ok(()) => good(ctx, "Copied"),
        Err(e) => bad(ctx, &format!("The clipboard refused the text: {}", e)),
    }
}

pub fn save_settings(ctx: &Shared) {
    ctx.settings.borrow().save();
}

fn save_placement(ctx: &Shared) {
    let w = ctx.window.window();
    let pos = w.position();
    let size = w.size();
    let placement = settings::WindowPlacement { x: pos.x, y: pos.y, width: size.width, height: size.height, maximized: w.is_maximized() };
    let mut s = ctx.settings.borrow_mut();
    s.window = Some(placement);
    s.tree_height = ui(ctx).get_tree_height();
    s.save();
}

fn restore_placement(ctx: &Shared) -> bool {
    let Some(p) = ctx.settings.borrow().window.clone() else { return false };
    if p.width < 400 || p.height < 300 {
        return false;
    }
    let rect = windows::Win32::Foundation::RECT { left: p.x, top: p.y, right: p.x + p.width as i32, bottom: p.y + p.height as i32 };
    let monitor = unsafe { windows::Win32::Graphics::Gdi::MonitorFromRect(&rect, windows::Win32::Graphics::Gdi::MONITOR_DEFAULTTONULL) };
    if monitor.is_invalid() {
        return false;
    }
    let w = ctx.window.window();
    w.set_position(slint::PhysicalPosition::new(p.x, p.y));
    w.set_size(slint::PhysicalSize::new(p.width, p.height));
    true
}

pub fn run(app: Arc<App>) -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    let settings = Settings::load();
    let ctx: Shared = Rc::new(Ctx { app, window, settings: RefCell::new(settings), st: RefCell::new(State::default()) });
    {
        let mut st = ctx.st.borrow_mut();
        st.mode = "processes".into();
        st.icon_count = 1;
        st.user = std::env::var("USERNAME").unwrap_or_default();
    }
    let u = ui(&ctx);
    u.set_window_title(ss("Keyhole"));
    sync_history(&ctx);
    {
        let s = ctx.settings.borrow();
        u.set_tree_flat(s.flat);
        u.set_named_only(s.named_only);
        u.set_tab(ss(&s.tab));
        u.set_tree_sort(ss(&s.sort));
        u.set_tree_desc(s.descending);
        u.set_rate_index(rate_index(s.rate_ms));
        u.set_tree_height(s.tree_height.max(120.0));
        ctx.app.set_refresh_interval_ms(s.rate_ms);
    }
    restore_placement(&ctx);

    wire_shell(&ctx);
    tree::wire(&ctx);
    lists::wire(&ctx);
    activity::wire(&ctx);
    system::wire(&ctx);
    finder::wire(&ctx);
    dumpview::wire(&ctx);
    menus::wire(&ctx);
    dialogs::wire(&ctx);
    detail::set_tabs(&ctx);

    {
        let ctx2 = ctx.clone();
        TICK.with(|t| *t.borrow_mut() = Some(Box::new(move || on_tick(&ctx2))));
    }
    start_sampler(&ctx);

    {
        let ctx2 = ctx.clone();
        ctx.window.window().on_close_requested(move || {
            SHUTTING_DOWN.store(true, Ordering::Relaxed);
            save_placement(&ctx2);
            ctx2.app.activity.stop();
            let _ = slint::quit_event_loop();
            slint::CloseRequestResponse::HideWindow
        });
    }

    tree::apply_tree(&ctx, keyhole::api::set_view(&ctx.app, current_view_change(&ctx)));
    tree::set_selected(&ctx, None);
    first_run_hint(&ctx);
    let maximize = ctx.settings.borrow().window.as_ref().map(|w| w.maximized).unwrap_or(true);
    slint::Timer::single_shot(std::time::Duration::from_millis(50), {
        let ctx2 = ctx.clone();
        move || {
            focus_keys(&ctx2);
            let ctx3 = ctx2.clone();
            dragdrop::install(window_hwnd(&ctx2), move |path| {
                if keyhole::sys::dumpan::looks_like_dump(&path) {
                    dumpview::open(&ctx3, &path);
                } else {
                    finder::on_drop(&ctx3, &path);
                }
            });
            dark_titlebar(window_hwnd(&ctx2));
        }
    });
    if maximize {
        slint::Timer::single_shot(std::time::Duration::from_millis(350), {
            let ctx2 = ctx.clone();
            move || maximize_window(&ctx2)
        });
    }
    ctx.window.run()?;
    SHUTTING_DOWN.store(true, Ordering::Relaxed);
    ctx.app.activity.stop();
    Ok(())
}

fn current_view_change(ctx: &Shared) -> keyhole::api::ViewChange {
    let s = ctx.settings.borrow();
    keyhole::api::ViewChange {
        sort: Some(keyhole::state::SortKey::parse(&s.sort)),
        descending: Some(s.descending),
        flat: Some(s.flat),
        filter: None,
    }
}

pub fn sync_history(ctx: &Shared) {
    let history = ctx.settings.borrow().history.clone();
    ui(ctx).set_search_history(strings(&history));
}

pub fn focus_keys(ctx: &Shared) {
    let u = ui(ctx);
    u.set_keys_focus_seq(u.get_keys_focus_seq() + 1);
}

const RATES: [u64; 6] = [500, 1000, 2000, 5000, 10000, 0];

fn rate_index(ms: u64) -> i32 {
    RATES.iter().position(|r| *r == ms).unwrap_or(1) as i32
}

fn start_sampler(ctx: &Shared) {
    let app = ctx.app.clone();
    std::thread::Builder::new()
        .name("keyhole-sampler".into())
        .spawn(move || {
            loop {
                let raw = app.refresh_interval_ms();
                std::thread::sleep(std::time::Duration::from_millis(if raw == 0 { 500 } else { raw.clamp(250, 60_000) }));
                if SHUTTING_DOWN.load(Ordering::Relaxed) {
                    break;
                }
                if app.refresh_interval_ms() == 0 {
                    continue;
                }
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| app.refresh_tree())).is_ok();
                if ok {
                    let _ = slint::invoke_from_event_loop(|| {
                        TICK.with(|t| {
                            if let Some(f) = t.borrow().as_ref() {
                                f();
                            }
                        });
                    });
                }
            }
        })
        .ok();
}

fn on_tick(ctx: &Shared) {
    let mode = ctx.st.borrow().mode.clone();
    let ticks = {
        let mut st = ctx.st.borrow_mut();
        st.ticks += 1;
        st.ticks
    };
    if mode == "processes" {
        tree::apply_tree(ctx, keyhole::api::tree(&ctx.app));
    }
    if mode == "events" {
        kinds::events::tick(ctx);
    }
    if ctx.app.paused.load(Ordering::Relaxed) {
        return;
    }
    let inflight = ctx.st.borrow().lists.inflight;
    match mode.as_str() {
        "activity" => activity::refresh_activity(ctx),
        "network" => activity::refresh_network(ctx),
        "resources" => resources::refresh_resources(ctx),
        "files" if ticks % 4 == 0 && !inflight => lists::refresh_current(ctx, false),
        "shares" if ticks % 3 == 0 && !inflight => lists::refresh_current(ctx, false),
        "services" | "sessions" if ticks % 2 == 0 && !inflight => lists::refresh_current(ctx, false),
        _ => {}
    }
    detail::maybe_live_detail(ctx);
}

fn wire_shell(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_set_mode(move |m| set_mode(&ctx, m.as_str()));
    }
    {
        let ctx = ctx.clone();
        u.on_window_resized(move || relayout(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_pause_clicked(move || {
            let paused = !ctx.app.paused.load(Ordering::Relaxed);
            keyhole::api::set_paused(&ctx.app, paused);
            update_pause_button(&ctx);
            tree::apply_tree(&ctx, keyhole::api::tree(&ctx.app));
            if !paused {
                kinds::events::resume(&ctx);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_rate_changed(move |i| {
            let ms = RATES.get(i as usize).copied().unwrap_or(1000);
            ctx.settings.borrow_mut().rate_ms = ms;
            save_settings(&ctx);
            keyhole::api::set_interval_ms(&ctx.app, ms);
            update_pause_button(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_refresh_clicked(move || refresh_current(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_export_clicked(move |x, y| export::export_menu(&ctx, x, y));
    }
    {
        let ctx = ctx.clone();
        u.on_help_clicked(move || dialogs::show_shortcuts(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_search_submitted(move |q| {
            let q = q.trim().trim_matches('"').to_string();
            if keyhole::sys::dumpan::looks_like_dump(&q) && std::path::Path::new(&q).is_file() {
                dumpview::open(&ctx, &q);
                return;
            }
            if !q.is_empty() {
                let subtree = ui(&ctx).get_finder_subtree();
                finder::run_search(&ctx, &q, subtree);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_history_picked(move |q| {
            ui(&ctx).set_search_text(q.clone());
            let subtree = ui(&ctx).get_finder_subtree();
            finder::run_search(&ctx, q.as_str(), subtree);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_browse_clicked(move || {
            if let Some(path) = keyhole::sys::dialogs::open_file(window_hwnd(&ctx)) {
                finder::on_drop(&ctx, &path);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_pill_clicked(move |id| {
            if id == "etw" {
                activity::toggle_tracing(&ctx);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_hint_close(move || ui(&ctx).set_hint_open(false));
    }
    {
        let ctx = ctx.clone();
        u.on_key_pressed(move |text, control, shift| on_key(&ctx, text.as_str(), control, shift));
    }
    let tips = ctx.window.global::<Tips>();
    {
        let ctx = ctx.clone();
        tips.on_hover(move |text, x, y| {
            let timer = slint::Timer::default();
            let ctx2 = ctx.clone();
            let text = text.clone();
            timer.start(slint::TimerMode::SingleShot, std::time::Duration::from_millis(550), move || {
                let t = ctx2.window.global::<Tips>();
                t.set_text(text.clone());
                t.set_x(x);
                t.set_y(y);
                t.set_shown(true);
                let ctx3 = ctx2.clone();
                let hide = slint::Timer::default();
                hide.start(slint::TimerMode::SingleShot, std::time::Duration::from_millis(12000), move || {
                    ctx3.window.global::<Tips>().set_shown(false);
                });
                ctx2.st.borrow_mut().tip_hide = Some(hide);
            });
            ctx.st.borrow_mut().tip_timer = Some(timer);
        });
    }
    {
        let ctx = ctx.clone();
        tips.on_leave(move || {
            ctx.st.borrow_mut().tip_timer = None;
            ctx.window.global::<Tips>().set_shown(false);
        });
    }
}

fn dark_titlebar(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    let enabled: i32 = 1;
    unsafe {
        let _ = windows::Win32::Graphics::Dwm::DwmSetWindowAttribute(
            windows::Win32::Foundation::HWND(hwnd as *mut std::ffi::c_void),
            windows::Win32::Graphics::Dwm::DWMWA_USE_IMMERSIVE_DARK_MODE,
            &enabled as *const i32 as *const std::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
        );
    }
}

fn maximize_window(ctx: &Shared) {
    ctx.window.window().set_maximized(true);
    if ctx.window.window().is_maximized() {
        return;
    }
    let hwnd = window_hwnd(ctx);
    if hwnd != 0 {
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::ShowWindow(windows::Win32::Foundation::HWND(hwnd as *mut std::ffi::c_void), windows::Win32::UI::WindowsAndMessaging::SW_MAXIMIZE);
        }
    }
}

pub fn window_hwnd(ctx: &Shared) -> isize {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match ctx.window.window().window_handle().window_handle() {
        Ok(h) => match h.as_raw() {
            RawWindowHandle::Win32(w) => w.hwnd.get(),
            _ => 0,
        },
        Err(_) => 0,
    }
}


pub fn update_pause_button(ctx: &Shared) {
    let paused = ctx.app.paused.load(Ordering::Relaxed);
    let manual = ctx.app.refresh_interval_ms() == 0;
    let u = ui(ctx);
    u.set_pause_label(ss(if paused { "Frozen" } else if manual { "Manual" } else { "Live" }));
    u.set_pause_dot(if paused || manual { 2 } else { 1 });
    u.set_pause_active(paused);
}

pub fn is_live(mode: &str) -> bool {
    matches!(mode, "processes" | "activity" | "network" | "resources" | "files" | "services" | "sessions" | "events" | "shares")
}

pub fn set_mode(ctx: &Shared, mode: &str) {
    if ctx.st.borrow().mode == mode {
        return;
    }
    ctx.st.borrow_mut().mode = mode.to_string();
    let u = ui(ctx);
    u.set_mode(ss(mode));
    u.set_live_view(is_live(mode));
    ctx.window.global::<Tips>().set_shown(false);
    match mode {
        "processes" => tree::apply_tree(ctx, keyhole::api::tree(&ctx.app)),
        "activity" => activity::enter_activity(ctx),
        "network" => activity::enter_network(ctx),
        "resources" => resources::enter_resources(ctx),
        "environment" => system::refresh_environment(ctx),
        _ => lists::enter(ctx, mode),
    }
    focus_keys(ctx);
}

pub fn refresh_current(ctx: &Shared) {
    let mode = ctx.st.borrow().mode.clone();
    match mode.as_str() {
        "processes" => {
            spawn(ctx, keyhole::api::refresh, move |ctx, view| {
                tree::apply_tree(ctx, view);
                detail::load_detail(ctx);
            });
        }
        "activity" => activity::refresh_activity(ctx),
        "network" => activity::refresh_network(ctx),
        "resources" => resources::refresh_resources(ctx),
        "environment" => system::refresh_environment(ctx),
        _ => lists::refresh_current(ctx, true),
    }
}

fn on_key(ctx: &Shared, text: &str, control: bool, shift: bool) -> bool {
    let u = ui(ctx);
    let key = text.chars().next().unwrap_or('\0');
    if key == char::from(slint::platform::Key::Escape) {
        if u.get_menu_open() {
            menus::close(ctx);
        } else if u.get_shortcuts_open() {
            u.set_shortcuts_open(false);
        } else if u.get_dialog_open() {
            dialogs::cancel(ctx);
        } else if u.get_dump_open() {
            dumpview::close(ctx);
        } else if u.get_finder_open() {
            finder::close(ctx);
        } else {
            lists::clear_multi(ctx);
        }
        focus_keys(ctx);
        return true;
    }
    if u.get_dialog_open() {
        if key == char::from(slint::platform::Key::Return) {
            dialogs::confirm_current(ctx);
            return true;
        }
        return false;
    }
    if u.get_finder_open() {
        return finder::on_key(ctx, key);
    }
    let mode = ctx.st.borrow().mode.clone();
    if key == '?' || (key == '/' && shift) {
        dialogs::show_shortcuts(ctx);
        return true;
    }
    if control && (key == 'f' || key == 'F') {
        u.set_search_focus_seq(u.get_search_focus_seq() + 1);
        return true;
    }
    if control && (key == 'a' || key == 'A') {
        let mode = ctx.st.borrow().mode.clone();
        if kinds::kind_of(&mode).is_some() {
            lists::select_all(ctx);
            return true;
        }
    }
    if key == char::from(slint::platform::Key::F5) {
        refresh_current(ctx);
        return true;
    }
    if key == ' ' {
        if u.get_live_view() {
            u.invoke_pause_clicked();
        }
        return true;
    }
    if mode == "processes" {
        return tree::on_key(ctx, key);
    }
    if kinds::kind_of(&mode).is_some() {
        return lists::on_key(ctx, key);
    }
    false
}

fn first_run_hint(ctx: &Shared) {
    if ctx.settings.borrow().seen_hint {
        return;
    }
    ctx.settings.borrow_mut().seen_hint = true;
    save_settings(ctx);
    let u = ui(ctx);
    u.set_hint_text(ss("Tip: to find what is locking a file, paste its path in the search box and press Enter, or click Browse. Press ? for shortcuts."));
    u.set_hint_open(true);
    let ctx2 = ctx.clone();
    slint::Timer::single_shot(std::time::Duration::from_millis(14000), move || ui(&ctx2).set_hint_open(false));
}

pub fn chip(id: &str, label: &str, count: Option<usize>, tip: &str) -> crate::Chip {
    crate::Chip { id: ss(id), label: ss(label), count: count.map(|c| c.to_string()).map(|c| ss(&c)).unwrap_or_default(), tip: ss(tip) }
}

pub fn logical_width(ctx: &Shared) -> f32 {
    let w = ctx.window.window();
    w.size().width as f32 / w.scale_factor().max(0.5)
}

pub fn view_width(ctx: &Shared) -> f32 {
    (logical_width(ctx) - 172.0 - 60.0).max(300.0)
}

pub fn table_width(ctx: &Shared, table: &str) -> f32 {
    let inset = if table == "finder" { 82.0 } else { 198.0 };
    (logical_width(ctx) - inset).max(320.0)
}

pub fn reconcile_tip(ctx: &Shared, rows: &[crate::Row]) {
    let t = ctx.window.global::<Tips>();
    if !t.get_shown() {
        return;
    }
    let text = t.get_text();
    if !rows.iter().any(|r| r.tip == text) {
        t.set_shown(false);
    }
}

pub fn highlight_row(rows: &ModelRc<crate::Row>, old: Option<usize>, new: Option<usize>) {
    for (i, on) in [(old, false), (new, true)] {
        if let Some(i) = i
            && let Some(mut r) = rows.row_data(i)
                && r.selected != on {
                    r.selected = on;
                    rows.set_row_data(i, r);
                }
    }
}

pub fn relayout(ctx: &Shared) {
    let mode = ctx.st.borrow().mode.clone();
    match mode.as_str() {
        "processes" => {
            tree::rebuild_tree_cols(ctx);
            detail::render_detail_head(ctx);
        }
        "activity" | "resources" => {}
        _ => lists::set_cols(ctx, &mode),
    }
    if ui(ctx).get_finder_open() {
        finder::render_head(ctx);
    }
}

fn chip_width(c: &crate::Chip) -> f32 {
    c.label.chars().count() as f32 * 6.8 + if c.count.is_empty() { 20.0 } else { c.count.chars().count() as f32 * 6.5 + 26.0 } + 6.0
}

pub fn no_chip_rows() -> ModelRc<ModelRc<crate::Chip>> {
    ModelRc::new(VecModel::from(Vec::<ModelRc<crate::Chip>>::new()))
}

pub fn split_chips(ctx: &Shared, chips: Vec<crate::Chip>, reserve: f32) -> (Vec<crate::Chip>, ModelRc<ModelRc<crate::Chip>>) {
    let available = view_width(ctx) - reserve;
    let mut rows: Vec<Vec<crate::Chip>> = vec![Vec::new()];
    let mut used = 0.0f32;
    for c in chips {
        let w = chip_width(&c);
        if used + w > available && !rows.last().unwrap().is_empty() {
            rows.push(Vec::new());
            used = 0.0;
        }
        used += w;
        rows.last_mut().unwrap().push(c);
    }
    let first = rows.remove(0);
    let more: Vec<ModelRc<crate::Chip>> = rows.into_iter().map(model).collect();
    (first, ModelRc::new(VecModel::from(more)))
}

pub fn do_action(ctx: &Shared, action: Action, success: &str) {
    let success = success.to_string();
    spawn(ctx, move |app| api::run(app, action), move |ctx, result| match result {
        Ok(()) => {
            good(ctx, &success);
            apply_tree(ctx, api::tree(&ctx.app));
            if ctx.st.borrow().tree.selected.is_some() {
                load_detail(ctx);
            }
            finder::rerun_if_open(ctx);
        }
        Err(e) => bad(ctx, &e),
    });
}

pub fn batch_action(ctx: &Shared, actions: Vec<(String, Action)>, verb: &str, noun: (&str, &str), refresh: Option<Box<dyn FnOnce(&Shared)>>) {
    let total = actions.len();
    let verb = verb.to_string();
    let noun = (noun.0.to_string(), noun.1.to_string());
    spawn(
        ctx,
        move |app| {
            let mut errors: Vec<String> = Vec::new();
            for (label, action) in actions {
                if let Err(e) = api::run(app, action) {
                    errors.push(format!("{}: {}", label, e));
                }
            }
            errors
        },
        move |ctx, errors: Vec<String>| {
            let done = total - errors.len();
            if errors.is_empty() {
                good(ctx, &format!("{} {}", verb, kinds::plural(done, &noun.0, &noun.1)));
            } else {
                let mut shown: Vec<String> = errors.iter().take(3).cloned().collect();
                if errors.len() > 3 {
                    shown.push(format!("and {} more", errors.len() - 3));
                }
                bad(ctx, &format!("{} {} of {}. {}", verb, done, kinds::plural(total, &noun.0, &noun.1), shown.join(". ")));
            }
            if done > 0
                && let Some(r) = refresh
            {
                let ctx2 = ctx.clone();
                slint::Timer::single_shot(std::time::Duration::from_millis(400), move || r(&ctx2));
            }
        },
    );
}

pub fn simple_action(ctx: &Shared, action: Action, success: &str, refresh: Option<Box<dyn FnOnce(&Shared)>>) {
    let success = success.to_string();
    spawn(ctx, move |app| api::run(app, action), move |ctx, result| match result {
        Ok(()) => {
            good(ctx, &success);
            if let Some(r) = refresh {
                let ctx2 = ctx.clone();
                slint::Timer::single_shot(std::time::Duration::from_millis(400), move || r(&ctx2));
            }
        }
        Err(e) => bad(ctx, &e),
    });
}
