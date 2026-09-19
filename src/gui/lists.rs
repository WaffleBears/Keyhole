use super::columns;
use super::kinds::{self, Kind, RenderInput};
use super::{Shared, model, save_settings, spawn, ss, ui};
use crate::{Chip, Row};
use keyhole::api::{self, Connections, OpenFiles, SessionEntry, StartupEntry};
use keyhole::sys::drivers::DriverRow;
use keyhole::sys::firewall::{FirewallRow, ProfileStatus};
use keyhole::sys::services::ServiceRow;
use keyhole::sys::software::SoftwareRow;
use keyhole::sys::tasks::TaskRow;
use slint::{Model, SharedString};
use std::collections::{BTreeSet, HashMap};

#[derive(Default)]
pub enum ListData {
    #[default]
    None,
    Services(Vec<ServiceRow>),
    Startup(Vec<StartupEntry>),
    Tasks(Vec<TaskRow>, String),
    Drivers(Vec<DriverRow>),
    Software(Vec<SoftwareRow>),
    Firewall(Vec<FirewallRow>, Vec<ProfileStatus>, String),
    Sessions(Vec<SessionEntry>),
    Handles(api::AllHandles),
    Files(OpenFiles),
    Connections(Connections),
    Events(api::EventsData),
    Crashes(keyhole::sys::crashes::CrashData),
    Shares(keyhole::sys::shares::SharesData),
    Accounts(keyhole::sys::accounts::AccountsData),
    Updates(keyhole::sys::updates::UpdatesData),
    Certs(keyhole::sys::certs::CertsData),
    NetConfig(keyhole::sys::netconfig::NetConfigData),
}


#[derive(Default)]
pub struct ListState {
    pub kind: String,
    pub data: ListData,
    pub shown: Vec<usize>,
    pub sort: HashMap<String, (String, bool)>,
    pub chip: HashMap<String, String>,
    pub filter: HashMap<String, String>,
    pub token: u64,
    pub gh_type: String,
    pub net_resolve: bool,
    pub sel: Option<usize>,
    pub multi: BTreeSet<usize>,
    pub count: String,
    pub events: super::kinds::events::EventsUi,
    pub segment: HashMap<String, String>,
    pub updates_pending: Option<Result<Vec<keyhole::sys::updates::PendingRow>, String>>,
    pub updates_installing: bool,
    pub inflight: bool,
}

fn kind(name: &str) -> &'static Kind {
    kinds::kind_of(name).unwrap_or(&kinds::services::KIND)
}

pub fn defs(ctx: &Shared, name: &str) -> &'static [columns::ColDef] {
    (kind(name).columns)(&ctx.st.borrow().lists)
}

pub fn table_of(ctx: &Shared, name: &str) -> String {
    (kind(name).table)(&ctx.st.borrow().lists)
}

fn default_sort(ctx: &Shared, name: &str) -> (&'static str, bool) {
    match kinds::kind_of(name) {
        Some(k) => (k.default_sort)(&ctx.st.borrow().lists),
        None => ("", false),
    }
}

fn buttons(ctx: &Shared, name: &str) -> Vec<Chip> {
    kinds::kind_of(name).map(|k| (k.buttons)(&ctx.st.borrow().lists)).unwrap_or_default()
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_list_sort_clicked(move |k| {
            let kind = ctx.st.borrow().lists.kind.clone();
            let table = table_of(&ctx, &kind);
            let d = default_sort(&ctx, &kind);
            {
                let mut st = ctx.st.borrow_mut();
                let entry = st.lists.sort.entry(table).or_insert_with(|| (d.0.to_string(), d.1));
                if entry.0 == k.as_str() {
                    entry.1 = !entry.1;
                } else {
                    *entry = (k.to_string(), kind == "files" && matches!(k.as_str(), "activity" | "handles" | "write"));
                }
            }
            render(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_resize(move |i, w| {
            let kind = ctx.st.borrow().lists.kind.clone();
            let table = table_of(&ctx, &kind);
            let defs = defs(&ctx, &kind);
            columns::set_width(&ctx, &table, defs, i as usize, w);
            set_cols(&ctx, &kind);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_resized_done(move || save_settings(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_list_double(move |i| on_double(&ctx, i as usize));
    }
    {
        let ctx = ctx.clone();
        u.on_list_clicked(move |i| select_index(&ctx, i as usize));
    }
    {
        let ctx = ctx.clone();
        u.on_list_multi_clicked(move |i, ctrl, shift| multi_click(&ctx, i as usize, ctrl, shift));
    }
    {
        let ctx = ctx.clone();
        u.on_list_right(move |i, x, y| {
            let i = i as usize;
            let in_multi = {
                let st = ctx.st.borrow();
                st.lists.multi.len() > 1 && st.lists.multi.contains(&i)
            };
            if in_multi && on_multi_menu(&ctx, x, y) {
                return;
            }
            select_index(&ctx, i);
            on_menu(&ctx, i, x, y);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_filter_edited(move |t| {
            let kind = ctx.st.borrow().lists.kind.clone();
            ctx.st.borrow_mut().lists.filter.insert(kind.clone(), t.to_string());
            if kind == "network" {
                let ctx2 = ctx.clone();
                let text = t.to_string();
                let timer = slint::Timer::default();
                timer.start(slint::TimerMode::SingleShot, std::time::Duration::from_millis(160), move || {
                    let current = ctx2.st.borrow().lists.filter.get("network").cloned().unwrap_or_default();
                    if current == text {
                        super::activity::refresh_network(&ctx2);
                    }
                });
                ctx.st.borrow_mut().net_filter_timer = Some(timer);
            } else {
                render(&ctx);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_chip_picked(move |id| {
            let kind = ctx.st.borrow().lists.kind.clone();
            if kind == "handles" {
                let mut st = ctx.st.borrow_mut();
                st.lists.gh_type = id.to_string();
                st.lists.chip.insert(kind, id.to_string());
                drop(st);
                refresh_current(&ctx, true);
                return;
            }
            ctx.st.borrow_mut().lists.chip.insert(kind, id.to_string());
            render(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_button(move |id| {
            let kind = ctx.st.borrow().lists.kind.clone();
            match id.as_str() {
                "rescan" => refresh_current(&ctx, true),
                other => (self::kind(&kind).button)(&ctx, other),
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_toggle(move |v| {
            let kind = ctx.st.borrow().lists.kind.clone();
            (self::kind(&kind).toggled)(&ctx, v);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_list_segment_picked(move |id| {
            let kind = ctx.st.borrow().lists.kind.clone();
            (self::kind(&kind).segment_picked)(&ctx, id.as_str());
        });
    }
}

pub fn set_cols(ctx: &Shared, kind: &str) {
    let table = table_of(ctx, kind);
    let (cols, fixed) = columns::build(ctx, &table, defs(ctx, kind), ui(ctx).get_list_cols());
    let u = ui(ctx);
    u.set_list_cols(cols);
    u.set_list_fixed(fixed);
}

pub fn enter(ctx: &Shared, kind: &str) {
    let has_data = setup(ctx, kind);
    refresh_current(ctx, !has_data || !matches!(kind, "files" | "handles"));
}

fn select_index(ctx: &Shared, i: usize) {
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.multi.clear();
        st.lists.sel = Some(i);
    }
    apply_highlight(ctx);
}

fn multi_click(ctx: &Shared, i: usize, ctrl: bool, shift: bool) {
    {
        let mut st = ctx.st.borrow_mut();
        let len = st.lists.shown.len();
        if i >= len {
            return;
        }
        if shift {
            let anchor = st.lists.sel.unwrap_or(i).min(len - 1);
            let (a, b) = if anchor <= i { (anchor, i) } else { (i, anchor) };
            if !ctrl {
                st.lists.multi.clear();
            }
            st.lists.multi.extend(a..=b);
            st.lists.sel = Some(anchor);
        } else {
            if st.lists.multi.is_empty()
                && let Some(s) = st.lists.sel
                && s != i
                && s < len
            {
                st.lists.multi.insert(s);
            }
            if !st.lists.multi.remove(&i) {
                st.lists.multi.insert(i);
            }
            st.lists.sel = Some(i);
        }
        if st.lists.multi.len() == 1 {
            let only = *st.lists.multi.iter().next().unwrap();
            st.lists.multi.clear();
            st.lists.sel = Some(only);
        }
    }
    apply_highlight(ctx);
}

fn apply_highlight(ctx: &Shared) {
    let (sel, multi, count) = {
        let st = ctx.st.borrow();
        (st.lists.sel, st.lists.multi.clone(), st.lists.count.clone())
    };
    let u = ui(ctx);
    let rows = u.get_list_rows();
    for i in 0..rows.row_count() {
        let on = multi.contains(&i) || (multi.is_empty() && sel == Some(i));
        if let Some(mut r) = rows.row_data(i)
            && r.selected != on
        {
            r.selected = on;
            rows.set_row_data(i, r);
        }
    }
    u.set_list_count(ss(&count_text(&count, multi.len())));
}

fn count_text(base: &str, selected: usize) -> String {
    if selected > 1 {
        if base.is_empty() { format!("{} selected", selected) } else { format!("{}  ·  {} selected", base, selected) }
    } else {
        base.to_string()
    }
}

pub fn clear_multi(ctx: &Shared) -> bool {
    if ctx.st.borrow().lists.multi.is_empty() {
        return false;
    }
    ctx.st.borrow_mut().lists.multi.clear();
    apply_highlight(ctx);
    true
}

pub fn select_all(ctx: &Shared) {
    {
        let mut st = ctx.st.borrow_mut();
        let len = st.lists.shown.len();
        if len < 2 {
            return;
        }
        st.lists.multi = (0..len).collect();
        if st.lists.sel.is_none() {
            st.lists.sel = Some(0);
        }
    }
    apply_highlight(ctx);
}

pub fn selected_sources(ctx: &Shared) -> Vec<usize> {
    let st = ctx.st.borrow();
    st.lists.multi.iter().filter_map(|&i| st.lists.shown.get(i).copied()).collect()
}

pub fn on_key(ctx: &Shared, key: char) -> bool {
    use slint::platform::Key;
    let len = ctx.st.borrow().lists.shown.len();
    if len == 0 {
        return false;
    }
    if key == char::from(Key::DownArrow) || key == char::from(Key::UpArrow) {
        let sel = ctx.st.borrow().lists.sel;
        let next = match (sel, key == char::from(Key::DownArrow)) {
            (None, _) => 0,
            (Some(i), true) => (i + 1).min(len - 1),
            (Some(i), false) => i.saturating_sub(1),
        };
        select_index(ctx, next);
        let u = ui(ctx);
        u.set_list_scroll_index(next as i32);
        u.set_list_scroll_seq(u.get_list_scroll_seq() + 1);
        return true;
    }
    if key == char::from(Key::Return) {
        let sel = ctx.st.borrow().lists.sel;
        if let Some(sel) = sel {
            on_double(ctx, sel);
        }
        return true;
    }
    false
}

pub fn setup(ctx: &Shared, kind: &str) -> bool {
    if ctx.st.borrow().lists.kind != kind {
        let mut st = ctx.st.borrow_mut();
        st.lists.sel = None;
        st.lists.multi.clear();
    }
    ctx.st.borrow_mut().lists.kind = kind.to_string();
    let u = ui(ctx);
    let k = self::kind(kind);
    u.set_list_title(ss(k.title));
    let (ph, tip) = k.placeholder;
    u.set_list_filter_placeholder(ss(ph));
    u.set_list_filter_tip(ss(tip));
    u.set_list_filter(ss(&ctx.st.borrow().lists.filter.get(kind).cloned().unwrap_or_default()));
    u.set_list_buttons(model(buttons(ctx, kind)));
    {
        let st = ctx.st.borrow();
        match (k.toggle)(&st.lists) {
            Some((label, tip, checked)) => {
                u.set_list_toggle_visible(true);
                u.set_list_toggle_label(ss(label));
                u.set_list_toggle_tip(ss(tip));
                u.set_list_toggle_checked(checked);
            }
            None => u.set_list_toggle_visible(false),
        }
        u.set_list_segments(model((k.segments)(&st.lists)));
        u.set_list_segment(ss(&(k.segment)(&st.lists)));
    }
    u.set_list_chips(model(Vec::<Chip>::new()));
    u.set_list_chips_more(super::no_chip_rows());
    u.set_list_rows(model(Vec::<Row>::new()));
    u.set_list_count(SharedString::default());
    u.set_list_empty_text(SharedString::default());
    set_cols(ctx, kind);
    let data_matches = kinds::data_kind(&ctx.st.borrow().lists.data) == Some(kind);
    if data_matches {
        render(ctx);
    } else {
        ctx.st.borrow_mut().lists.data = ListData::None;
    }
    data_matches
}

pub fn refresh_current(ctx: &Shared, show_bar: bool) {
    let kind = ctx.st.borrow().lists.kind.clone();
    if kind == "network" {
        super::activity::refresh_network(ctx);
        return;
    }
    let token = {
        let mut st = ctx.st.borrow_mut();
        st.lists.token += 1;
        st.lists.inflight = true;
        st.lists.token
    };
    if show_bar {
        ui(ctx).set_list_loading(true);
    }
    let k = self::kind(&kind);
    let snapshot = {
        let st = ctx.st.borrow();
        ListState { kind: kind.clone(), gh_type: st.lists.gh_type.clone(), events: st.lists.events.settings_only(), updates_pending: st.lists.updates_pending.clone(), ..Default::default() }
    };
    spawn(
        ctx,
        move |app| (k.refresh)(app, &snapshot),
        move |ctx, mut data| {
            if ctx.st.borrow().lists.token != token {
                return;
            }
            ctx.st.borrow_mut().lists.inflight = false;
            ui(ctx).set_list_loading(false);
            let current = ctx.st.borrow().lists.kind == kind;
            if current {
                (k.after_load)(ctx, &data);
            }
            {
                let mut st = ctx.st.borrow_mut();
                if current {
                    if let ListData::Updates(d) = &mut data {
                        d.pending = st.lists.updates_pending.clone();
                    }
                    st.lists.data = data;
                }
            }
            if ctx.st.borrow().lists.kind == kind {
                render(ctx);
            }
        },
    );
}

pub fn set_connections(ctx: &Shared, conn: Connections) {
    ctx.st.borrow_mut().lists.data = ListData::Connections(conn);
    if ctx.st.borrow().lists.kind == "network" {
        render(ctx);
    }
}

pub fn show_services_for_pid(ctx: &Shared, pid: u32) {
    set_filter_and_show(ctx, "services", &format!("pid:{}", pid));
}

pub fn set_filter_and_show(ctx: &Shared, kind: &str, text: &str) {
    ctx.st.borrow_mut().lists.filter.insert(kind.to_string(), text.to_string());
    if ctx.st.borrow().mode == kind {
        ui(ctx).set_list_filter(ss(text));
        if kind == "network" {
            super::activity::refresh_network(ctx);
        } else {
            render(ctx);
        }
    } else {
        super::set_mode(ctx, kind);
    }
}

pub fn render(ctx: &Shared) {
    let kind = ctx.st.borrow().lists.kind.clone();
    let input = RenderInput {
        filter: ctx.st.borrow().lists.filter.get(&kind).cloned().unwrap_or_default().trim().to_lowercase(),
        chip: ctx.st.borrow().lists.chip.get(&kind).cloned().unwrap_or_default(),
        sort: { let table = table_of(ctx, &kind); ctx.st.borrow().lists.sort.get(&table).cloned().unwrap_or_else(|| { let d = default_sort(ctx, &kind); (d.0.to_string(), d.1) }) },
        gh_type: ctx.st.borrow().lists.gh_type.clone(),
        table: table_of(ctx, &kind),
    };
    let rendered = {
        let st = ctx.st.borrow();
        (self::kind(&kind).render)(ctx, &st.lists.data, &input)
    };
    let kinds::Rendered { chips, mut rows, shown, count, empty } = rendered;
    let u = ui(ctx);
    let old_rows = u.get_list_rows();
    let previous_key = ctx.st.borrow().lists.sel.and_then(|i| old_rows.row_data(i)).map(|r| row_key(&r));
    let multi_keys: std::collections::HashSet<String> = ctx.st.borrow().lists.multi.iter().filter_map(|&i| old_rows.row_data(i)).map(|r| row_key(&r)).collect();
    let (sel, multi) = {
        let mut st = ctx.st.borrow_mut();
        let moved = previous_key.as_ref().and_then(|k| rows.iter().position(|r| row_key(r) == *k));
        st.lists.sel = match (moved, st.lists.sel) {
            (Some(i), _) => Some(i),
            (None, Some(i)) if i < shown.len() && previous_key.is_none() => Some(i),
            _ => None,
        };
        st.lists.multi = if multi_keys.is_empty() { BTreeSet::new() } else { rows.iter().enumerate().filter(|(_, r)| multi_keys.contains(&row_key(r))).map(|(i, _)| i).collect() };
        if st.lists.multi.len() < 2 {
            st.lists.multi.clear();
        }
        st.lists.shown = shown;
        st.lists.count = count.clone();
        (st.lists.sel, st.lists.multi.clone())
    };
    if multi.is_empty() {
        if let Some(i) = sel {
            rows[i].selected = true;
        }
    } else {
        for &i in &multi {
            rows[i].selected = true;
        }
    }
    let count = count_text(&count, multi.len());
    let is_empty = rows.is_empty();
    let (chips, chips2) = super::split_chips(ctx, chips, 0.0);
    u.set_list_chips(model(chips));
    u.set_list_chips_more(chips2);
    u.set_list_chip(ss(&input.chip));
    u.set_list_sort(ss(&input.sort.0));
    u.set_list_desc(input.sort.1);
    super::reconcile_tip(ctx, &rows);
    u.set_list_rows(model(rows));
    u.set_list_count(ss(&count));
    if is_empty {
        u.set_list_empty_icon(ss(&empty.0));
        u.set_list_empty_text(ss(&empty.1));
        u.set_list_empty_sub(ss(&empty.2));
    }
}

fn row_key(r: &Row) -> String {
    if r.tip.is_empty() {
        r.cells.iter().take(3).map(|c| c.text.to_string()).collect::<Vec<_>>().join("\u{1F}")
    } else {
        format!("{}\u{1F}{}", r.tip, r.id)
    }
}

pub fn nothing_matches(filter: &str) -> String {
    if filter.is_empty() { "Nothing to show.".into() } else { format!("Nothing matches \"{}\".", filter) }
}

fn src_index(ctx: &Shared, i: usize) -> Option<usize> {
    ctx.st.borrow().lists.shown.get(i).copied()
}

fn on_double(ctx: &Shared, i: usize) {
    let Some(src) = src_index(ctx, i) else { return };
    let kind = ctx.st.borrow().lists.kind.clone();
    (self::kind(&kind).double)(ctx, src);
}

fn on_menu(ctx: &Shared, i: usize, x: f32, y: f32) {
    let Some(src) = src_index(ctx, i) else { return };
    let kind = ctx.st.borrow().lists.kind.clone();
    (self::kind(&kind).menu)(ctx, src, x, y);
}

fn on_multi_menu(ctx: &Shared, x: f32, y: f32) -> bool {
    let kind = ctx.st.borrow().lists.kind.clone();
    let Some(multi) = self::kind(&kind).multi else { return false };
    let sources = selected_sources(ctx);
    if sources.len() < 2 {
        return false;
    }
    multi(ctx, &sources, x, y);
    true
}

pub fn csv_of(ctx: &Shared) -> Option<(String, String)> {
    let st = ctx.st.borrow();
    let (name, body) = (self::kind(&st.lists.kind).csv)(&st.lists.data, &st.lists.shown, &st.lists)?;
    Some((name.to_string(), body))
}
