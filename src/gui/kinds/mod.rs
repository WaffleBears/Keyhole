use super::Shared;
use super::columns::ColDef;
use super::lists::{ListData, ListState};
use crate::{Chip, Row};
use keyhole::state::App;

pub mod certs;
pub mod connections;
pub mod crashes;
pub mod drivers;
pub mod events;
pub mod files;
pub mod firewall;
pub mod handles;
pub mod netconfig;
pub mod services;
pub mod sessions;
pub mod shares;
pub mod software;
pub mod startup;
pub mod tasks;
pub mod updates;
pub mod users;

pub struct RenderInput {
    pub filter: String,
    pub chip: String,
    pub sort: (String, bool),
    pub gh_type: String,
    pub table: String,
}

#[derive(Default)]
pub struct Rendered {
    pub chips: Vec<Chip>,
    pub rows: Vec<Row>,
    pub shown: Vec<usize>,
    pub count: String,
    pub empty: (String, String, String),
}

pub struct Kind {
    pub name: &'static str,
    pub title: &'static str,
    pub placeholder: (&'static str, &'static str),
    pub columns: fn(&ListState) -> &'static [ColDef],
    pub table: fn(&ListState) -> String,
    pub segment: fn(&ListState) -> String,
    pub default_sort: fn(&ListState) -> (&'static str, bool),
    pub buttons: fn(&ListState) -> Vec<Chip>,
    pub refresh: fn(&App, &ListState) -> ListData,
    pub render: fn(&Shared, &ListData, &RenderInput) -> Rendered,
    pub menu: fn(&Shared, usize, f32, f32),
    pub multi: Option<fn(&Shared, &[usize], f32, f32)>,
    pub double: fn(&Shared, usize),
    pub button: fn(&Shared, &str),
    pub csv: fn(&ListData, &[usize], &ListState) -> Option<(&'static str, String)>,
    pub segments: fn(&ListState) -> Vec<Chip>,
    pub segment_picked: fn(&Shared, &str),
    pub toggle: fn(&ListState) -> Option<(&'static str, &'static str, bool)>,
    pub toggled: fn(&Shared, bool),
    pub after_load: fn(&Shared, &ListData),
}

pub fn no_after_load(_ctx: &Shared, _data: &ListData) {}

pub fn same_table(st: &ListState) -> String {
    st.kind.clone()
}

pub fn no_segment(_st: &ListState) -> String {
    String::new()
}

pub fn no_segments(_st: &ListState) -> Vec<Chip> {
    Vec::new()
}

pub fn no_segment_picked(_ctx: &Shared, _id: &str) {}

pub fn no_toggle(_st: &ListState) -> Option<(&'static str, &'static str, bool)> {
    None
}

pub fn no_toggled(_ctx: &Shared, _on: bool) {}

pub const ALL: &[&Kind] = &[&services::KIND, &startup::KIND, &tasks::KIND, &drivers::KIND, &software::KIND, &firewall::KIND, &sessions::KIND, &handles::KIND, &files::KIND, &connections::KIND, &events::KIND, &crashes::KIND, &shares::KIND, &users::KIND, &updates::KIND, &certs::KIND, &netconfig::KIND];

pub fn kind_of(name: &str) -> Option<&'static Kind> {
    ALL.iter().copied().find(|k| k.name == name)
}

pub fn data_kind(data: &ListData) -> Option<&'static str> {
    match data {
        ListData::None => None,
        ListData::Services(_) => Some("services"),
        ListData::Startup(_) => Some("startup"),
        ListData::Tasks(..) => Some("tasks"),
        ListData::Drivers(_) => Some("drivers"),
        ListData::Software(_) => Some("software"),
        ListData::Firewall(..) => Some("firewall"),
        ListData::Sessions(_) => Some("sessions"),
        ListData::Handles(_) => Some("handles"),
        ListData::Files(_) => Some("files"),
        ListData::Connections(_) => Some("network"),
        ListData::Events(_) => Some("events"),
        ListData::Crashes(_) => Some("crashes"),
        ListData::Shares(_) => Some("shares"),
        ListData::Accounts(_) => Some("users"),
        ListData::Updates(_) => Some("updates"),
        ListData::Certs(_) => Some("certs"),
        ListData::NetConfig(_) => Some("netconfig"),
    }
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", n, if n == 1 { one } else { many })
}

pub fn refresh_after(kind: &'static str) -> Option<Box<dyn FnOnce(&Shared)>> {
    Some(Box::new(move |ctx| {
        if ctx.st.borrow().lists.kind == kind {
            super::lists::refresh_current(ctx, false);
        }
    }))
}

pub fn is_ms(company: &str) -> bool {
    company.to_lowercase().contains("microsoft")
}

pub fn unsigned(trust: &str) -> bool {
    !trust.is_empty() && trust != "signed" && trust != "unchecked" && trust != "error"
}
