use super::menus::{self, MenuItem};
use super::rows::{doc_default, kv, section};
use super::{Shared, bad, copy_text, good, model, spawn, ss, ui};
use crate::DocItem;
use keyhole::api;
use keyhole::sys::dumpan::DumpReport;
use std::path::PathBuf;

#[derive(Default)]
pub struct DumpState {
    pub report: Option<DumpReport>,
    pub path: Option<PathBuf>,
    pub token: u64,
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_dump_close(move || close(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_dump_copy(move || {
            let text = ctx.st.borrow().dump.report.as_ref().map(|r| r.text());
            match text {
                Some(t) => copy_text(&ctx, &t),
                None => bad(&ctx, "Nothing to copy yet"),
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_dump_save(move || save(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_dump_doc_right(move |i, x, y| doc_menu(&ctx, i as usize, x, y));
    }
}

pub fn open(ctx: &Shared, path: &str) {
    let path = PathBuf::from(path);
    let token = {
        let mut st = ctx.st.borrow_mut();
        st.dump.token += 1;
        st.dump.path = Some(path.clone());
        st.dump.report = None;
        st.dump.token
    };
    let u = ui(ctx);
    u.set_dump_title(ss(&path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()));
    u.set_dump_kind(ss(""));
    u.set_dump_verdict(ss(&path.display().to_string()));
    u.set_dump_verdict_tone(0);
    u.set_dump_doc(model(Vec::<DocItem>::new()));
    u.set_dump_loading(true);
    u.set_dump_open(true);
    spawn(ctx, move |_| api::analyze_dump(&path), move |ctx, res| {
        if ctx.st.borrow().dump.token != token {
            return;
        }
        let u = ui(ctx);
        u.set_dump_loading(false);
        match res {
            Ok(report) => {
                u.set_dump_kind(ss(&report.kind));
                u.set_dump_verdict(ss(&report.verdict));
                u.set_dump_verdict_tone(report.verdict_tone);
                u.set_dump_doc(model(items_of(&report)));
                ctx.st.borrow_mut().dump.report = Some(report);
            }
            Err(e) => {
                u.set_dump_kind(ss("not analyzed"));
                u.set_dump_verdict(ss(&e));
                u.set_dump_verdict_tone(4);
                bad(ctx, &e);
            }
        }
    });
}

fn items_of(report: &DumpReport) -> Vec<DocItem> {
    let mut out = Vec::new();
    for s in &report.sections {
        out.push(section(&s.title, &s.hint));
        for r in &s.rows {
            if r.key.is_empty() {
                out.push(DocItem { kind: 1, key: ss(""), value: ss(&r.value), tone: r.tone, ..doc_default() });
            } else {
                let mut it = kv(&r.key, &r.value);
                it.tone = r.tone;
                out.push(it);
            }
        }
    }
    out
}

pub fn close(ctx: &Shared) {
    ui(ctx).set_dump_open(false);
    ctx.st.borrow_mut().dump.token += 1;
}

fn save(ctx: &Shared) {
    let Some(report) = ctx.st.borrow().dump.report.clone() else {
        bad(ctx, "Nothing to save yet");
        return;
    };
    let stem = ctx.st.borrow().dump.path.as_ref().and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_string())).unwrap_or_else(|| "dump".into());
    let Some(path) = keyhole::sys::dialogs::save_file(super::window_hwnd(ctx), &format!("{}-analysis.txt", stem), "txt") else { return };
    match std::fs::write(&path, report.text()) {
        Ok(()) => good(ctx, &format!("Saved {}", path)),
        Err(e) => bad(ctx, &e.to_string()),
    }
}

fn doc_menu(ctx: &Shared, index: usize, x: f32, y: f32) {
    let items = ui(ctx).get_dump_doc();
    let Some(it) = slint::Model::row_data(&items, index) else { return };
    if it.kind != 1 {
        return;
    }
    let value = it.value.to_string();
    let key = it.key.to_string();
    let line = if key.is_empty() { value.clone() } else { format!("{}: {}", key, value) };
    let entries = vec![
        MenuItem::new("cv", "Copy value", { let v = value.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("cb", "Copy line", move |ctx| copy_text(ctx, &line)),
        MenuItem::new("all", "Copy whole report", |ctx| {
            let text = ctx.st.borrow().dump.report.as_ref().map(|r| r.text());
            if let Some(t) = text {
                copy_text(ctx, &t);
            }
        }),
    ];
    menus::show(ctx, x, y, &if key.is_empty() { "Analysis".to_string() } else { key }, entries);
}
