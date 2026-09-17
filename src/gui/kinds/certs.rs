use super::{Kind, RenderInput, Rendered};
use crate::gui::columns::{ColDef, c};
use crate::gui::format::*;
use crate::gui::lists::{self, ListData, ListState};
use crate::gui::{dialogs, ui};
use std::collections::HashMap;
use crate::gui::menus::{self, MenuItem};
use crate::gui::rows::{cell, dot_cell, simple_row, sort_indices, suffix_cell, sv_b, sv_n, sv_s};
use crate::gui::simple_action;
use crate::gui::{Shared, bad, chip, copy_text, good, spawn, ss};
use crate::{Cell, Chip};
use keyhole::api::{self, Action};
use keyhole::state::App;
use keyhole::sys::certs::{self, CertRow};

pub const COLUMNS: &[ColDef] = &[
    c("subject", "Subject", 260.0, false, "The certificate's subject name, or its friendly name in the suffix when it has one. Click to sort."),
    c("expires", "Expires", 110.0, true, "How long until the certificate expires. Red when it already has, amber inside 30 days. Hover a row for the exact dates."),
    c("issuer", "Issuer", 200.0, false, "Who issued it. Self-signed certificates are their own issuer."),
    c("store", "Store", 120.0, false, "Which machine store holds it. Click to sort."),
    c("key", "Key", 130.0, false, "Key algorithm and size, with a dot when the private key is present on this machine."),
    c("bindings", "Bound to", 200.0, false, "HTTP.sys SSL bindings (IP:port or SNI host name) and the Remote Desktop listener that use this certificate."),
    c("template", "Template", 150.0, false, "The enterprise CA template it was issued from, when it was."),
    c("thumbprint", "Thumbprint", 330.0, false, "SHA-1 thumbprint, the id every other tool uses. Double-click a row to copy it."),
];

fn columns(_st: &ListState) -> &'static [ColDef] {
    COLUMNS
}

fn default_sort(_st: &ListState) -> (&'static str, bool) {
    ("expires", false)
}

pub static KIND: Kind = Kind {
    name: "certs",
    title: "Certificates",
    placeholder: ("Filter by subject, issuer, SAN or thumbprint", "Show only certificates whose subject, friendly name, issuer, SANs, template or thumbprint contains this text. Prefixes: store:personal  issuer:contoso  thumbprint:AB12  san:www"),
    columns,
    table,
    segment,
    default_sort,
    buttons,
    refresh,
    render,
    menu,
    double,
    button,
    csv: export_csv,
    segments,
    segment_picked,
    toggle: super::no_toggle,
    toggled: super::no_toggled,
    after_load: super::no_after_load,
};

fn current(st: &ListState) -> &'static str {
    let picked = st.segment.get("certs").map(|s| s.as_str()).unwrap_or("personal");
    certs::SEGMENTS.iter().find(|(id, _, _)| *id == picked).map(|(id, _, _)| *id).unwrap_or("personal")
}

fn segment(st: &ListState) -> String {
    current(st).to_string()
}

fn table(st: &ListState) -> String {
    format!("certs.{}", current(st))
}

fn segments(_st: &ListState) -> Vec<Chip> {
    certs::SEGMENTS
        .iter()
        .map(|(id, label, _)| {
            chip(id, label, None, match *id {
                "personal" => "Certificates this machine serves or signs with: the Personal, Web Hosting and Remote Desktop stores",
                "roots" => "Root authorities this machine trusts: the Trusted Root and Third-Party Root stores",
                "ca" => "Intermediate certification authorities used to build chains",
                "trust" => "Publishers whose signed code runs without prompts, and people whose certificates are trusted directly",
                _ => "Certificates explicitly distrusted on this machine",
            })
        })
        .collect()
}

pub fn switch(ctx: &Shared, id: &str) {
    {
        let mut st = ctx.st.borrow_mut();
        st.lists.segment.insert("certs".into(), id.to_string());
        st.lists.chip.insert("certs".into(), String::new());
        st.lists.sel = None;
    }
    ui(ctx).set_list_segment(ss(id));
    lists::set_cols(ctx, "certs");
    lists::render(ctx);
}

fn segment_picked(ctx: &Shared, id: &str) {
    switch(ctx, id);
}

fn buttons(_st: &ListState) -> Vec<Chip> {
    vec![
        chip("import", "Import…", None, "Add a certificate from a .cer, .crt, .pem, .p7b, .sst or .pfx file to one of the machine stores"),
        chip("certlm", "Certificates console", None, "Open the Local Computer certificates console (certlm.msc) for requests and private key tasks"),
    ]
}

fn refresh(_app: &App, _st: &ListState) -> ListData {
    ListData::Certs(api::certificates())
}

const DAY: i64 = 86_400_000;

fn expiry_tone(r: &CertRow, now: i64) -> i32 {
    let left = r.not_after_ms - now;
    if left <= 0 {
        4
    } else if left <= 30 * DAY {
        3
    } else if left <= 90 * DAY {
        7
    } else {
        0
    }
}

fn expiry_text(r: &CertRow, now: i64) -> String {
    let left = r.not_after_ms - now;
    if left <= 0 {
        format!("expired {}", fmt_age(-left))
    } else if now < r.not_before_ms {
        "not yet valid".to_string()
    } else {
        format!("in {}", fmt_age(left))
    }
}

fn key_text(r: &CertRow) -> String {
    if r.key_bits > 0 { format!("{} {}", r.key_algorithm, r.key_bits) } else { r.key_algorithm.clone() }
}

fn subject_cell(r: &CertRow) -> Cell {
    if r.friendly.is_empty() || r.friendly == r.subject {
        cell(&r.subject, 0)
    } else {
        suffix_cell(&r.subject, &format!("· {}", r.friendly))
    }
}

fn tip_of(r: &CertRow) -> String {
    certs::summary(r)
}

fn render(_ctx: &Shared, data: &ListData, input: &RenderInput) -> Rendered {
    let ListData::Certs(d) = data else { return Rendered::default() };
    let terms = filter_terms(&input.filter);
    let now = crate::gui::rows::now_ms();
    let mut out = Rendered::default();
    let seg = input.table.strip_prefix("certs.").unwrap_or("personal");
    let in_segment = |r: &CertRow| certs::segment_of(&r.store_id) == seg;
    let seg_rows: Vec<&CertRow> = d.rows.iter().filter(|r| in_segment(r)).collect();
    let seg_label = certs::SEGMENTS.iter().find(|(id, _, _)| *id == seg).map(|(_, l, _)| *l).unwrap_or("Personal");
    let expired = |r: &CertRow| r.not_after_ms <= now;
    let within = |r: &CertRow, days: i64| r.not_after_ms > now && r.not_after_ms - now <= days * DAY;
    let server_auth = |r: &CertRow| r.eku.iter().any(|e| e == "Server Authentication") || (r.eku.is_empty() && !r.sans.is_empty());
    let chip_ok = |r: &CertRow| match input.chip.as_str() {
        "expired" => expired(r),
        "30d" => within(r, 30),
        "90d" => within(r, 90),
        "key" => r.has_private_key,
        "bound" => !r.bindings.is_empty(),
        "self" => r.self_signed,
        "server" => server_auth(r),
        _ => true,
    };
    out.chips = vec![
        chip("", "All", Some(seg_rows.len()), "Every certificate in these stores"),
        chip("expired", "Expired", Some(seg_rows.iter().filter(|r| expired(r)).count()), "Already past their end date"),
        chip("30d", "Expiring in 30 days", Some(seg_rows.iter().filter(|r| within(r, 30)).count()), "Renew these now"),
        chip("90d", "Expiring in 90 days", Some(seg_rows.iter().filter(|r| within(r, 90)).count()), "Renew these soon"),
        chip("key", "With private key", Some(seg_rows.iter().filter(|r| r.has_private_key).count()), "The private key is on this machine, so the certificate can be used to serve or sign"),
        chip("bound", "In use", Some(seg_rows.iter().filter(|r| !r.bindings.is_empty()).count()), "Bound to an HTTPS port in HTTP.sys or to the Remote Desktop listener"),
        chip("self", "Self-signed", Some(seg_rows.iter().filter(|r| r.self_signed).count()), "Issued to itself. Clients will not trust it unless told to"),
        chip("server", "Server auth", Some(seg_rows.iter().filter(|r| server_auth(r)).count()), "Usable for TLS servers (Server Authentication EKU)"),
    ];
    if seg != "personal" {
        out.chips.retain(|c| c.id != "bound" && c.id != "server");
    }
    out.shown = (0..d.rows.len())
        .filter(|&i| {
            let r = &d.rows[i];
            in_segment(r)
                && chip_ok(r)
                && (terms.is_empty()
                    || term_matches(
                        &terms,
                        |k| match k {
                            "store" => Some(r.store.clone()),
                            "issuer" => Some(r.issuer.clone()),
                            "thumbprint" | "thumb" => Some(r.thumbprint.clone()),
                            "san" => Some(r.sans.join(" ")),
                            "template" => Some(r.template.clone()),
                            "subject" => Some(format!("{} {}", r.subject, r.friendly)),
                            _ => None,
                        },
                        &format!("{} {} {} {} {} {} {} {}", r.subject, r.friendly, r.issuer, r.sans.join(" "), r.template, r.thumbprint, r.store, r.bindings.join(" ")),
                    ))
        })
        .collect();
    sort_indices(&d.rows, &mut out.shown, &input.sort.0, input.sort.1, |r, k| match k {
        "subject" => sv_s(&r.subject),
        "expires" => sv_n(r.not_after_ms as f64),
        "issuer" => sv_s(&r.issuer),
        "store" => sv_s(&r.store),
        "key" => sv_b(r.has_private_key),
        "bindings" => sv_s(&r.bindings.join(", ")),
        "template" => sv_s(&r.template),
        "thumbprint" => sv_s(&r.thumbprint),
        _ => sv_s(""),
    });
    out.rows = out
        .shown
        .iter()
        .map(|&i| {
            let r = &d.rows[i];
            let tone = expiry_tone(r, now);
            simple_row(
                i as i32,
                vec![
                    subject_cell(r),
                    cell(&expiry_text(r, now), tone),
                    cell(&r.issuer, if r.self_signed { 7 } else { 0 }),
                    cell(&r.store, 0),
                    dot_cell(&key_text(r), if r.has_private_key { 2 } else { 0 }),
                    cell(&r.bindings.join(", "), if r.bindings.is_empty() { 0 } else { 2 }),
                    cell(&r.template, 0),
                    Cell { mono: true, ..cell(&r.thumbprint, 0) },
                ],
                if tone == 4 { 4 } else { 0 },
                &tip_of(r),
            )
        })
        .collect();
    let mut head = if seg == "personal" {
        format!(
            "{}  ·  {} expired  ·  {} expiring in 30 days  ·  {} bound",
            plural(seg_rows.len(), "certificate", "certificates"),
            seg_rows.iter().filter(|r| expired(r)).count(),
            seg_rows.iter().filter(|r| within(r, 30)).count(),
            seg_rows.iter().filter(|r| !r.bindings.is_empty()).count()
        )
    } else {
        format!(
            "{} in {}  ·  {} expired  ·  {} expiring in 90 days",
            plural(seg_rows.len(), "certificate", "certificates"),
            seg_label,
            seg_rows.iter().filter(|r| expired(r)).count(),
            seg_rows.iter().filter(|r| within(r, 90)).count()
        )
    };
    if seg == "personal" {
        for n in &d.notes {
            head.push_str(&format!("  ·  {}", n));
        }
    }
    out.count = head;
    out.empty = (
        "\u{EB95}".into(),
        if input.filter.is_empty() && input.chip.is_empty() {
            match seg {
                "personal" => "No certificates in the machine's Personal, Web Hosting or Remote Desktop stores.".into(),
                "untrusted" => "No explicitly distrusted certificates on this machine.".into(),
                _ => format!("No certificates in the {} stores.", seg_label),
            }
        } else {
            lists::nothing_matches(&input.filter)
        },
        if input.filter.is_empty() && input.chip.is_empty() && seg == "personal" { "Certificates for IIS, Remote Desktop, LDAPS and most server roles live here. Use Import… to add one.".into() } else { String::new() },
    );
    out
}

fn row_at(ctx: &Shared, src: usize) -> Option<CertRow> {
    let st = ctx.st.borrow();
    let ListData::Certs(d) = &st.lists.data else { return None };
    d.rows.get(src).cloned()
}

fn double(ctx: &Shared, src: usize) {
    if let Some(r) = row_at(ctx, src) {
        copy_text(ctx, &r.thumbprint);
    }
}

fn export(ctx: &Shared, r: &CertRow) {
    let stem = safe_name(if r.friendly.is_empty() { &r.subject } else { &r.friendly });
    let stem = if stem.is_empty() { r.thumbprint.clone() } else { stem };
    let Some(path) = keyhole::sys::dialogs::save_file(crate::gui::window_hwnd(ctx), &format!("{}.cer", stem), "cer") else { return };
    let thumb = r.thumbprint.clone();
    let shown = path.clone();
    spawn(ctx, move |_| api::export_cer(&thumb, std::path::Path::new(&path)), move |ctx, res| match res {
        Ok(()) => good(ctx, &format!("Saved {}", shown)),
        Err(e) => bad(ctx, &e),
    });
}

fn menu(ctx: &Shared, src: usize, x: f32, y: f32) {
    let Some(r) = row_at(ctx, src) else { return };
    let items = vec![
        MenuItem::new("thumb", "Copy thumbprint", { let v = r.thumbprint.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("subject", "Copy subject", { let v = r.subject.clone(); move |ctx| copy_text(ctx, &v) }),
        MenuItem::new("sans", "Copy subject alternative names", { let v = r.sans.join("\n"); move |ctx| copy_text(ctx, &v) }).disabled(r.sans.is_empty()),
        MenuItem::new("copySummary", "Copy summary", { let v = certs::summary(&r); move |ctx| copy_text(ctx, &v) }),
        MenuItem::sep(),
        MenuItem::new("export", "Export public certificate (.cer)", { let row = r.clone(); move |ctx| export(ctx, &row) }).tip("Saves the DER encoded certificate without its private key"),
        MenuItem::new("certlm", "Open Certificates console", |ctx| simple_action(ctx, Action::OpenTool("certlm".into()), "Opened the Certificates console", None)),
        MenuItem::sep(),
        MenuItem::new("remove", &format!("Remove from {} store", r.store), { let row = r.clone(); move |ctx| remove(ctx, &row) }).danger().tip(if r.has_private_key { "Deletes the certificate from the store. The private key stays on the machine" } else { "Deletes the certificate from the store" }),
    ];
    menus::show(ctx, x, y, &format!("{}  ·  {}", r.subject, expiry_text(&r, crate::gui::rows::now_ms())), items);
}

fn remove(ctx: &Shared, r: &CertRow) {
    let what = if r.friendly.is_empty() { r.subject.clone() } else { format!("{} ({})", r.subject, r.friendly) };
    let mut body = format!("This removes {} from the machine's {} store.", what, r.store);
    if !r.bindings.is_empty() {
        body.push_str(&format!(" It is in use by {}, which will stop working until another certificate is bound.", r.bindings.join(", ")));
    }
    if r.has_private_key {
        body.push_str(" The private key is not deleted.");
    }
    if r.store_id == "Root" || r.store_id == "AuthRoot" {
        body.push_str(" Removing a root authority makes every certificate it issued untrusted on this machine.");
    }
    let thumb = r.thumbprint.clone();
    let store = r.store_id.clone();
    dialogs::confirm(ctx, "Remove certificate?", &body, "Remove", true, Box::new(move |ctx| simple_action(ctx, Action::CertRemove { thumbprint: thumb.clone(), store: store.clone() }, "Removed the certificate", super::refresh_after("certs"))));
}

pub fn import(ctx: &Shared, preset: HashMap<String, String>) {
    let seg = current(&ctx.st.borrow().lists);
    let default_store = match seg {
        "roots" => "Root",
        "ca" => "CA",
        "trust" => "TrustedPublisher",
        "untrusted" => "Disallowed",
        _ => "My",
    };
    let g = |k: &str, d: &str| preset.get(k).cloned().unwrap_or_else(|| d.to_string());
    let path = match preset.get("path") {
        Some(p) => p.clone(),
        None => match keyhole::sys::dialogs::open_file_titled(crate::gui::window_hwnd(ctx), "Pick a certificate file to import", "cert") {
            Some(p) => p,
            None => return,
        },
    };
    let stores: Vec<(&str, &str)> = certs::STORES.to_vec();
    let fields = vec![
        dialogs::FieldSpec::text("path", "File", &path, "Path to a .cer, .crt, .pem, .p7b, .sst or .pfx file", true),
        dialogs::FieldSpec::select("store", "Store", &g("store", default_store), &stores),
        dialogs::FieldSpec::password("password", "Password", "Only for .pfx files that have one").optional(),
        dialogs::FieldSpec::check("exportable", "Mark the private key exportable (.pfx only)", g("exportable", "false") == "true"),
    ];
    dialogs::form(
        ctx,
        "Import certificate",
        "Adds every certificate in the file to the chosen Local Computer store. A .pfx also installs its private key.",
        fields,
        "Import",
        Box::new(|ctx, v| {
            let get = |k: &str| v.get(k).cloned().unwrap_or_default();
            let path = get("path");
            let store = get("store");
            let password = get("password");
            let exportable = get("exportable") == "true";
            let again = v.clone();
            let store_id = store.clone();
            spawn(ctx, move |_| certs::import_file(std::path::Path::new(&path), &store, &password, exportable), move |ctx, res| match res {
                Ok(report) => {
                    good(ctx, &report.text());
                    switch(ctx, certs::segment_of(&store_id));
                    if let Some(r) = super::refresh_after("certs") {
                        r(ctx);
                    }
                }
                Err(e) => {
                    bad(ctx, &e);
                    let mut preset = HashMap::new();
                    for k in ["path", "store", "exportable"] {
                        if let Some(x) = again.get(k) {
                            preset.insert(k.to_string(), x.clone());
                        }
                    }
                    import(ctx, preset);
                }
            });
        }),
    );
}

fn button(ctx: &Shared, id: &str) {
    match id {
        "certlm" => simple_action(ctx, Action::OpenTool("certlm".into()), "Opened the Certificates console", None),
        "import" => import(ctx, HashMap::new()),
        _ => {}
    }
}

fn export_csv(data: &ListData, shown: &[usize], st: &ListState) -> Option<(&'static str, String)> {
    let ListData::Certs(d) = data else { return None };
    let name = match current(st) {
        "roots" => "keyhole-certificates-roots",
        "ca" => "keyhole-certificates-intermediate",
        "trust" => "keyhole-certificates-trusted",
        "untrusted" => "keyhole-certificates-untrusted",
        _ => "keyhole-certificates",
    };
    Some((name, csv(&shown.iter().filter_map(|&i| d.rows.get(i)).map(|r| vec![r.subject.clone(), r.friendly.clone(), r.issuer.clone(), time_of(r.not_before_ms), time_of(r.not_after_ms), r.store.clone(), r.store_id.clone(), key_text(r), r.has_private_key.to_string(), r.self_signed.to_string(), r.eku.join("; "), r.sans.join("; "), r.template.clone(), r.bindings.join("; "), r.thumbprint.clone(), r.serial.clone()]).collect::<Vec<_>>(), &["Subject", "Friendly name", "Issuer", "Valid from", "Expires", "Store", "Store id", "Key", "Private key", "Self-signed", "EKU", "SANs", "Template", "Bound to", "Thumbprint", "Serial"])))
}
