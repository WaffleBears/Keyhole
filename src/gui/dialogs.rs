use super::{Shared, model, ss, strings, ui};
use slint::{ComponentHandle, Model};
use crate::{FormField, ShortcutRow};
use std::collections::HashMap;

pub enum DialogKind {
    Confirm(Box<dyn FnOnce(&Shared)>),
    Prompt(Box<dyn FnOnce(&Shared, String)>),
    Form { fields: Vec<FieldSpec>, values: HashMap<String, String>, on_ok: Box<dyn FnOnce(&Shared, HashMap<String, String>)> },
}

pub struct DialogState {
    pub kind: DialogKind,
}

#[derive(Clone)]
pub struct FieldSpec {
    pub key: String,
    pub label: String,
    pub kind: i32,
    pub value: String,
    pub placeholder: String,
    pub options: Vec<(String, String)>,
    pub text: String,
    pub required: bool,
    pub depends: Option<(String, Vec<String>)>,
    pub disabled_hint: String,
}

impl FieldSpec {
    pub fn only_when(mut self, key: &str, values: &[&str], hint: &str) -> FieldSpec {
        self.depends = Some((key.to_string(), values.iter().map(|v| v.to_string()).collect()));
        self.disabled_hint = hint.to_string();
        self
    }

    fn enabled_in(&self, values: &HashMap<String, String>) -> bool {
        match &self.depends {
            Some((key, allowed)) => values.get(key).map(|v| allowed.iter().any(|a| a == v)).unwrap_or(false),
            None => true,
        }
    }
}

impl FieldSpec {
    pub fn password(key: &str, label: &str, placeholder: &str) -> FieldSpec {
        FieldSpec { key: key.into(), label: label.into(), kind: 3, value: String::new(), placeholder: placeholder.into(), options: Vec::new(), text: String::new(), required: true, depends: None, disabled_hint: String::new() }
    }

    pub fn optional(mut self) -> FieldSpec {
        self.required = false;
        self
    }

    pub fn text(key: &str, label: &str, value: &str, placeholder: &str, required: bool) -> FieldSpec {
        FieldSpec { key: key.into(), label: label.into(), kind: 0, value: value.into(), placeholder: placeholder.into(), options: Vec::new(), text: String::new(), required, depends: None, disabled_hint: String::new() }
    }
    pub fn select(key: &str, label: &str, value: &str, options: &[(&str, &str)]) -> FieldSpec {
        let value = if options.iter().any(|(k, _)| *k == value) { value } else { options.first().map(|(k, _)| *k).unwrap_or("") };
        FieldSpec { key: key.into(), label: label.into(), kind: 1, value: value.into(), placeholder: String::new(), options: options.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), text: String::new(), required: false, depends: None, disabled_hint: String::new() }
    }
    pub fn check(key: &str, text: &str, value: bool) -> FieldSpec {
        FieldSpec { key: key.into(), label: String::new(), kind: 2, value: if value { "true".into() } else { "false".into() }, placeholder: String::new(), options: Vec::new(), text: text.into(), required: false, depends: None, disabled_hint: String::new() }
    }
}

pub fn wire(ctx: &Shared) {
    let u = ui(ctx);
    {
        let ctx = ctx.clone();
        u.on_dialog_confirmed(move || confirm_current(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_dialog_cancelled(move || cancel(&ctx));
    }
    {
        let ctx = ctx.clone();
        u.on_dialog_field_text(move |k, v| set_value(&ctx, k.as_str(), v.to_string()));
    }
    {
        let ctx = ctx.clone();
        u.on_dialog_field_select(move |k, i| {
            let value = {
                let st = ctx.st.borrow();
                match st.dialog.as_ref().map(|d| &d.kind) {
                    Some(DialogKind::Form { fields, .. }) => fields.iter().find(|f| f.key == k.as_str()).and_then(|f| f.options.get(i.max(0) as usize)).map(|o| o.0.clone()),
                    _ => None,
                }
            };
            if let Some(v) = value {
                set_value(&ctx, k.as_str(), v);
                on_form_changed(&ctx);
            }
        });
    }
    {
        let ctx = ctx.clone();
        u.on_dialog_field_check(move |k, v| {
            set_value(&ctx, k.as_str(), if v { "true".into() } else { "false".into() });
            on_form_changed(&ctx);
        });
    }
    {
        let ctx = ctx.clone();
        u.on_shortcuts_close(move || {
            ui(&ctx).set_shortcuts_open(false);
            super::focus_keys(&ctx);
        });
    }
}

fn set_value(ctx: &Shared, key: &str, value: String) {
    let mut st = ctx.st.borrow_mut();
    if let Some(DialogKind::Form { values, .. }) = st.dialog.as_mut().map(|d| &mut d.kind) {
        values.insert(key.to_string(), value);
    }
}

fn on_form_changed(ctx: &Shared) {
    let (states, values): (Vec<(String, bool, String, String)>, HashMap<String, String>) = {
        let st = ctx.st.borrow();
        match st.dialog.as_ref().map(|d| &d.kind) {
            Some(DialogKind::Form { fields, values, .. }) => (fields.iter().filter(|f| f.depends.is_some()).map(|f| (f.key.clone(), f.enabled_in(values), f.placeholder.clone(), f.disabled_hint.clone())).collect(), values.clone()),
            _ => (Vec::new(), HashMap::new()),
        }
    };
    if states.is_empty() {
        return;
    }
    let u = ui(ctx);
    let fields: Vec<FormField> = u
        .get_dialog_fields()
        .iter()
        .map(|mut f| {
            if let Some(v) = values.get(f.key.as_str()) {
                match f.kind {
                    0 | 3 => f.value = ss(v),
                    1 => f.selected = f.option_ids.iter().position(|id| id.as_str() == v.as_str()).unwrap_or(0) as i32,
                    2 => f.checked = v == "true",
                    _ => {}
                }
            }
            if let Some((_, enabled, placeholder, hint)) = states.iter().find(|(k, ..)| *k == f.key.as_str()) {
                f.disabled = !enabled;
                f.placeholder = ss(if *enabled { placeholder } else { hint });
            }
            f
        })
        .collect();
    u.set_dialog_fields(model(fields));
}

fn open(ctx: &Shared, title: &str, body: &str, ok: &str, danger: bool, mode: i32, kind: DialogKind) {
    ctx.st.borrow_mut().dialog = Some(DialogState { kind });
    let u = ui(ctx);
    u.set_dialog_title(ss(title));
    u.set_dialog_body(ss(body));
    u.set_dialog_ok(ss(ok));
    u.set_dialog_danger(danger);
    u.set_dialog_mode(mode);
    u.set_dialog_open(true);
    ctx.window.global::<crate::Tips>().set_shown(false);
}

pub fn confirm(ctx: &Shared, title: &str, body: &str, ok: &str, danger: bool, on_ok: Box<dyn FnOnce(&Shared)>) {
    ui(ctx).set_dialog_fields(model(Vec::<FormField>::new()));
    open(ctx, title, body, ok, danger, 0, DialogKind::Confirm(on_ok));
    super::focus_keys(ctx);
}

pub fn prompt(ctx: &Shared, title: &str, body: &str, placeholder: &str, ok: &str, on_ok: Box<dyn FnOnce(&Shared, String)>) {
    let u = ui(ctx);
    u.set_dialog_prompt(ss(""));
    u.set_dialog_placeholder(ss(placeholder));
    u.set_dialog_fields(model(Vec::<FormField>::new()));
    open(ctx, title, body, ok, false, 1, DialogKind::Prompt(on_ok));
    u.set_prompt_focus_seq(u.get_prompt_focus_seq() + 1);
}

pub fn form(ctx: &Shared, title: &str, intro: &str, fields: Vec<FieldSpec>, ok: &str, on_ok: Box<dyn FnOnce(&Shared, HashMap<String, String>)>) {
    let values: HashMap<String, String> = fields.iter().map(|f| (f.key.clone(), f.value.clone())).collect();
    let items: Vec<FormField> = fields
        .iter()
        .map(|f| FormField {
            key: ss(&f.key),
            label: ss(&f.label),
            kind: f.kind,
            value: ss(&f.value),
            placeholder: ss(&f.placeholder),
            options: strings(&f.options.iter().map(|o| o.1.clone()).collect::<Vec<_>>()),
            option_ids: strings(&f.options.iter().map(|o| o.0.clone()).collect::<Vec<_>>()),
            selected: f.options.iter().position(|o| o.0 == f.value).unwrap_or(0) as i32,
            checked: f.value == "true",
            text: ss(&f.text),
            required: f.required,
            disabled: false,
        })
        .collect();
    ui(ctx).set_dialog_fields(model(items));
    open(ctx, title, intro, ok, false, 2, DialogKind::Form { fields, values, on_ok });
    on_form_changed(ctx);
}

pub fn cancel(ctx: &Shared) {
    ctx.st.borrow_mut().dialog = None;
    ui(ctx).set_dialog_open(false);
    super::focus_keys(ctx);
}

pub fn confirm_current(ctx: &Shared) {
    let Some(state) = ctx.st.borrow_mut().dialog.take() else { return };
    let u = ui(ctx);
    match state.kind {
        DialogKind::Confirm(run) => {
            u.set_dialog_open(false);
            super::focus_keys(ctx);
            run(ctx);
        }
        DialogKind::Prompt(run) => {
            let text = u.get_dialog_prompt().trim().to_string();
            if text.is_empty() {
                ctx.st.borrow_mut().dialog = Some(DialogState { kind: DialogKind::Prompt(run) });
                u.set_prompt_focus_seq(u.get_prompt_focus_seq() + 1);
                return;
            }
            u.set_dialog_open(false);
            super::focus_keys(ctx);
            run(ctx, text);
        }
        DialogKind::Form { fields, values, on_ok } => {
            for f in &fields {
                if f.required && f.enabled_in(&values) && values.get(&f.key).map(|v| v.trim().is_empty()).unwrap_or(true) {
                    ctx.st.borrow_mut().dialog = Some(DialogState { kind: DialogKind::Form { fields: fields.clone(), values, on_ok } });
                    super::bad(ctx, &format!("{} is required", f.label));
                    return;
                }
            }
            u.set_dialog_open(false);
            super::focus_keys(ctx);
            let off: Vec<String> = fields.iter().filter(|f| !f.enabled_in(&values)).map(|f| f.key.clone()).collect();
            let secret: Vec<String> = fields.iter().filter(|f| f.kind == 3).map(|f| f.key.clone()).collect();
            let trimmed: HashMap<String, String> = values.into_iter().map(|(k, v)| if off.contains(&k) { (k, String::new()) } else if secret.contains(&k) { (k, v) } else { (k, v.trim().to_string()) }).collect();
            on_ok(ctx, trimmed);
        }
    }
}

pub fn show_shortcuts(ctx: &Shared) {
    let groups: [(&str, &[(&str, &[&str])]); 4] = [
        ("Search & find", &[("Focus the search box", &["Ctrl", "F"]), ("Run the search", &["Enter"]), ("Close a dialog / menu", &["Esc"])]),
        ("Process tree", &[("Move selection", &["↑", "↓"]), ("Collapse / expand the selected branch", &["←", "→"]), ("Terminate selected", &["Del"]), ("Refresh now", &["F5"]), ("Freeze / unfreeze the view", &["Space"]), ("Filter box understands  user:name   pid:1234   session:1", &[])]),
        ("Lists and the finder", &[("Move the highlighted row", &["↑", "↓"]), ("Open the highlighted row (jump to its process)", &["Enter"]), ("Select several rows, then right-click for actions on all of them", &["Ctrl", "click"]), ("Select a range of rows", &["Shift", "click"]), ("Select every row in the list", &["Ctrl", "A"]), ("Clear a multiple selection", &["Esc"])]),
        ("General", &[("Show this help", &["?"]), ("Paste a path in the search box, or click Browse, to find what's using it", &[]), ("Right-click any row for actions", &[]), ("Drag a column edge to resize. Right-click the process header to choose columns", &[])]),
    ];
    let mut rows = Vec::new();
    for (group, items) in groups.iter() {
        rows.push(ShortcutRow { group: ss(group), label: ss(""), keys: model(Vec::<slint::SharedString>::new()) });
        for (label, keys) in items.iter() {
            rows.push(ShortcutRow { group: ss(group), label: ss(label), keys: model(keys.iter().map(|k| ss(k)).collect()) });
        }
    }
    let u = ui(ctx);
    u.set_shortcut_rows(model(rows));
    u.set_shortcuts_open(true);
}
