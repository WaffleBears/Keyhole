use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WindowPlacement {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub maximized: bool,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    pub sort: String,
    pub descending: bool,
    pub flat: bool,
    pub named_only: bool,
    pub tab: String,
    pub rate_ms: u64,
    pub widths: HashMap<String, f32>,
    pub hidden_cols: Vec<String>,
    pub history: Vec<String>,
    pub seen_hint: bool,
    pub tree_height: f32,
    pub window: Option<WindowPlacement>,
    pub cols_version: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            sort: "name".into(),
            descending: false,
            flat: false,
            named_only: true,
            tab: "handles".into(),
            rate_ms: 1000,
            widths: HashMap::new(),
            hidden_cols: vec!["company".into(), "start".into(), "session".into(), "trust".into(), "path".into(), "cmd".into()],
            history: Vec::new(),
            seen_hint: false,
            tree_height: 380.0,
            window: None,
            cols_version: 3,
        }
    }
}

pub fn path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("Keyhole").join("settings.json"))
}

impl Settings {
    pub fn load() -> Settings {
        path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Settings>(&s).ok())
            .map(|mut s| {
                if s.cols_version < 2 && !s.hidden_cols.iter().any(|c| c == "cmd") {
                    s.hidden_cols.push("cmd".into());
                }
                if s.cols_version < 3 {
                    s.hidden_cols.retain(|c| c != "started");
                    if !s.hidden_cols.iter().any(|c| c == "start") {
                        s.hidden_cols.push("start".into());
                    }
                }
                s.cols_version = 3;
                s
            })
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let Some(p) = path() else { return };
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let tmp = p.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }

    pub fn push_history(&mut self, query: &str) {
        self.history.retain(|h| h != query);
        self.history.insert(0, query.to_string());
        self.history.truncate(12);
    }
}
