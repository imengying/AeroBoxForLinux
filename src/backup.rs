//! Portable application data backup. Credentials are intentionally preserved:
/// this is a user data export, not a redacted support report.
use crate::model::{RuleSet, Settings, State, Subscription};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fs, path::Path};

const FORMAT: &str = "aerobox-linux-backup";
const VERSION: u32 = 1;
const MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    format: String,
    version: u32,
    settings: Settings,
    active_subscription: String,
    subscriptions: Vec<Subscription>,
    rulesets: Vec<BackupRule>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRule {
    #[serde(flatten)]
    rule: RuleSet,
    /// Binary rule bytes are portable across machines, unlike local cache paths.
    binary_data: Option<String>,
}

pub fn export(
    path: &Path,
    state: &State,
    rule_bytes: impl Fn(&RuleSet) -> Option<Vec<u8>>,
) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let rulesets = state
        .rulesets
        .iter()
        .map(|rule| {
            let binary_data = if rule.binary {
                let bytes = rule_bytes(rule)
                    .or_else(|| crate::model::builtin_seed(&rule.id).map(<[u8]>::to_vec));
                if bytes.is_none() {
                    anyhow::bail!("规则集「{}」缺少缓存文件，请先更新或重新导入", rule.name);
                }
                bytes.map(|bytes| STANDARD.encode(bytes))
            } else {
                None
            };
            Ok(BackupRule {
                rule: rule.clone(),
                binary_data,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let backup = Backup {
        format: FORMAT.into(),
        version: VERSION,
        settings: state.settings.clone(),
        active_subscription: state.settings.active_subscription.clone(),
        subscriptions: state.subscriptions.clone(),
        rulesets,
    };
    crate::model::atomic_write(path, &serde_json::to_vec_pretty(&backup)?, 0o600)
}

pub fn read(path: &Path) -> Result<(State, HashMap<String, Vec<u8>>)> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let metadata = fs::metadata(path).context("无法读取备份")?;
    ensure!(metadata.is_file(), "备份必须是普通文件");
    ensure!(metadata.len() <= MAX_BYTES, "备份文件不能超过 32 MiB");
    let bytes = fs::read(path).context("无法读取备份")?;
    let value: Value = serde_json::from_slice(&bytes).context("不是有效的 AeroBox JSON 备份")?;
    ensure!(value["format"] == FORMAT, "不是 AeroBox Linux 备份文件");
    ensure!(value["version"] == VERSION, "不支持的备份版本");
    let backup: Backup = serde_json::from_value(value).context("备份字段不完整或类型错误")?;
    ensure!(backup.subscriptions.len() <= 5000, "备份中的订阅过多");
    ensure!(backup.rulesets.len() <= 5000, "备份中的规则集过多");
    let mut files = HashMap::new();
    let mut state = State {
        schema: 2,
        settings: backup.settings,
        subscriptions: backup.subscriptions,
        rulesets: backup
            .rulesets
            .into_iter()
            .map(|mut item| {
                if let Some(encoded) = item.binary_data.take() {
                    ensure!(item.rule.binary, "JSON 规则集不能包含 SRS 数据");
                    let bytes = STANDARD.decode(encoded).context("SRS 规则数据无效")?;
                    ensure!(bytes.starts_with(b"SRS"), "文件不是有效 SRS 规则集");
                    files.insert(item.rule.id.clone(), bytes);
                }
                Ok(item.rule)
            })
            .collect::<Result<Vec<_>>>()?,
    };
    // Validate the backup in its own namespace before changing any live state.
    state.settings.active_subscription = backup.active_subscription;
    state.normalize_selection();
    state.validate().context("备份内容未通过校验")?;
    for rule in &state.rulesets {
        if rule.binary {
            ensure!(
                files.contains_key(&rule.id),
                "SRS 规则集「{}」缺少二进制数据",
                rule.name
            );
        }
    }
    Ok((state, files))
}

/// Merge resources under fresh IDs, retaining current subscriptions and rules.
/// Restored selection follows the backup. Login autostart and window dimensions
/// remain local to this desktop.
pub fn merge(
    current: &State,
    imported: State,
    files: HashMap<String, Vec<u8>>,
) -> Result<(State, HashMap<String, Vec<u8>>)> {
    let mut next = current.clone();
    let mut ids = HashMap::new();
    let mut used_ids: std::collections::HashSet<_> = current
        .subscriptions
        .iter()
        .map(|sub| sub.id.clone())
        .chain(current.rulesets.iter().map(|rule| rule.id.clone()))
        .collect();
    let fresh_id = |used: &mut std::collections::HashSet<String>| {
        loop {
            let id = crate::model::id();
            if used.insert(id.clone()) {
                return id;
            }
        }
    };
    let unique_name = |name: &str, existing: &[String]| {
        let candidate = name.trim();
        if !existing.iter().any(|existing| existing == candidate) {
            return candidate.to_owned();
        }
        let mut n = 2;
        loop {
            let candidate = format!("{name}（备份 {n}）");
            if !existing.iter().any(|existing| existing == &candidate) {
                return candidate;
            }
            n += 1;
        }
    };
    let mut names: Vec<_> = next.subscriptions.iter().map(|s| s.name.clone()).collect();
    for mut sub in imported.subscriptions {
        let old = sub.id.clone();
        sub.id = fresh_id(&mut used_ids);
        sub.name = unique_name(&sub.name, &names);
        names.push(sub.name.clone());
        ids.insert(old, sub.id.clone());
        next.subscriptions.push(sub);
    }
    let mut names: Vec<_> = next.rulesets.iter().map(|r| r.name.clone()).collect();
    let mut binary_files = HashMap::new();
    for mut rule in imported.rulesets {
        let old = rule.id.clone();
        rule.id = fresh_id(&mut used_ids);
        rule.name = unique_name(&rule.name, &names);
        names.push(rule.name.clone());
        if let Some(bytes) = files.get(&old) {
            binary_files.insert(rule.id.clone(), bytes.clone());
        }
        if rule.binary {
            ensure!(
                binary_files.contains_key(&rule.id),
                "SRS 规则集「{}」缺少二进制数据",
                rule.name
            );
        }
        // Imported built-ins are independent user copies; their bytes are
        // carried in the backup instead of relying on built-in seed IDs.
        if rule.binary && rule.is_remote() {
            rule.updated = 0;
        }
        next.rulesets.push(rule);
    }
    let active_subscription = imported.settings.active_subscription.clone();
    let mut settings = imported.settings;
    settings.active_subscription = ids
        .get(&active_subscription)
        .cloned()
        .or_else(|| {
            next.subscriptions
                .iter()
                .find(|s| s.selected_node.is_some())
                .map(|s| s.id.clone())
        })
        .unwrap_or_default();
    // Preserve machine-local startup and window behavior from this desktop.
    // A backup must not make another login session start AeroBox or its core.
    settings.auto_start = current.settings.auto_start;
    settings.width = current.settings.width;
    settings.height = current.settings.height;
    next.settings = settings;
    next.normalize_selection();
    next.validate()?;
    Ok((next, binary_files))
}
