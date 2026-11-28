//! Portable application data backup. Credentials are intentionally preserved:
/// this is a user data export, not a redacted support report.
use crate::model::{RuleSet, Settings, State, Subscription};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};

const FORMAT: &str = "aerobox-linux-backup";
const MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    format: String,
    settings: Settings,
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
        settings: state.settings.clone(),
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
    let backup: Backup = serde_json::from_slice(&bytes).context("备份数据无效")?;
    ensure!(backup.format == FORMAT, "不是 AeroBox Linux 备份文件");
    ensure!(backup.subscriptions.len() <= 5000, "备份中的订阅过多");
    ensure!(backup.rulesets.len() <= 5000, "备份中的规则集过多");
    let mut files = HashMap::new();
    let state = State {
        settings: backup.settings,
        subscriptions: backup.subscriptions,
        rulesets: backup
            .rulesets
            .into_iter()
            .map(|mut item| {
                if let Some(encoded) = item.binary_data.take() {
                    ensure!(item.rule.binary, "JSON 规则集不能包含 SRS 数据");
                    let bytes = STANDARD.decode(encoded).context("SRS 规则数据无效")?;
                    shoes::rule_set::validate_bytes(&bytes, true)
                        .map_err(|error| anyhow::anyhow!("SRS 规则数据无效：{error}"))?;
                    files.insert(item.rule.id.clone(), bytes);
                }
                Ok(item.rule)
            })
            .collect::<Result<Vec<_>>>()?,
    };
    // Validate the backup in its own namespace before changing any live state.
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
    mut files: HashMap<String, Vec<u8>>,
) -> Result<(State, HashMap<String, Vec<u8>>)> {
    imported.validate().context("备份内容未通过校验")?;
    let mut next = current.clone();
    let mut ids = HashMap::new();
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
        sub.id = crate::model::id();
        sub.name = unique_name(&sub.name, &names);
        names.push(sub.name.clone());
        ids.insert(old, sub.id.clone());
        next.subscriptions.push(sub);
    }
    let mut names: Vec<_> = next.rulesets.iter().map(|r| r.name.clone()).collect();
    let mut binary_files = HashMap::new();
    for mut rule in imported.rulesets {
        let old = rule.id.clone();
        rule.id = crate::model::id();
        rule.name = unique_name(&rule.name, &names);
        names.push(rule.name.clone());
        if let Some(bytes) = files.remove(&old) {
            binary_files.insert(rule.id.clone(), bytes);
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
    let mut settings = imported.settings;
    if !settings.active_subscription.is_empty() {
        settings.active_subscription = ids
            .get(&settings.active_subscription)
            .context("备份中的当前订阅不存在")?
            .clone();
    }
    // Window geometry describes this desktop; a backup must not resize it.
    settings.width = current.settings.width;
    settings.height = current.settings.height;
    next.settings = settings;
    next.validate()?;
    Ok((next, binary_files))
}
