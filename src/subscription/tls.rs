use super::query_bool;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

// Android share-link names and the corresponding Clash spellings. Aliases
// identify the same setting; two spellings must never overwrite one another.
pub(super) const OPTIONAL_FIELDS: &[(&str, &str, bool)] = &[
    ("fragment", "fragment", true),
    ("tls_fragment", "fragment", true),
    ("tls-fragment", "fragment", true),
    ("record_fragment", "record_fragment", true),
    ("record-fragment", "record_fragment", true),
    ("tls-record-fragment", "record_fragment", true),
    ("fragment_fallback_delay", "fragment_fallback_delay", false),
    ("fragment-fallback-delay", "fragment_fallback_delay", false),
    (
        "tls-fragment-fallback-delay",
        "fragment_fallback_delay",
        false,
    ),
    ("kernel_tx", "kernel_tx", true),
    ("kernel-tx", "kernel_tx", true),
    ("kernel_rx", "kernel_rx", true),
    ("kernel-rx", "kernel_rx", true),
];

const ECH_FIELDS: &[(&str, &str)] = &[
    ("ech_enabled", "enabled"),
    ("ech-enabled", "enabled"),
    ("ech_config", "config"),
    ("ech-config", "config"),
    ("ech_config_path", "config_path"),
    ("ech-config-path", "config_path"),
    ("ech_query_server_name", "query_server_name"),
    ("ech-query-server-name", "query_server_name"),
];

pub(super) fn link_fields() -> impl Iterator<Item = &'static str> {
    OPTIONAL_FIELDS
        .iter()
        .map(|(alias, _, _)| *alias)
        .chain(ECH_FIELDS.iter().map(|(alias, _)| *alias))
        .chain(std::iter::once("ech"))
}

fn boolean(value: &Value, query: bool, field: &str) -> Result<Value> {
    Ok(if query {
        query_bool(value.as_str().context("链接参数须为文本")?, field)?
    } else {
        value
            .as_bool()
            .with_context(|| format!("{field} 须为开关"))?
    }
    .into())
}

pub(super) fn copy_optional(
    source: &Value,
    tls: &mut Value,
    query: bool,
    context: &str,
) -> Result<()> {
    for &(alias, field, is_bool) in OPTIONAL_FIELDS {
        if let Some(value) = source.get(alias) {
            ensure!(tls.get(field).is_none(), "{context} 重复设置 {field}");
            tls[field] = if is_bool {
                boolean(value, query, alias)?
            } else {
                value
                    .as_str()
                    .with_context(|| format!("{alias} 须为时长文本"))?
                    .into()
            };
        }
    }
    Ok(())
}

pub(super) fn link(source: &Value, tls: &mut Value, query: bool) -> Result<()> {
    copy_optional(source, tls, query, "节点链接")?;
    let mut ech = json!({});
    for &(alias, field) in ECH_FIELDS {
        if let Some(value) = source.get(alias) {
            ensure!(ech.get(field).is_none(), "节点链接重复设置 ECH {field}");
            ech[field] = if field == "enabled" {
                boolean(value, query, alias)?
            } else {
                value
                    .as_str()
                    .with_context(|| format!("{alias} 须为文本"))?
                    .into()
            };
        }
    }
    if let Some(value) = source.get("ech") {
        ensure!(ech.get("enabled").is_none(), "节点链接重复设置 ECH enabled");
        // Android exposes an ECH switch. Xray's share-link proposal uses the
        // same query key for the base64 ECHConfigList; an empty value disables it.
        if value.is_boolean()
            || value
                .as_str()
                .is_some_and(|s| matches!(s, "" | "0" | "1" | "false" | "true"))
        {
            ech["enabled"] = if value.is_boolean() {
                value.clone()
            } else {
                query_bool(value.as_str().unwrap(), "ech")?.into()
            };
        } else {
            ensure!(ech.get("config").is_none(), "节点链接重复设置 ECH config");
            ech["enabled"] = true.into();
            ech["config"] = config_pem(
                value
                    .as_str()
                    .context("节点链接 ech 须为开关或 Base64 文本")?,
                "节点链接 ech",
            )?
            .into();
        }
    }
    if !ech.as_object().unwrap().is_empty() {
        ech.as_object_mut()
            .unwrap()
            .entry("enabled")
            .or_insert(true.into());
        tls["ech"] = ech;
    }
    Ok(())
}

pub(super) fn config_pem(text: &str, context: &str) -> Result<String> {
    if text.is_empty() {
        return Ok(String::new());
    }
    let decoded = STANDARD
        .decode(text)
        .with_context(|| format!("{context} Base64 无效"))?;
    Ok(format!(
        "-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----\n",
        STANDARD.encode(decoded)
    ))
}
