use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

fn assign(plugin: &str, options: &str, node: &mut Value) -> Result<()> {
    let mut fields = crate::protocol::Fields::new(
        json!({"plugin":plugin,"plugin_opts":options}),
        "Shadowsocks",
    )?;
    crate::protocol::ss_plugin::convert(&mut fields)?;
    fields.finish()?;
    node["plugin"] = plugin.into();
    node["plugin_opts"] = options.into();
    Ok(())
}

pub(super) fn link(value: &str, node: &mut Value) -> Result<()> {
    let (plugin, options) = value.split_once(';').unwrap_or((value, ""));
    assign(plugin, options, node)
}

fn escaped(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace('=', "\\=")
}

pub(super) fn clash(source: &Value, node: &mut Value) -> Result<()> {
    ensure!(
        source.get("plugin-opts").is_none() || source.get("plugin_opts").is_none(),
        "Clash 节点重复设置 plugin-opts"
    );
    let plugin = match source.get("plugin") {
        Some(value) => value.as_str().context("Clash plugin 须为文本")?,
        None => {
            ensure!(
                source
                    .get("plugin-opts")
                    .or_else(|| source.get("plugin_opts"))
                    .is_none(),
                "plugin-opts 需要指定 plugin"
            );
            return Ok(());
        }
    };
    let plugin = if plugin == "obfs" {
        "obfs-local"
    } else {
        plugin
    };
    let Some(options) = source
        .get("plugin-opts")
        .or_else(|| source.get("plugin_opts"))
    else {
        return assign(plugin, "", node);
    };
    if let Some(options) = options.as_str() {
        return assign(plugin, options, node);
    }
    let options = options
        .as_object()
        .context("Clash plugin-opts 须为对象或文本")?;
    let mut fields = Vec::new();
    for (name, value) in options {
        let key = match (plugin, name.as_str()) {
            ("obfs-local", "mode") => "obfs",
            ("obfs-local", "host") => "obfs-host",
            _ => name,
        };
        if key == "tls" {
            let enabled = value.as_bool().context("Clash plugin-opts.tls 须为开关")?;
            if enabled {
                fields.push("tls".into());
            }
            continue;
        }
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) if key == "mux" => value.to_string(),
            Value::Bool(value) if key == "mux" => u8::from(*value).to_string(),
            _ => bail!("Clash plugin-opts.{name} 参数类型无效"),
        };
        fields.push(format!("{}={}", escaped(key), escaped(&value)));
    }
    assign(plugin, &fields.join(";"), node)
}
