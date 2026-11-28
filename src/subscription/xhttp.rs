use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Subscription spellings map to one transport representation before validation.
pub(super) fn clash(options: &Value) -> Result<Value> {
    let mut transport = json!({"type":"xhttp"});
    if options.is_null() {
        return Ok(transport);
    }
    for (key, value) in options.as_object().context("Clash xhttp-opts 须为对象")? {
        let target = match key.as_str() {
            "path" | "host" | "mode" | "headers" => key,
            "http-version" => "http_version",
            "x-padding-bytes" => "x_padding_bytes",
            "sc-max-each-post-bytes" => "sc_max_each_post_bytes",
            "sc-min-posts-interval-ms" => "sc_min_posts_interval_ms",
            "no-grpc-header" => "no_grpc_header",
            _ => bail!("Clash xhttp-opts 不支持参数: {key}"),
        };
        transport[target] = value.clone();
    }
    Ok(transport)
}

pub(super) fn link(path: &str, host: &str, mode: &str, extra: &str) -> Result<Value> {
    let mut transport = super::link_transport("xhttp", path, host);
    if !mode.is_empty() {
        transport["mode"] = mode.into();
    }
    if !extra.is_empty() {
        let extra: Value = serde_json::from_str(extra).context("XHTTP extra 须为 JSON 对象")?;
        for (key, value) in extra.as_object().context("XHTTP extra 须为 JSON 对象")? {
            let target = match key.as_str() {
                "headers" => "headers",
                "xPaddingBytes" => "x_padding_bytes",
                "scMaxEachPostBytes" => "sc_max_each_post_bytes",
                "scMinPostsIntervalMs" => "sc_min_posts_interval_ms",
                "noGRPCHeader" => "no_grpc_header",
                _ => bail!("XHTTP extra 不支持参数: {key}"),
            };
            transport[target] = value.clone();
        }
    }
    Ok(transport)
}
