use super::{Fields, Result, error, strings};
use serde_json::{Value, json};

pub(super) fn convert(
    mut fields: Fields,
    protocol: Value,
    tls: Option<&Value>,
    path: &str,
) -> Result<(Value, bool)> {
    let enabled = tls.is_some_and(|tls| tls["enabled"] == true);
    let alpn = tls
        .and_then(|tls| tls.get("alpn"))
        .map(|value| strings(value.clone(), &format!("{path}.tls.alpn")))
        .transpose()?
        .unwrap_or_default();
    let mut version = fields.string("http_version")?.unwrap_or_default();
    if version.is_empty() {
        version = "auto".into();
    }
    if version == "auto" && alpn == ["h3"] {
        version = "h3".into();
    }
    let quic = version == "h3";
    if quic && !enabled {
        return Err(error(&fields.path, "XHTTP HTTP/3 requires TLS"));
    }
    let mut out = json!({"type":"xhttp", "http_version":version, "protocol":protocol});
    for key in ["path", "host", "mode"] {
        if let Some(value) = fields.string(key)?.filter(|value| !value.is_empty()) {
            out[key] = value.into();
        }
    }
    for key in [
        "headers",
        "x_padding_bytes",
        "sc_max_each_post_bytes",
        "sc_min_posts_interval_ms",
        "no_grpc_header",
        "download_idle_timeout_secs",
        "packet_pipeline_depth",
        "limits",
        "pool",
    ] {
        fields.copy(key, &mut out, key);
    }
    fields.finish()?;
    Ok((out, quic))
}
