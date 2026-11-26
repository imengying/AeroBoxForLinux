use super::{
    Fields, Result,
    outbound::{byte_size, parse_duration_millis},
};
use serde_json::{Value, json};

pub(super) fn configure(fields: &mut Fields, client: &mut Value) -> Result<()> {
    let mut settings = json!({});
    for key in [
        "initial_packet_size",
        "max_concurrent_streams",
        "disable_path_mtu_discovery",
    ] {
        fields.copy(key, &mut settings, key);
    }
    for (field, target) in [
        ("idle_timeout", "idle_timeout_ms"),
        ("keep_alive_period", "keep_alive_period_ms"),
    ] {
        if let Some(value) = fields.take(field).filter(|value| value != "") {
            settings[target] =
                parse_duration_millis(value, &format!("{}.{field}", fields.path))?.into();
        }
    }
    for field in ["stream_receive_window", "connection_receive_window"] {
        if let Some(value) = fields.take(field).filter(|value| value != "") {
            settings[field] = byte_size(value, &format!("{}.{field}", fields.path))?.into();
        }
    }
    if !settings.as_object().unwrap().is_empty() {
        client["quic_settings"]["transport"] = settings;
    }
    Ok(())
}
