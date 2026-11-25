//! Naive's exported receive window has different meanings in HTTP/2 and HTTP/3.
use super::{Fields, Result, error, outbound::byte_size};
use serde_json::Value;

pub(super) fn windows(fields: &mut Fields, settings: &mut Value, quic: bool) -> Result<()> {
    let receive = size(fields, "stream_receive_window")?;
    let session = size(fields, "quic_session_receive_window")?;
    let (stream, connection) = if quic {
        (
            receive.unwrap_or(6 * 1024 * 1024),
            session.unwrap_or(15 * 1024 * 1024),
        )
    } else {
        if session.is_some() {
            return Err(error(
                format!("{}.quic_session_receive_window", fields.path),
                "requires Naive QUIC",
            ));
        }
        let connection = receive.unwrap_or(128 * 1024 * 1024);
        (connection / 2, connection)
    };
    if !(16 * 1024..=64 * 1024 * 1024).contains(&stream) {
        return Err(error(
            format!("{}.stream_receive_window", fields.path),
            if quic {
                "expected 16 KiB..64 MiB"
            } else {
                "HTTP/2 connection window must be 32 KiB..128 MiB"
            },
        ));
    }
    if !(16 * 1024..=128 * 1024 * 1024).contains(&connection) {
        return Err(error(
            format!(
                "{}.{}",
                fields.path,
                if quic {
                    "quic_session_receive_window"
                } else {
                    "stream_receive_window"
                }
            ),
            "expected 16 KiB..128 MiB",
        ));
    }
    settings["stream_receive_window"] = stream.into();
    settings["session_receive_window"] = connection.into();
    Ok(())
}

fn size(fields: &mut Fields, key: &str) -> Result<Option<u32>> {
    fields
        .take(key)
        .map(|value| byte_size(value, &format!("{}.{}", fields.path, key)))
        .transpose()
        .map(|value| value.filter(|size| *size != 0))
}
