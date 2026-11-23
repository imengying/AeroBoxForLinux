use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub(super) fn ports(text: &str) -> Result<Value> {
    let mut ranges = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        let (first, last) = part.split_once(['-', ':']).unwrap_or((part, part));
        let first: u16 = first.trim().parse().context("端口范围无效")?;
        let last: u16 = last.trim().parse().context("端口范围无效")?;
        ensure!(first != 0 && first <= last, "端口须在 1–65535 且范围须递增");
        ranges.push(if first == last {
            first.to_string()
        } else {
            format!("{first}:{last}")
        });
    }
    Ok(json!(ranges))
}

fn bandwidth(value: &Value) -> Result<f64> {
    // Clash uses decimal bit rates; an omitted unit means Mbps. Preserve
    // fractional rates rather than rounding a kbit/s limit to whole Mbit/s.
    let result = if let Some(number) = value.as_f64() {
        number
    } else {
        let text = value.as_str().context("带宽须为数字或带单位的文本")?.trim();
        let end = text
            .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .unwrap_or(text.len());
        let number: f64 = text[..end].parse().context("带宽数值无效")?;
        let scale = match text[end..].trim().to_ascii_lowercase().as_str() {
            "" | "mbps" => 1.0,
            "bps" => 0.000_001,
            "kbps" => 0.001,
            "gbps" => 1000.0,
            "tbps" => 1_000_000.0,
            _ => anyhow::bail!("带宽单位须为 bps、Kbps、Mbps、Gbps 或 Tbps"),
        };
        number * scale
    };
    ensure!(
        result.is_finite() && (0.0..=f64::from(u32::MAX)).contains(&result),
        "带宽超出支持范围"
    );
    Ok(result)
}

pub(super) fn clash(value: &Value, kind: &str, node: &mut Value) -> Result<()> {
    match kind {
        "hysteria2" => {
            if let Some(value) = value.get("ports") {
                let text = match value {
                    Value::String(text) => text.clone(),
                    Value::Number(number) => number.to_string(),
                    _ => anyhow::bail!("Clash ports 须为端口或端口范围文本"),
                };
                node["server_ports"] = ports(&text)?;
                // Hopping ports supersede the single port in Clash.
                node.as_object_mut().unwrap().remove("server_port");
            }
            if let Some(value) = value.get("hop-interval") {
                let text = value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string());
                let (first, last) = text.split_once('-').unwrap_or((&text, &text));
                let first: u64 = first
                    .trim()
                    .parse()
                    .context("跳跃间隔须为整数秒或秒数范围")?;
                let last: u64 = last
                    .trim()
                    .parse()
                    .context("跳跃间隔须为整数秒或秒数范围")?;
                ensure!(first <= last, "跳跃间隔范围须递增");
                node["hop_interval"] = format!("{first}s").into();
                if first != last {
                    node["hop_interval_max"] = format!("{last}s").into();
                }
            }
            for (source, target) in [("up", "up_mbps"), ("down", "down_mbps")] {
                if let Some(value) = value.get(source) {
                    node[target] = bandwidth(value)?.into();
                }
            }
        }
        "tuic" => {
            if let Some(value) = value.get("heartbeat-interval") {
                let milliseconds = value
                    .as_u64()
                    .context("Clash heartbeat-interval 须为非负整数毫秒")?;
                node["heartbeat"] = format!("{milliseconds}ms").into();
            }
            for (source, target) in [
                ("reduce-rtt", "zero_rtt_handshake"),
                ("udp-over-stream", "udp_over_stream"),
            ] {
                if let Some(value) = value.get(source) {
                    ensure!(value.is_boolean(), "Clash {source} 须为开关");
                    node[target] = value.clone();
                }
            }
        }
        _ => {}
    }
    Ok(())
}
