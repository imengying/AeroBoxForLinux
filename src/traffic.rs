use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub download: u64,
    pub upload: u64,
    pub connections: usize,
}

impl Counters {
    pub fn from_api(value: &Value) -> Result<Self> {
        let connections = value.get("connections").context("缺少连接统计")?;
        ensure!(
            connections.is_null() || connections.is_array(),
            "连接统计格式无效"
        );
        Ok(Self {
            download: value["downloadTotal"].as_u64().context("缺少下载统计")?,
            upload: value["uploadTotal"].as_u64().context("缺少上传统计")?,
            connections: connections.as_array().map_or(0, Vec::len),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Rates {
    pub download: f64,
    pub upload: f64,
}

#[derive(Default)]
pub struct RateMeter {
    previous: Option<(Instant, Counters)>,
}

impl RateMeter {
    pub fn record(&mut self, at: Instant, counters: Counters) -> Option<Rates> {
        let previous = self.previous.replace((at, counters));
        let (before, old) = previous?;
        let elapsed = at.saturating_duration_since(before).as_secs_f64();
        // A stopped/reloaded core, missed polling interval or reset counter is
        // a new baseline, not a speed spike or a fabricated zero sample.
        if elapsed <= 0.0
            || elapsed > 5.0
            || counters.download < old.download
            || counters.upload < old.upload
        {
            return None;
        }
        let sample = Rates {
            download: (counters.download - old.download) as f64 / elapsed,
            upload: (counters.upload - old.upload) as f64 / elapsed,
        };
        Some(sample)
    }

    pub fn clear(&mut self) {
        self.previous = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn parses_totals_including_closed_connections_and_null_connection_list() {
        let result = Counters::from_api(
            &json!({"downloadTotal":4096,"uploadTotal":1024,"connections":[{"download":8}]}),
        )
        .unwrap();
        assert_eq!(
            (result.download, result.upload, result.connections),
            (4096, 1024, 1)
        );
        assert_eq!(
            Counters::from_api(&json!({"downloadTotal":0,"uploadTotal":0,"connections":null}))
                .unwrap()
                .connections,
            0
        );
        assert!(Counters::from_api(&json!({"message":"unavailable"})).is_err());
        assert!(
            Counters::from_api(&json!({"downloadTotal":0,"uploadTotal":0,"connections":{}}))
                .is_err()
        );
    }

    #[test]
    fn rates_use_elapsed_time_and_begin_with_a_baseline() {
        let at = Instant::now();
        let mut history = RateMeter::default();
        assert!(
            history
                .record(
                    at,
                    Counters {
                        download: 1024,
                        upload: 512,
                        connections: 1
                    }
                )
                .is_none()
        );
        let sample = history
            .record(
                at + Duration::from_millis(1500),
                Counters {
                    download: 4096,
                    upload: 2048,
                    connections: 2,
                },
            )
            .unwrap();
        assert_eq!(sample.download, 2048.0);
        assert_eq!(sample.upload, 1024.0);
    }

    #[test]
    fn resets_and_gaps_do_not_produce_misleading_rates() {
        let at = Instant::now();
        let mut history = RateMeter::default();
        history.record(
            at,
            Counters {
                download: 100,
                ..Counters::default()
            },
        );
        assert!(history.record(at, Counters::default()).is_none());
        history.record(
            at + Duration::from_secs(1),
            Counters {
                download: 200,
                ..Counters::default()
            },
        );
        assert!(
            history
                .record(at + Duration::from_secs(2), Counters::default())
                .is_none()
        );
        assert!(
            history
                .record(
                    at + Duration::from_secs(20),
                    Counters {
                        download: 10000,
                        ..Counters::default()
                    }
                )
                .is_none()
        );
        history.clear();
        assert!(
            history
                .record(at + Duration::from_secs(21), Counters::default())
                .is_none()
        );
    }
}
