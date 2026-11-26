//! Error context at network boundaries. Keep the original error and its kind:
//! retry, resource-budget and DNS-deadline decisions must survive reporting.
use std::{error::Error, fmt, io, time::Instant};

#[derive(Debug)]
struct Context {
    description: String,
    source: io::Error,
    stage: Option<&'static str>,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.description, self.source)
    }
}

impl Error for Context {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) fn context(description: impl Into<String>, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        Context {
            description: description.into(),
            source,
            stage: None,
        },
    )
}

pub(crate) fn stage(stage: &'static str, source: io::Error) -> io::Error {
    stage_context(stage, "", source)
}

pub(crate) fn stage_context(
    stage: &'static str,
    details: impl fmt::Display,
    source: io::Error,
) -> io::Error {
    io::Error::new(
        source.kind(),
        Context {
            description: format!("stage={stage} {details}").trim_end().to_owned(),
            source,
            stage: Some(stage),
        },
    )
}

pub(crate) fn timed(stage: &'static str, began: Instant, source: io::Error) -> io::Error {
    stage_context(
        stage,
        format_args!("elapsed_ms={}", began.elapsed().as_millis()),
        source,
    )
}

#[derive(Debug)]
struct VlessResponse {
    received: usize,
    expected: usize,
    source: io::Error,
}

impl fmt::Display for VlessResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stage=vless_response received={} expected={}: {}",
            self.received, self.expected, self.source
        )
    }
}

impl Error for VlessResponse {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) fn vless_response(source: io::Error, received: &[u8]) -> io::Error {
    io::Error::new(
        source.kind(),
        VlessResponse {
            received: received.len(),
            expected: received.get(1).map_or(2, |length| 2 + usize::from(*length)),
            source,
        },
    )
}

#[derive(Debug)]
pub(crate) struct DnsPolicyRejection(pub u16);

impl fmt::Display for DnsPolicyRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS query rejected by local policy (rcode={})", self.0)
    }
}
impl Error for DnsPolicyRejection {}

#[derive(Debug)]
pub(crate) struct FlowCancelled;
impl fmt::Display for FlowCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("flow cancelled")
    }
}
impl Error for FlowCancelled {}

#[derive(Debug)]
pub(crate) struct DnsResponse(pub hickory_resolver::proto::op::ResponseCode);
impl fmt::Display for DnsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS response {}", self.0)
    }
}
impl Error for DnsResponse {}

#[derive(Debug)]
pub(crate) struct DnsNoData;
impl fmt::Display for DnsNoData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS returned no usable IP addresses")
    }
}
impl Error for DnsNoData {}

#[derive(Debug)]
pub(crate) struct TlsTruncation(pub io::Error);
impl fmt::Display for TlsTruncation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl Error for TlsTruncation {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Classify at the connection boundary, without changing error propagation or
/// matching human-readable messages. A closed relay is not a failed handshake.
pub(crate) fn connection_level(error: &io::Error) -> log::Level {
    use hickory_resolver::proto::op::ResponseCode;
    use io::ErrorKind;
    use log::Level;
    if contains::<FlowCancelled>(error)
        || contains::<DnsPolicyRejection>(error)
        || contains::<DnsNoData>(error)
        || crate::routing::ingress::is_policy_block(error)
    {
        return Level::Debug;
    }
    let mut relay = false;
    let mut vless_response = None;
    let mut dns_code = None;
    walk(error, |cause| {
        if let Some(context) = cause.downcast_ref::<Context>() {
            relay |= matches!(
                context.stage,
                Some("relay" | "relay_upload" | "relay_download")
            );
        }
        if let Some(response) = cause.downcast_ref::<VlessResponse>() {
            vless_response = Some((response.received, response.source.kind()));
        }
        if let Some(response) = cause.downcast_ref::<DnsResponse>() {
            dns_code = Some(response.0);
        }
        if let Some(hickory_resolver::net::NetError::Dns(response)) = cause.downcast_ref() {
            use hickory_resolver::net::DnsError;
            dns_code = match response {
                DnsError::ResponseCode(code) => Some(*code),
                DnsError::NoRecordsFound(records) => Some(records.response_code),
                _ => dns_code,
            };
        }
        false
    });
    if let Some(code) = dns_code {
        return if matches!(code, ResponseCode::NXDomain | ResponseCode::NoError) {
            Level::Debug
        } else {
            Level::Warn
        };
    }
    if let Some((received, kind)) = vless_response {
        // VLESS has no target-connect failure status. Servers can close before
        // sending a response when the destination is unreachable (including an
        // IPv6-only target). Keep the failed connection, but distinguish it
        // from malformed or partially received protocol headers.
        return if received == 0
            && matches!(
                kind,
                ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::NotConnected
                    | ErrorKind::TimedOut
            ) {
            Level::Warn
        } else {
            Level::Error
        };
    }
    if relay && contains::<TlsTruncation>(error) {
        return Level::Warn;
    }
    match error.kind() {
        ErrorKind::BrokenPipe
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
            if relay =>
        {
            Level::Debug
        }
        ErrorKind::TimedOut
        | ErrorKind::ConnectionRefused
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NetworkDown => Level::Warn,
        _ => Level::Error,
    }
}

pub(crate) fn report_connection(peer: impl fmt::Display, error: &io::Error) {
    log::log!(
        connection_level(error),
        "connection peer={peer} kind={:?}: {error}",
        error.kind()
    );
}

/// io::Error::source can skip the custom error stored inside it.
pub(crate) fn contains<T: Error + 'static>(error: &(dyn Error + 'static)) -> bool {
    walk(error, |cause| cause.is::<T>())
}

fn walk(
    mut error: &(dyn Error + 'static),
    mut visit: impl FnMut(&(dyn Error + 'static)) -> bool,
) -> bool {
    loop {
        if visit(error) {
            return true;
        }
        let next = match error.downcast_ref::<io::Error>() {
            Some(error) => error.get_ref().map(|inner| inner as &dyn Error),
            None => error.source(),
        };
        let Some(next) = next else { return false };
        error = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_levels_separate_lifecycle_dns_and_protocol_failures() {
        use hickory_resolver::{
            net::{DnsError, NetError},
            proto::op::ResponseCode,
        };
        use io::ErrorKind;
        use log::Level;
        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::NotConnected,
        ] {
            assert_eq!(
                connection_level(&stage("relay_download", kind.into())),
                Level::Debug
            );
            assert_eq!(
                connection_level(&stage("tls_handshake", kind.into())),
                Level::Error
            );
        }
        assert_eq!(
            connection_level(&stage(
                "outbound_setup",
                crate::control::tracked_stream::cancelled()
            )),
            Level::Debug
        );
        assert_eq!(
            connection_level(&context(
                "dns",
                io::Error::new(ErrorKind::NotFound, DnsNoData)
            )),
            Level::Debug
        );
        for (code, level) in [
            (ResponseCode::NXDomain, Level::Debug),
            (ResponseCode::ServFail, Level::Warn),
            (ResponseCode::Refused, Level::Warn),
        ] {
            assert_eq!(
                connection_level(&context(
                    "dns",
                    io::Error::new(ErrorKind::NotFound, DnsResponse(code))
                )),
                level
            );
            assert_eq!(
                connection_level(&context(
                    "dns",
                    io::Error::other(NetError::Dns(DnsError::ResponseCode(code)))
                )),
                level
            );
        }
        assert_eq!(
            connection_level(&stage("outbound_setup", ErrorKind::TimedOut.into())),
            Level::Warn
        );
        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::UnexpectedEof,
            ErrorKind::PermissionDenied,
        ] {
            assert_eq!(
                connection_level(&stage("relay_download", kind.into())),
                Level::Error
            );
        }
        let tls_eof = || {
            io::Error::new(
                ErrorKind::UnexpectedEof,
                TlsTruncation(ErrorKind::UnexpectedEof.into()),
            )
        };
        assert_eq!(
            connection_level(&stage("relay_download", tls_eof())),
            Level::Warn
        );
        assert_eq!(
            connection_level(&stage("tls_handshake", tls_eof())),
            Level::Error
        );
        for kind in [
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::TimedOut,
        ] {
            for (received, level) in [(&[][..], Level::Warn), (&[0][..], Level::Error)] {
                let error = stage("relay_download", vless_response(kind.into(), received));
                assert_eq!(error.kind(), kind);
                assert_eq!(connection_level(&error), level);
            }
        }
        assert_eq!(
            connection_level(&vless_response(ErrorKind::InvalidData.into(), &[])),
            Level::Error
        );
        assert_eq!(
            connection_level(&stage("relay_download", vless_response(tls_eof(), &[0]))),
            Level::Error
        );
        // Message text alone never downgrades an unclassified failure.
        assert_eq!(
            connection_level(&io::Error::other(
                "flow cancelled; DNS response Non-Existent Domain"
            )),
            Level::Error
        );
    }

    #[test]
    fn context_keeps_error_classification_and_original_source() {
        let error = timed(
            "tls_handshake",
            Instant::now(),
            io::Error::from_raw_os_error(libc::ECONNRESET),
        );
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let original = error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(original.raw_os_error(), Some(libc::ECONNRESET));
        assert!(
            error
                .to_string()
                .contains("stage=tls_handshake elapsed_ms=")
        );
        let pending = context(
            "outbound",
            io::Error::new(io::ErrorKind::TimedOut, crate::resolver::DnsSetupPending),
        );
        assert!(crate::resolver::dns_setup_pending(&pending));
        assert!(!crate::resolver::dns_caller_deadline(&pending));
        let deadline = context(
            "dns",
            io::Error::new(io::ErrorKind::TimedOut, crate::resolver::DnsCallerDeadline),
        );
        assert!(crate::resolver::dns_caller_deadline(&deadline));
        assert!(crate::resources::is_exhausted(&stage(
            "outbound",
            crate::resources::exhausted()
        )));
    }
}
