//! Error context at network boundaries. Keep the original error and its kind:
//! retry, resource-budget and DNS-deadline decisions must survive reporting.
use std::{error::Error, fmt, io, time::Instant};

#[derive(Debug)]
struct Context {
    description: String,
    source: io::Error,
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
        },
    )
}

pub(crate) fn stage(stage: &'static str, source: io::Error) -> io::Error {
    context(format!("stage={stage}"), source)
}

pub(crate) fn timed(stage: &'static str, began: Instant, source: io::Error) -> io::Error {
    context(
        format!("stage={stage} elapsed_ms={}", began.elapsed().as_millis()),
        source,
    )
}

pub(crate) fn vless_response(source: io::Error, received: &[u8]) -> io::Error {
    let expected = received.get(1).map_or(2, |length| 2 + usize::from(*length));
    context(
        format!(
            "stage=vless_response received={} expected={expected}",
            received.len()
        ),
        source,
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

/// io::Error::source can skip the custom error stored inside it.
pub(crate) fn contains<T: Error + 'static>(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<T>() {
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
