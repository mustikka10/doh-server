use std::io;

use hyper::StatusCode;

#[derive(Debug)]
pub enum DoHError {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    UpstreamTimeout,
    StaleKey,
    Hyper(hyper::Error),
    Io(io::Error),
    ODoHConfigError(anyhow::Error),
    TooManyTcpSessions,
}

impl std::error::Error for DoHError {}

impl std::fmt::Display for DoHError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DoHError::Incomplete => write!(fmt, "Incomplete"),
            DoHError::InvalidData => write!(fmt, "Invalid data"),
            DoHError::TooLarge => write!(fmt, "Too large"),
            DoHError::UpstreamIssue => write!(fmt, "Upstream error"),
            DoHError::UpstreamTimeout => write!(fmt, "Upstream timeout"),
            DoHError::StaleKey => write!(fmt, "Stale key material"),
            DoHError::Hyper(e) => write!(fmt, "HTTP error: {e}"),
            DoHError::Io(e) => write!(fmt, "IO error: {e}"),
            DoHError::ODoHConfigError(e) => write!(fmt, "ODoH config error: {e}"),
            DoHError::TooManyTcpSessions => write!(fmt, "Too many TCP sessions"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_display_simple_variants() {
        assert_eq!(DoHError::Incomplete.to_string(), "Incomplete");
        assert_eq!(DoHError::InvalidData.to_string(), "Invalid data");
        assert_eq!(DoHError::TooLarge.to_string(), "Too large");
        assert_eq!(DoHError::UpstreamIssue.to_string(), "Upstream error");
        assert_eq!(DoHError::UpstreamTimeout.to_string(), "Upstream timeout");
        assert_eq!(DoHError::StaleKey.to_string(), "Stale key material");
        assert_eq!(DoHError::TooManyTcpSessions.to_string(), "Too many TCP sessions");
    }

    #[test]
    fn test_display_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let e = DoHError::Io(io_err);
        let s = e.to_string();
        assert!(s.starts_with("IO error:"), "got: {s}");
    }

    #[test]
    fn test_display_odoh_config_error() {
        let e = DoHError::ODoHConfigError(anyhow::anyhow!("something went wrong"));
        let s = e.to_string();
        assert!(s.starts_with("ODoH config error:"), "got: {s}");
        assert!(s.contains("something went wrong"), "got: {s}");
    }

    #[test]
    fn test_status_codes_simple_variants() {
        assert_eq!(StatusCode::from(DoHError::Incomplete), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(StatusCode::from(DoHError::InvalidData), StatusCode::BAD_REQUEST);
        assert_eq!(StatusCode::from(DoHError::TooLarge), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(StatusCode::from(DoHError::UpstreamIssue), StatusCode::BAD_GATEWAY);
        assert_eq!(StatusCode::from(DoHError::UpstreamTimeout), StatusCode::BAD_GATEWAY);
        assert_eq!(StatusCode::from(DoHError::StaleKey), StatusCode::UNAUTHORIZED);
        assert_eq!(StatusCode::from(DoHError::TooManyTcpSessions), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_status_code_io_error() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test");
        assert_eq!(StatusCode::from(DoHError::Io(io_err)), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_status_code_odoh_config_error() {
        let e = DoHError::ODoHConfigError(anyhow::anyhow!("test"));
        assert_eq!(StatusCode::from(e), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

impl From<DoHError> for StatusCode {
    fn from(e: DoHError) -> StatusCode {
        match e {
            DoHError::Incomplete => StatusCode::UNPROCESSABLE_ENTITY,
            DoHError::InvalidData => StatusCode::BAD_REQUEST,
            DoHError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            DoHError::UpstreamIssue => StatusCode::BAD_GATEWAY,
            DoHError::UpstreamTimeout => StatusCode::BAD_GATEWAY,
            DoHError::StaleKey => StatusCode::UNAUTHORIZED,
            DoHError::Hyper(_) => StatusCode::SERVICE_UNAVAILABLE,
            DoHError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DoHError::ODoHConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DoHError::TooManyTcpSessions => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}
