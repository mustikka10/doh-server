// functions to verify the startup arguments as correct

use std::net::{SocketAddr, ToSocketAddrs};

pub(crate) fn verify_sock_addr(arg_val: &str) -> Result<String, String> {
    match arg_val.parse::<SocketAddr>() {
        Ok(_addr) => Ok(arg_val.to_string()),
        Err(_) => Err(format!(
            "Could not parse \"{arg_val}\" as a valid socket address (with port)."
        )),
    }
}

pub(crate) fn verify_remote_server(arg_val: &str) -> Result<String, String> {
    match arg_val.to_socket_addrs() {
        Ok(mut addr_iter) => match addr_iter.next() {
            Some(_) => Ok(arg_val.to_string()),
            None => Err(format!(
                "Could not parse \"{arg_val}\" as a valid remote uri"
            )),
        },
        Err(err) => Err(format!("{err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── verify_sock_addr ──────────────────────────────────────────────────────

    #[test]
    fn test_verify_sock_addr_valid_ipv4() {
        assert_eq!(
            verify_sock_addr("127.0.0.1:3000"),
            Ok("127.0.0.1:3000".to_string())
        );
    }

    #[test]
    fn test_verify_sock_addr_valid_ipv6() {
        assert_eq!(
            verify_sock_addr("[::1]:8080"),
            Ok("[::1]:8080".to_string())
        );
    }

    #[test]
    fn test_verify_sock_addr_missing_port() {
        assert!(verify_sock_addr("127.0.0.1").is_err());
    }

    #[test]
    fn test_verify_sock_addr_invalid_ip() {
        assert!(verify_sock_addr("999.999.999.999:3000").is_err());
    }

    #[test]
    fn test_verify_sock_addr_empty_string() {
        assert!(verify_sock_addr("").is_err());
    }

    #[test]
    fn test_verify_sock_addr_hostname_rejected() {
        // verify_sock_addr requires a literal IP address, not a hostname
        assert!(verify_sock_addr("localhost:3000").is_err());
    }

    // ── verify_remote_server ──────────────────────────────────────────────────

    #[test]
    fn test_verify_remote_server_valid_ip_port() {
        assert_eq!(
            verify_remote_server("9.9.9.9:53"),
            Ok("9.9.9.9:53".to_string())
        );
    }

    #[test]
    fn test_verify_remote_server_valid_ipv6() {
        assert_eq!(
            verify_remote_server("[::1]:53"),
            Ok("[::1]:53".to_string())
        );
    }

    #[test]
    fn test_verify_remote_server_missing_port() {
        assert!(verify_remote_server("9.9.9.9").is_err());
    }

    #[test]
    fn test_verify_remote_server_invalid_address() {
        assert!(verify_remote_server("not-a-real-address").is_err());
    }

    #[test]
    fn test_verify_remote_server_empty_string() {
        assert!(verify_remote_server("").is_err());
    }
}
