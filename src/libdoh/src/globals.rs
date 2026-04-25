use std::net::SocketAddr;
#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime;

use crate::odoh::ODoHRotator;

#[derive(Debug)]
pub struct Globals {
    #[cfg(feature = "tls")]
    pub tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    pub tls_cert_key_path: Option<PathBuf>,

    pub listen_address: SocketAddr,
    pub local_bind_address: SocketAddr,
    pub server_address: SocketAddr,
    pub path: String,
    pub max_clients: usize,
    pub timeout: Duration,
    pub clients_count: ClientsCount,
    pub max_concurrent_streams: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,
    pub enable_ecs: bool,
    pub ecs_prefix_v4: u8,
    pub ecs_prefix_v6: u8,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,
    pub mobileconfig_path: String,
    pub hostname: Option<String>,

    pub runtime_handle: runtime::Handle,
}

#[derive(Debug, Clone, Default)]
pub struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    pub fn current(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0
                && self
                    .0
                    .compare_exchange(count, count - 1, Ordering::Relaxed, Ordering::Relaxed)
                    != Ok(count)
        } {}
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clients_count_default_is_zero() {
        let count = ClientsCount::default();
        assert_eq!(count.current(), 0);
    }

    #[test]
    fn test_increment_returns_previous_value() {
        let count = ClientsCount::default();
        assert_eq!(count.increment(), 0); // returns value before incrementing
        assert_eq!(count.current(), 1);
        assert_eq!(count.increment(), 1);
        assert_eq!(count.current(), 2);
    }

    #[test]
    fn test_decrement_reduces_count() {
        let count = ClientsCount::default();
        count.increment();
        count.increment();
        assert_eq!(count.current(), 2);
        count.decrement();
        assert_eq!(count.current(), 1);
        count.decrement();
        assert_eq!(count.current(), 0);
    }

    #[test]
    fn test_decrement_at_zero_does_not_underflow() {
        let count = ClientsCount::default();
        assert_eq!(count.current(), 0);
        count.decrement(); // should be a no-op
        assert_eq!(count.current(), 0);
    }

    #[test]
    fn test_clone_shares_state() {
        let count = ClientsCount::default();
        count.increment();
        let count2 = count.clone();
        // Both handles share the same underlying Arc<AtomicUsize>
        assert_eq!(count2.current(), 1);
        count.increment();
        assert_eq!(count2.current(), 2);
    }

    #[test]
    fn test_increment_then_decrement_returns_to_zero() {
        let count = ClientsCount::default();
        for _ in 0..5 {
            count.increment();
        }
        assert_eq!(count.current(), 5);
        for _ in 0..5 {
            count.decrement();
        }
        assert_eq!(count.current(), 0);
    }
}
