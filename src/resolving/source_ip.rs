//! Per-target source-IP resolution via the kernel's routing decision.
//!
//! `UdpSocket::connect()` triggers a routing lookup *without sending a packet*;
//! the resulting `local_addr()` is the source IP the kernel would actually use
//! for outbound traffic to that target. Probe / scan call sites use
//! `resolve_for_targets` to convert their target list into `(target, source)`
//! pairs once; the probe functions then iterate the pairs directly.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

pub fn resolve_source_ip(target: Ipv4Addr) -> io::Result<Ipv4Addr> {
    if target.is_loopback() {
        return Ok(Ipv4Addr::LOCALHOST);
    }
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.connect((target, 1))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(io::Error::other("unexpected IPv6 source")),
    }
}

/// Per-target resolution; targets we can't resolve are logged and dropped.
pub fn resolve_for_targets(targets: &[Ipv4Addr]) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    targets
        .iter()
        .copied()
        .filter_map(|t| match resolve_source_ip(t) {
            Ok(src) => Some((t, src)),
            Err(e) => {
                eprintln!("warning: could not resolve source IP for {t}: {e}");
                None
            }
        })
        .collect()
}

pub fn filter_resolved_targets(
    resolved: &[(Ipv4Addr, Ipv4Addr)],
    targets: &[Ipv4Addr],
) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let by_target: HashMap<Ipv4Addr, Ipv4Addr> = resolved.iter().copied().collect();
    targets
        .iter()
        .filter_map(|target| by_target.get(target).map(|source| (*target, *source)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_short_circuits() {
        assert_eq!(
            resolve_source_ip(Ipv4Addr::LOCALHOST).unwrap(),
            Ipv4Addr::LOCALHOST
        );
        assert_eq!(
            resolve_source_ip(Ipv4Addr::new(127, 0, 0, 5)).unwrap(),
            Ipv4Addr::LOCALHOST
        );
    }

    #[test]
    fn resolve_for_targets_drops_nothing_for_loopback() {
        let pairs = resolve_for_targets(&[Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 5)]);
        assert_eq!(pairs.len(), 2);
        assert!(pairs.iter().all(|(_, src)| *src == Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn filter_resolved_targets_preserves_requested_order_and_drops_unresolved() {
        let resolved = vec![
            (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(10, 0, 0, 1)),
            (Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let filtered = filter_resolved_targets(
            &resolved,
            &[Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(192, 0, 2, 3)],
        );

        assert_eq!(
            filtered,
            vec![(Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(10, 0, 0, 2))]
        );
    }
}
