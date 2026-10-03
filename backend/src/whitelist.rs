//! Resolve operator-owned policy on the server before opening client listeners.
//! Only the resulting IP literals cross the authenticated configuration channel.

use anyhow::{bail, Result};
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::{timeout_at, Instant};
use tracing::warn;

const MAX_ENTRIES: usize = 128;
const MAX_ADDRESSES: usize = 256;
const LOOKUP_BUDGET: Duration = Duration::from_secs(5);

pub(crate) async fn resolve(entries: &[String]) -> Result<Vec<String>> {
    resolve_with(entries, LOOKUP_BUDGET, |name| async move {
        let addresses: Vec<IpAddr> = tokio::net::lookup_host((name, 0))
            .await
            .map(|addresses| addresses.take(MAX_ADDRESSES + 1).map(|a| a.ip()).collect())?;
        Ok(addresses)
    })
    .await
}

async fn resolve_with<F, Fut>(
    entries: &[String],
    budget: Duration,
    mut lookup: F,
) -> Result<Vec<String>>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<IpAddr>>>,
{
    if entries.len() > MAX_ENTRIES {
        bail!("VPN_WHITELIST_DOMAINS exceeds the {MAX_ENTRIES}-entry limit");
    }
    let deadline = Instant::now() + budget;
    let mut addresses = Vec::new();
    for entry in entries {
        let resolved = if let Ok(ip) = entry.parse::<IpAddr>() {
            vec![ip]
        } else {
            if Instant::now() >= deadline {
                warn!(%entry, "Whitelist lookup budget expired; destination stays tunneled");
                continue;
            }
            match timeout_at(deadline, lookup(entry.clone())).await {
                Ok(Ok(ips)) => {
                    if ips.len() > MAX_ADDRESSES {
                        bail!("VPN_WHITELIST_DOMAINS lookup exceeds the {MAX_ADDRESSES}-address limit");
                    }
                    ips
                }
                Ok(Err(error)) => {
                    warn!(%entry, %error, "Whitelist lookup failed; destination stays tunneled");
                    continue;
                }
                Err(_) => {
                    warn!(%entry, "Whitelist lookup budget expired; unresolved destinations stay tunneled");
                    continue;
                }
            }
        };
        for ip in resolved {
            let address = ip.to_string();
            if !addresses.contains(&address) {
                if addresses.len() == MAX_ADDRESSES {
                    bail!("VPN_WHITELIST_DOMAINS exceeds the {MAX_ADDRESSES}-address limit");
                }
                addresses.push(address);
            }
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn names_are_resolved_on_server_and_literals_do_not_use_dns() {
        let entries = ["example.test", "192.0.2.1", "2001:db8::1"].map(str::to_string);
        let result = resolve_with(&entries, LOOKUP_BUDGET, |name| async move {
            assert_eq!(name, "example.test");
            Ok(vec!["192.0.2.1".parse().unwrap()])
        })
        .await
        .unwrap();
        assert_eq!(result, ["192.0.2.1", "2001:db8::1"]);
    }

    #[tokio::test]
    async fn lookup_failure_never_sends_a_hostname_to_clients() {
        let result = resolve_with(
            &["missing.test".into(), "192.0.2.1".into()],
            LOOKUP_BUDGET,
            |_| async { Err(std::io::Error::other("resolver unavailable")) },
        )
        .await
        .unwrap();
        assert_eq!(result, ["192.0.2.1"]);
    }

    #[tokio::test]
    async fn excessive_configuration_is_rejected_explicitly() {
        assert!(resolve(&vec!["192.0.2.1".into(); MAX_ENTRIES + 1])
            .await
            .is_err());
        let result = resolve_with(&["example.test".into()], LOOKUP_BUDGET, |_| async {
            Ok((0..=MAX_ADDRESSES)
                .map(|n| IpAddr::V6(std::net::Ipv6Addr::from(n as u128)))
                .collect())
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn expired_budget_skips_new_lookups_but_preserves_literals() {
        let result = resolve_with(
            &[
                "first.test".into(),
                "second.test".into(),
                "192.0.2.1".into(),
            ],
            Duration::ZERO,
            |_| async { panic!("must not start a DNS lookup after the deadline") },
        )
        .await
        .unwrap();
        assert_eq!(result, ["192.0.2.1"]);
    }
}
