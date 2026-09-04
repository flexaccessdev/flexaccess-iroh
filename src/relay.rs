//! Relay configuration, the shared relay auth token, and the per-relay startup
//! probe.
//!
//! The design is documented in
//! <https://github.com/flexaccessdev/iroh-common-architecture> (see
//! `relays-and-address-lookup.md`); this module is its implementation.

use anyhow::{Context, Result};
use futures::future::join_all;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, endpoint::presets};
use log::info;
use std::sync::Arc;
use std::time::Duration;

/// How long a freshly bound endpoint (or a relay probe) may take to come
/// online before that is treated as a relay connectivity failure.
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay configuration, resolved once from the raw config strings.
///
/// This is the single source of the default-vs-custom distinction. It selects
/// both which relay map iroh uses **and** whether iroh *internet* discovery is
/// enabled: [`Default`](Self::Default) uses the n0 relays with the n0 lookup
/// stack (pkarr publishing + DNS resolution of the peer's home relay — see
/// <https://docs.iroh.computer/concepts/address-lookup>), while
/// [`Custom`](Self::Custom) uses the configured relays with n0 internet
/// discovery disabled (dialers use relay hints instead). mDNS local-network
/// discovery is independent of this choice (see the `mdns` feature).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelayConfig {
    /// iroh's default relay map, with n0 address lookup.
    #[default]
    Default,
    /// Custom relay set (parsed, sorted, deduped). Never empty.
    ///
    /// `auth_token`, when set, is sent to every custom relay as an
    /// `Authorization: Bearer <token>` header on the WebSocket upgrade (see
    /// [`Self::relay_mode`]). It is only ever carried by custom relays — the
    /// default relays never receive a token (see [`Self::from_urls_with_token`]).
    Custom {
        urls: Vec<RelayUrl>,
        auth_token: Option<String>,
    },
}

impl RelayConfig {
    /// Parse raw config strings with no relay auth token.
    ///
    /// Thin wrapper over [`Self::from_urls_with_token`]; see there for behavior.
    pub fn from_urls(urls: &[String]) -> Result<Self> {
        Self::from_urls_with_token(urls, None)
    }

    /// Parse raw config strings and attach an optional shared relay auth token.
    ///
    /// Empty input selects the default relays. Parsing fails on the first
    /// malformed URL, so config typos surface at resolve time instead of at each
    /// use site.
    ///
    /// The token is normalized (blank/whitespace-only becomes `None`) and is
    /// **strictly gated to custom relays**: a non-empty token with no custom
    /// relay URLs is a hard error, since the default iroh relays never take a
    /// token. This surfaces the misconfiguration before the endpoint starts.
    pub fn from_urls_with_token(urls: &[String], auth_token: Option<String>) -> Result<Self> {
        let auth_token = auth_token.and_then(|token| {
            let token = token.trim();
            (!token.is_empty()).then(|| token.to_string())
        });
        if urls.is_empty() {
            if auth_token.is_some() {
                anyhow::bail!(
                    "relay_auth_token requires custom relay_urls; it is not used with the default iroh relays"
                );
            }
            return Ok(Self::Default);
        }
        let mut parsed = urls
            .iter()
            .map(|url| {
                url.parse::<RelayUrl>()
                    .with_context(|| format!("Invalid relay URL: {url}"))
            })
            .collect::<Result<Vec<_>>>()?;
        parsed.sort();
        parsed.dedup();
        Ok(Self::Custom {
            urls: parsed,
            auth_token,
        })
    }

    /// The custom relay URLs; empty for [`RelayConfig::Default`].
    pub fn custom_urls(&self) -> &[RelayUrl] {
        match self {
            Self::Default => &[],
            Self::Custom { urls, .. } => urls,
        }
    }

    /// The shared relay auth token, if configured (custom relays only).
    pub fn relay_auth_token(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Custom { auth_token, .. } => auth_token.as_deref(),
        }
    }

    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }

    /// The corresponding iroh [`RelayMode`].
    ///
    /// For custom relays, an `auth_token` (when set) is applied to every relay in
    /// the map via [`RelayMap::with_auth_token`], which iroh sends as an
    /// `Authorization: Bearer <token>` header on the relay WebSocket upgrade.
    pub fn relay_mode(&self) -> RelayMode {
        match self {
            Self::Default => RelayMode::Default,
            Self::Custom { urls, auth_token } => {
                let map = RelayMap::from_iter(urls.iter().cloned());
                let map = match auth_token {
                    Some(token) => map.with_auth_token(token.clone()),
                    None => map,
                };
                RelayMode::Custom(map)
            }
        }
    }

    /// Log which relays are in use (silent for the default relays).
    pub fn log_status(&self) {
        match self.custom_urls().len() {
            0 => {}
            1 => info!("Using custom relay server"),
            n => info!("Using {n} custom relay servers (with failover)"),
        }
    }
}

/// Build a minimal, relay-only endpoint for probing a single relay.
///
/// It uses an ephemeral identity (no persistent secret, no address publishing)
/// and clears IP transports so [`Endpoint::online`] reflects *pure relay*
/// connectivity — a holepunched direct path can never mask a dead or
/// auth-rejecting relay. The auth token, when set, rides the WebSocket upgrade
/// exactly as it does for the real endpoint, so the probe validates the token
/// too. iroh's default QUIC transport settings are fine here: the probe only
/// needs the relay link to come up, never a data path.
fn probe_endpoint_builder(relay_url: &RelayUrl, auth_token: Option<&str>) -> iroh::endpoint::Builder {
    let map = RelayMap::from_iter([relay_url.clone()]);
    let map = match auth_token {
        Some(token) => map.with_auth_token(token.to_string()),
        None => map,
    };
    // iroh 1.x requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Custom(map))
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        // Relay-only: drop direct IP transports so `online()` is a pure relay
        // reachability signal, independent of holepunching.
        .clear_ip_transports()
}

/// Probe a single custom relay by binding a relay-only endpoint and waiting for
/// it to come online, bounded by [`RELAY_CONNECT_TIMEOUT`]. `Ok(())` means the
/// relay connected (and accepted the auth token, if any); otherwise the error
/// describes the failure. The probe endpoint is always closed before returning.
async fn probe_relay(relay_url: &RelayUrl, auth_token: Option<&str>) -> Result<()> {
    let endpoint = probe_endpoint_builder(relay_url, auth_token)
        .bind()
        .await
        .with_context(|| format!("Failed to bind probe endpoint for relay {relay_url}"))?;
    let outcome = tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await;
    endpoint.close().await;
    outcome.map_err(|_| {
        anyhow::anyhow!(
            "did not come online within {}s (unreachable or rejected the auth token)",
            RELAY_CONNECT_TIMEOUT.as_secs()
        )
    })
}

/// Probe every configured custom relay individually (in parallel) and fail if
/// **any** relay is unreachable.
///
/// This is stricter than a single endpoint-wide `online()` wait, which only
/// proves that *one* relay in the set (the home relay) connected and so
/// reports a misleading all-clear when a backup relay is down. Default relays
/// are not probed (returns `Ok(())` immediately).
///
/// Run this at first creation only: it validates the configuration (fail fast
/// if *any* relay is down). During an outage that strictness would block a
/// rebuild's recovery through the one relay that still answers, so
/// [`crate::endpoint::rebuild_endpoint`] deliberately skips it.
pub async fn probe_custom_relays(relay_config: &RelayConfig) -> Result<()> {
    let RelayConfig::Custom { urls, auth_token } = relay_config else {
        return Ok(());
    };
    let token = auth_token.as_deref();
    info!("Probing {} custom relay(s) for reachability...", urls.len());
    let results = join_all(
        urls.iter()
            .map(|url| async move { (url, probe_relay(url, token).await) }),
    )
    .await;
    let failures: Vec<String> = results
        .into_iter()
        .filter_map(|(url, res)| res.err().map(|e| format!("{url}: {e}")))
        .collect();
    if !failures.is_empty() {
        anyhow::bail!(
            "{} of {} custom relay(s) failed to come online:\n  {}",
            failures.len(),
            urls.len(),
            failures.join("\n  ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "https://relay.example.com./";

    #[test]
    fn empty_urls_no_token_is_default() {
        let cfg = RelayConfig::from_urls_with_token(&[], None).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
        assert!(!cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn blank_token_without_urls_is_default() {
        // A whitespace-only token normalizes to None, so it is not an error.
        let cfg = RelayConfig::from_urls_with_token(&[], Some("   ".to_string())).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
    }

    #[test]
    fn token_without_custom_urls_is_error() {
        let err = RelayConfig::from_urls_with_token(&[], Some("secret".to_string()))
            .expect_err("token without custom relays must be rejected");
        assert!(
            err.to_string()
                .contains("relay_auth_token requires custom relay_urls"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_custom_url_is_rejected_without_token() {
        // Custom relays are always parse-validated, independent of any token.
        let err = RelayConfig::from_urls_with_token(&["not a url".to_string()], None)
            .expect_err("malformed relay URL must be rejected");
        assert!(
            err.to_string().contains("Invalid relay URL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn custom_urls_without_token() {
        let cfg = RelayConfig::from_urls_with_token(&[RELAY.to_string()], None).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.custom_urls().len(), 1);
        assert_eq!(cfg.relay_auth_token(), None);
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn custom_urls_are_sorted_and_deduped() {
        let cfg = RelayConfig::from_urls(&[
            "https://b.example.com./".to_string(),
            "https://a.example.com./".to_string(),
            "https://b.example.com./".to_string(),
        ])
        .unwrap();
        let urls: Vec<String> = cfg.custom_urls().iter().map(ToString::to_string).collect();
        assert_eq!(urls, ["https://a.example.com./", "https://b.example.com./"]);
    }

    #[test]
    fn custom_urls_with_token_trimmed() {
        let cfg =
            RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("  secret\n".to_string()))
                .unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), Some("secret"));
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn token_is_trimmed_to_none_with_custom_urls() {
        // A blank token alongside custom relays is simply no token, not an error.
        let cfg =
            RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("  ".to_string())).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn from_urls_carries_no_token() {
        let cfg = RelayConfig::from_urls(&[RELAY.to_string()]).unwrap();
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[tokio::test]
    async fn default_relays_are_not_probed() {
        // Must return immediately without touching the network.
        tokio::time::timeout(
            Duration::from_millis(100),
            probe_custom_relays(&RelayConfig::Default),
        )
        .await
        .expect("no probe for the default relays")
        .unwrap();
    }
}
