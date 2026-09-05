//! Relay configuration, the shared relay auth token, and the per-relay startup
//! probe.
//!
//! The design is documented in
//! <https://github.com/flexaccessdev/iroh-common-architecture> (see
//! `relays-and-address-lookup.md`); this module is its implementation.

use anyhow::{Context, Result};
use futures::future::join_all;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, endpoint::presets};
use log::{info, warn};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// How long a freshly bound endpoint (or a relay probe) may take to come
/// online before that is treated as a relay connectivity failure.
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The fewest distinct custom relays a configuration may name. Relay failover
/// needs somewhere to fail over *to*; the default relay map is n0's and is
/// not subject to this.
pub const MIN_CUSTOM_RELAYS: usize = 2;

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
#[derive(Clone, PartialEq, Eq, Default)]
pub enum RelayConfig {
    /// iroh's default relay map, with n0 address lookup.
    #[default]
    Default,
    /// Custom relay set (parsed, deduped, in configured order). Never fewer
    /// than [`MIN_CUSTOM_RELAYS`] distinct relays: a server keeps working
    /// through a relay outage only by moving onto another configured relay,
    /// and with one relay there is nothing to move to (see
    /// [`crate::relay_failover`]).
    ///
    /// The configured order is kept because it is meaningful to a relay-only
    /// dialer, which tries the relays one at a time: the first URL is the
    /// preferred relay. Only exact duplicates are dropped (first occurrence
    /// wins).
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

/// Manual `Debug` so the relay auth token is never written to logs or error
/// messages: `Custom.auth_token` is shown only as a redacted marker (present
/// vs. absent), while `urls` keep their normal `Debug` formatting.
impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("Default"),
            Self::Custom { urls, auth_token } => f
                .debug_struct("Custom")
                .field("urls", urls)
                .field("auth_token", &auth_token.as_ref().map(|_| RedactedToken))
                .finish(),
        }
    }
}

/// Placeholder used in place of the real auth token in `Debug` output.
struct RedactedToken;

impl fmt::Debug for RedactedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
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
    /// use site. Custom relays must number at least [`MIN_CUSTOM_RELAYS`]
    /// distinct URLs after deduplication (listing the same relay twice counts
    /// once): one relay leaves a server nothing to fail over to when it stops
    /// working, which is rejected up front rather than discovered during an
    /// outage.
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
        let mut parsed: Vec<RelayUrl> = Vec::with_capacity(urls.len());
        for url in urls {
            let url = url
                .parse::<RelayUrl>()
                .with_context(|| format!("Invalid relay URL: {url}"))?;
            if !parsed.contains(&url) {
                parsed.push(url);
            }
        }
        if parsed.len() < MIN_CUSTOM_RELAYS {
            anyhow::bail!(
                "custom relays need at least {MIN_CUSTOM_RELAYS} distinct relay_urls (got {}): a \
                 server rides out a relay outage by moving onto another configured relay, and \
                 with one relay there is nothing to fail over to",
                parsed.len()
            );
        }
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
                RelayMode::Custom(relay_map(urls.iter().cloned(), auth_token.as_deref()))
            }
        }
    }

    /// The custom relay map without `excluded`: what an endpoint is bound
    /// with when some configured relays failed the startup probe (see
    /// [`crate::endpoint::create_endpoint`]). The auth token is applied as in
    /// [`Self::relay_mode`]. Empty for the default relays.
    pub fn relay_map_without(&self, excluded: &[RelayUrl]) -> RelayMap {
        match self {
            Self::Default => RelayMap::empty(),
            Self::Custom { urls, auth_token } => relay_map(
                urls.iter().filter(|url| !excluded.contains(url)).cloned(),
                auth_token.as_deref(),
            ),
        }
    }

    /// Log which relays are in use (silent for the default relays). Only ever
    /// reports *whether* an auth token is set — never the token itself.
    pub fn log_status(&self) {
        let auth = if self.relay_auth_token().is_some() {
            " (authenticated)"
        } else {
            ""
        };
        match self.custom_urls().len() {
            0 => {}
            n => info!("Using {n} custom relay servers with failover{auth}"),
        }
    }
}

/// A relay map of `urls`, with `auth_token` (when set) applied to every relay.
fn relay_map(urls: impl IntoIterator<Item = RelayUrl>, auth_token: Option<&str>) -> RelayMap {
    let map = RelayMap::from_iter(urls);
    match auth_token {
        Some(token) => map.with_auth_token(token.to_string()),
        None => map,
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
fn probe_endpoint_builder(
    relay_url: &RelayUrl,
    auth_token: Option<&str>,
) -> iroh::endpoint::Builder {
    let map = relay_map([relay_url.clone()], auth_token);
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
pub(crate) async fn probe_relay(relay_url: &RelayUrl, auth_token: Option<&str>) -> Result<()> {
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

/// Probe every configured custom relay individually (in parallel). Startup
/// fails only if **every** relay is unreachable; each relay that does not
/// come online is reported as a warning and returned, so the caller can bind
/// the endpoint without it. Default relays are not probed (returns an empty
/// list immediately).
///
/// Probing each relay on its own is what makes this possible: a single
/// endpoint-wide `online()` wait proves only that *one* relay (the home
/// relay) connected and says nothing about the others.
///
/// A relay that is down at startup must not stop the process: with at least
/// [`MIN_CUSTOM_RELAYS`] distinct relays configured, the remaining ones carry
/// it, and refusing to start would turn a survivable relay outage into an
/// outage of every client that restarts during it. Nor may it stay in the
/// relay map: iroh picks its home relay by probe latency, and a relay that
/// answers probes but cannot be connected (the outage shape of
/// [`crate::relay_failover`]) would be preferred, never connect, and keep the
/// endpoint from ever coming online — every client that restarts during such
/// an outage would then fail to start, even though the other relay works and
/// the server has already failed over to it.
pub async fn probe_custom_relays(relay_config: &RelayConfig) -> Result<Vec<RelayUrl>> {
    let RelayConfig::Custom { urls, auth_token } = relay_config else {
        return Ok(Vec::new());
    };
    let token = auth_token.as_deref();
    info!("Probing {} custom relays for reachability...", urls.len());
    let results = join_all(
        urls.iter()
            .map(|url| async move { (url, probe_relay(url, token).await) }),
    )
    .await;
    let failures: Vec<(RelayUrl, anyhow::Error)> = results
        .into_iter()
        .filter_map(|(url, res)| res.err().map(|e| (url.clone(), e)))
        .collect();
    let describe = |failures: &[(RelayUrl, anyhow::Error)]| {
        failures
            .iter()
            .map(|(url, e)| format!("{url}: {e}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    };
    if failures.len() == urls.len() {
        anyhow::bail!(
            "all {} custom relays failed to come online:\n  {}",
            urls.len(),
            describe(&failures)
        );
    }
    if !failures.is_empty() {
        warn!(
            "{} of {} custom relays failed to come online; continuing with the rest, but a \
             further relay failure now has less to fail over to. They are left out of the \
             relay map so the endpoint homes on a relay that works, and are put back once \
             they are connectable again (see relay_failover):\n  {}",
            failures.len(),
            urls.len(),
            describe(&failures)
        );
    }
    Ok(failures.into_iter().map(|(url, _)| url).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "https://relay.example.com./";
    const RELAY2: &str = "https://relay2.example.com./";

    fn two() -> [String; 2] {
        [RELAY.to_string(), RELAY2.to_string()]
    }

    #[test]
    fn relay_map_without_drops_only_the_excluded_relays_and_keeps_the_token() {
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("secret".to_string())).unwrap();
        let relay: RelayUrl = RELAY.parse().unwrap();
        let relay2: RelayUrl = RELAY2.parse().unwrap();
        let map = cfg.relay_map_without(std::slice::from_ref(&relay));
        assert!(!map.contains(&relay));
        assert!(map.contains(&relay2));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&relay2).unwrap().auth_token.as_deref(), Some("secret"));
        let full = cfg.relay_map_without(&[]);
        assert_eq!(full.len(), 2);
        assert!(RelayConfig::Default.relay_map_without(&[relay]).is_empty());
    }

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
    fn a_single_custom_url_is_rejected() {
        let err = RelayConfig::from_urls(&[RELAY.to_string()])
            .expect_err("one custom relay leaves nothing to fail over to");
        assert!(
            err.to_string().contains("at least 2 distinct relay_urls (got 1)"),
            "unexpected error: {err}"
        );
        // Repeats of one URL are still one relay.
        let err = RelayConfig::from_urls(&[RELAY.to_string(), RELAY.to_string()])
            .expect_err("a duplicated relay is still one relay");
        assert!(
            err.to_string().contains("(got 1)"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn custom_urls_without_token() {
        let cfg = RelayConfig::from_urls_with_token(&two(), None).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.custom_urls().len(), 2);
        assert_eq!(cfg.relay_auth_token(), None);
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn custom_urls_keep_configured_order_while_deduping() {
        // A relay-only dialer walks custom_urls() in order, so the configured
        // order is the failover order and must survive dedup unsorted.
        let cfg = RelayConfig::from_urls(&[
            "https://b.example.com./".to_string(),
            "https://a.example.com./".to_string(),
            "https://b.example.com./".to_string(),
        ])
        .unwrap();
        let urls: Vec<String> = cfg.custom_urls().iter().map(ToString::to_string).collect();
        assert_eq!(urls, ["https://b.example.com./", "https://a.example.com./"]);
    }

    #[test]
    fn custom_urls_with_token_trimmed() {
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("  secret\n".to_string())).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), Some("secret"));
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn token_is_trimmed_to_none_with_custom_urls() {
        // A blank token alongside custom relays is simply no token, not an error.
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("  ".to_string())).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn debug_output_redacts_auth_token() {
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("secret".to_string())).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("secret"),
            "token leaked in Debug output: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "unexpected Debug output: {dbg}");
        assert!(dbg.contains(RELAY), "urls missing from Debug output: {dbg}");

        let no_token = RelayConfig::from_urls(&two()).unwrap();
        assert!(format!("{no_token:?}").contains("auth_token: None"));
        assert_eq!(format!("{:?}", RelayConfig::Default), "Default");
    }

    #[test]
    fn from_urls_carries_no_token() {
        let cfg = RelayConfig::from_urls(&two()).unwrap();
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
