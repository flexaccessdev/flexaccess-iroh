//! Relay configuration, the shared relay auth token, the address lookup
//! service custom relays require, and the per-relay startup probe.
//!
//! The design is documented in
//! <https://github.com/flexaccessdev/iroh-common-architecture> (see
//! `relays-and-address-lookup.md`); this module is its implementation.

use crate::lookup::LookupConfig;
use anyhow::{Context, Result};
use futures::future::join_all;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, endpoint::presets};
use log::info;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// How long a freshly bound endpoint (or a relay probe) may take to come
/// online before that is treated as a relay connectivity failure.
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The raw relay settings a program collects from its config file, command
/// line, and environment, before [`RelayConfig::resolve`] validates them.
///
/// Blank strings are treated as unset, so a program can pass through empty
/// config values without normalizing them first.
#[derive(Debug, Clone, Default)]
pub struct RelaySettings {
    /// Custom relay URLs; empty selects the default relays.
    pub relay_urls: Vec<String>,
    /// Shared bearer token for the custom relays.
    pub relay_auth_token: Option<String>,
    /// Scheme and host of the self-hosted address lookup service.
    pub lookup_url: Option<String>,
    /// The lookup service's secret (`lks1-...`).
    pub lookup_secret: Option<String>,
}

/// Relay configuration, resolved once from the raw settings.
///
/// This is the single source of the default-vs-custom distinction. It selects
/// both which relay map iroh uses **and** where address lookup happens:
/// [`Default`](Self::Default) uses the n0 relays with the n0 lookup stack
/// (pkarr publishing + DNS resolution of the peer's home relay — see
/// <https://docs.iroh.computer/concepts/address-lookup>), while
/// [`Custom`](Self::Custom) uses the configured relays with a self-hosted
/// lookup service in place of n0's, which is why that service is mandatory:
/// without a publish path a peer that moves to another relay is unreachable,
/// and the standard iroh failover cannot work. mDNS local-network discovery
/// is independent of this choice (see the `mdns` feature).
#[derive(Clone, PartialEq, Eq, Default)]
pub enum RelayConfig {
    /// iroh's default relay map, with n0 address lookup.
    #[default]
    Default,
    /// Custom relay set (parsed, deduped, in configured order). Never empty.
    ///
    /// The configured order is kept because it is meaningful to a relay-only
    /// dialer, which tries the relays one at a time: the first URL is the
    /// preferred relay. Only exact duplicates are dropped (first occurrence
    /// wins).
    ///
    /// `auth_token`, when set, is sent to every custom relay as an
    /// `Authorization: Bearer <token>` header on the WebSocket upgrade (see
    /// [`Self::relay_mode`]). It is only ever carried by custom relays — the
    /// default relays never receive a token (see [`Self::resolve`]).
    ///
    /// `lookup` is the self-hosted address lookup service: servers publish
    /// their relay URL to it and clients resolve peers from it.
    Custom {
        urls: Vec<RelayUrl>,
        auth_token: Option<String>,
        lookup: LookupConfig,
    },
}

/// Manual `Debug` so the relay auth token is never written to logs or error
/// messages: `Custom.auth_token` is shown only as a redacted marker (present
/// vs. absent), while `urls` keep their normal `Debug` formatting (and the
/// lookup config redacts its own secret).
impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("Default"),
            Self::Custom {
                urls,
                auth_token,
                lookup,
            } => f
                .debug_struct("Custom")
                .field("urls", urls)
                .field("auth_token", &auth_token.as_ref().map(|_| RedactedToken))
                .field("lookup", lookup)
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

/// Blank or whitespace-only settings count as unset.
fn non_blank(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// Where the mandatory lookup service is explained.
const LOOKUP_DOCS: &str =
    "https://github.com/flexaccessdev/iroh-common-architecture/blob/main/relays-and-address-lookup.md#custom-relays";

impl RelayConfig {
    /// Validate the raw settings into a relay configuration.
    ///
    /// No relay URLs selects the default relays; then the auth token and the
    /// lookup pair must be unset, since the default relays take no token and
    /// use n0's lookup. Custom relay URLs are parsed (failing on the first
    /// malformed one, so config typos surface at resolve time instead of at
    /// each use site) and **require** both `lookup_url` and `lookup_secret`;
    /// the secret's checksum is verified here. Every misconfiguration is a
    /// hard error before any endpoint starts.
    pub fn resolve(settings: RelaySettings) -> Result<Self> {
        let auth_token = non_blank(settings.relay_auth_token);
        let lookup_url = non_blank(settings.lookup_url);
        let lookup_secret = non_blank(settings.lookup_secret);
        if settings.relay_urls.is_empty() {
            if auth_token.is_some() {
                anyhow::bail!(
                    "relay_auth_token requires custom relay_urls; it is not used with the default iroh relays"
                );
            }
            if lookup_url.is_some() || lookup_secret.is_some() {
                anyhow::bail!(
                    "lookup_url and lookup_secret require custom relay_urls; the default iroh relays use n0's address lookup"
                );
            }
            return Ok(Self::Default);
        }
        let lookup = match (lookup_url, lookup_secret) {
            (Some(url), Some(secret)) => LookupConfig::new(&url, &secret)?,
            (url, secret) => {
                let missing = match (url.is_some(), secret.is_some()) {
                    (false, false) => "lookup_url and lookup_secret",
                    (false, true) => "lookup_url",
                    _ => "lookup_secret",
                };
                anyhow::bail!(
                    "custom relay_urls require a self-hosted address lookup service: {missing} not set (see {LOOKUP_DOCS})"
                );
            }
        };
        let mut parsed: Vec<RelayUrl> = Vec::with_capacity(settings.relay_urls.len());
        for url in &settings.relay_urls {
            let url = url
                .parse::<RelayUrl>()
                .with_context(|| format!("Invalid relay URL: {url}"))?;
            if !parsed.contains(&url) {
                parsed.push(url);
            }
        }
        Ok(Self::Custom {
            urls: parsed,
            auth_token,
            lookup,
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

    /// The self-hosted lookup service (custom relays only).
    pub fn lookup(&self) -> Option<&LookupConfig> {
        match self {
            Self::Default => None,
            Self::Custom { lookup, .. } => Some(lookup),
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
            Self::Custom {
                urls, auth_token, ..
            } => {
                let map = RelayMap::from_iter(urls.iter().cloned());
                let map = match auth_token {
                    Some(token) => map.with_auth_token(token.clone()),
                    None => map,
                };
                RelayMode::Custom(map)
            }
        }
    }

    /// Log which relays and lookup service are in use (silent for the default
    /// relays). Only ever reports *whether* an auth token is set — never the
    /// token — and names the lookup service by host, never its secret.
    pub fn log_status(&self) {
        let Self::Custom {
            urls,
            auth_token,
            lookup,
        } = self
        else {
            return;
        };
        let auth = if auth_token.is_some() {
            " (authenticated)"
        } else {
            ""
        };
        let host = lookup.display_host();
        match urls.len() {
            1 => info!("Using custom relay server{auth}; address lookup via {host}"),
            n => info!("Using {n} custom relay servers with failover{auth}; address lookup via {host}"),
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
fn probe_endpoint_builder(
    relay_url: &RelayUrl,
    auth_token: Option<&str>,
) -> iroh::endpoint::Builder {
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
    let RelayConfig::Custom {
        urls, auth_token, ..
    } = relay_config
    else {
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
    use crate::lookup::LookupSecret;

    const RELAY: &str = "https://relay.example.com./";
    const LOOKUP: &str = "https://lookup.example.com";

    fn custom(urls: &[&str]) -> RelaySettings {
        RelaySettings {
            relay_urls: urls.iter().map(ToString::to_string).collect(),
            relay_auth_token: None,
            lookup_url: Some(LOOKUP.to_string()),
            lookup_secret: Some(LookupSecret::generate().to_string()),
        }
    }

    #[test]
    fn empty_settings_are_default() {
        let cfg = RelayConfig::resolve(RelaySettings::default()).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
        assert!(!cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
        assert!(cfg.lookup().is_none());
        assert!(matches!(cfg.relay_mode(), RelayMode::Default));
    }

    #[test]
    fn blank_values_without_urls_are_default() {
        // Whitespace-only values normalize to unset, so they are not errors.
        let cfg = RelayConfig::resolve(RelaySettings {
            relay_urls: vec![],
            relay_auth_token: Some("   ".to_string()),
            lookup_url: Some(" ".to_string()),
            lookup_secret: Some("".to_string()),
        })
        .unwrap();
        assert_eq!(cfg, RelayConfig::Default);
    }

    #[test]
    fn token_without_custom_urls_is_error() {
        let err = RelayConfig::resolve(RelaySettings {
            relay_auth_token: Some("secret".to_string()),
            ..RelaySettings::default()
        })
        .expect_err("token without custom relays must be rejected");
        assert!(
            err.to_string().contains("relay_auth_token requires custom relay_urls"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lookup_without_custom_urls_is_error() {
        let err = RelayConfig::resolve(RelaySettings {
            lookup_url: Some(LOOKUP.to_string()),
            ..RelaySettings::default()
        })
        .expect_err("lookup without custom relays must be rejected");
        assert!(
            err.to_string().contains("require custom relay_urls"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn custom_urls_require_the_lookup_pair() {
        let mut settings = custom(&[RELAY]);
        settings.lookup_secret = None;
        let err = RelayConfig::resolve(settings).expect_err("missing secret must be rejected");
        assert!(err.to_string().contains("lookup_secret not set"), "unexpected error: {err}");

        let mut settings = custom(&[RELAY]);
        settings.lookup_url = None;
        let err = RelayConfig::resolve(settings).expect_err("missing url must be rejected");
        assert!(err.to_string().contains("lookup_url not set"), "unexpected error: {err}");

        let mut settings = custom(&[RELAY]);
        settings.lookup_url = None;
        settings.lookup_secret = None;
        let err = RelayConfig::resolve(settings).expect_err("missing pair must be rejected");
        assert!(
            err.to_string().contains("lookup_url and lookup_secret not set"),
            "unexpected error: {err}"
        );

        let mut settings = custom(&[RELAY]);
        settings.lookup_secret = Some("lks1-typo".to_string());
        let err = RelayConfig::resolve(settings).expect_err("bad secret must be rejected");
        assert!(err.to_string().contains("lookup_secret"), "unexpected error: {err}");
    }

    #[test]
    fn malformed_custom_url_is_rejected() {
        let err = RelayConfig::resolve(custom(&["not a url"]))
            .expect_err("malformed relay URL must be rejected");
        assert!(
            err.to_string().contains("Invalid relay URL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn custom_urls_with_lookup() {
        let settings = custom(&[RELAY]);
        let secret = settings.lookup_secret.clone().unwrap();
        let cfg = RelayConfig::resolve(settings).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.custom_urls().len(), 1);
        assert_eq!(cfg.relay_auth_token(), None);
        assert_eq!(
            cfg.lookup().unwrap().pkarr_url().as_str(),
            format!("{LOOKUP}/{secret}/pkarr")
        );
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn custom_urls_keep_configured_order_while_deduping() {
        // A relay-only dialer walks custom_urls() in order, so the configured
        // order is the failover order and must survive dedup unsorted.
        let cfg = RelayConfig::resolve(custom(&[
            "https://b.example.com./",
            "https://a.example.com./",
            "https://b.example.com./",
        ]))
        .unwrap();
        let urls: Vec<String> = cfg.custom_urls().iter().map(ToString::to_string).collect();
        assert_eq!(urls, ["https://b.example.com./", "https://a.example.com./"]);
    }

    #[test]
    fn token_is_trimmed() {
        let mut settings = custom(&[RELAY]);
        settings.relay_auth_token = Some("  secret\n".to_string());
        let cfg = RelayConfig::resolve(settings).unwrap();
        assert_eq!(cfg.relay_auth_token(), Some("secret"));

        // A blank token alongside custom relays is simply no token, not an error.
        let mut settings = custom(&[RELAY]);
        settings.relay_auth_token = Some("  ".to_string());
        let cfg = RelayConfig::resolve(settings).unwrap();
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut settings = custom(&[RELAY]);
        settings.relay_auth_token = Some("hunter2".to_string());
        let lookup_secret = settings.lookup_secret.clone().unwrap();
        let cfg = RelayConfig::resolve(settings).unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("hunter2"), "token leaked in Debug output: {dbg}");
        assert!(!dbg.contains(&lookup_secret[10..]), "lookup secret leaked: {dbg}");
        assert!(dbg.contains("<redacted>"), "unexpected Debug output: {dbg}");
        assert!(dbg.contains(RELAY), "urls missing from Debug output: {dbg}");
        assert!(dbg.contains(LOOKUP), "lookup host missing from Debug output: {dbg}");

        let no_token = RelayConfig::resolve(custom(&[RELAY])).unwrap();
        assert!(format!("{no_token:?}").contains("auth_token: None"));
        assert_eq!(format!("{:?}", RelayConfig::Default), "Default");
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
