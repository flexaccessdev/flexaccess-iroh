//! On-demand health check of the configured custom relays, for status UIs.
//!
//! [`probe_custom_relay_health`] asks each custom relay for its `/healthz`
//! route over plain HTTP(S) and reports whether it answered. It is a
//! *different* thing from the startup probe in [`crate::relay`]: `/healthz` is
//! unauthenticated, so it confirms the relay is *up*, not that the relay auth
//! token is accepted. It runs only when called (a status command, a
//! connection-path sheet), never on a timer.
//!
//! The route is joined onto the relay URL as a relative path, the way iroh
//! joins `relay` to dial the relay, so a relay served under a path prefix
//! (`https://example.com/prefix/`) is checked under that prefix and not at the
//! host's root.

use std::{sync::Arc, time::Duration};

use futures::future::join_all;
use iroh::RelayUrl;
use serde::{Deserialize, Serialize};

use crate::relay::RelayConfig;

/// Per-request timeout for the `/healthz` check. Kept short so an on-demand
/// status call stays responsive even when a relay is unreachable.
pub const HEALTHZ_TIMEOUT: Duration = Duration::from_secs(3);

/// The relay's health route, relative to the relay URL.
const HEALTHZ_RELATIVE_PATH: &str = "healthz";

/// Health of one configured custom relay, from an on-demand `/healthz` probe.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomRelayStatus {
    pub url: String,
    /// `Some(true)` when the relay's `/healthz` returned a 2xx, `Some(false)`
    /// when it failed (unreachable, timed out, or a non-2xx response), or `None`
    /// if the check could not be run at all (e.g. the HTTP client failed to
    /// build). Note this probes the relay's plain HTTP health endpoint, which is
    /// unauthenticated — it confirms the relay is up, not that the auth token is
    /// accepted (the startup per-relay `online()` probe validates the token).
    pub working: Option<bool>,
    pub error: Option<String>,
}

/// TLS client config for the `/healthz` probe: ring plus the embedded Mozilla
/// roots, i.e. exactly what iroh uses to verify the relay's own TLS (its
/// `platform-verifier` feature is off), so a relay the endpoint trusts is one
/// the health check trusts. reqwest's own default on the `rustls-no-provider`
/// feature is `rustls-platform-verifier`; handing reqwest a preconfigured config
/// keeps that verifier out entirely, and needs no process-wide crypto provider.
fn healthz_tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Probe the `/healthz` endpoint of every configured custom relay in parallel.
/// Empty for the default relays (nothing custom to check). The result keeps
/// the configured relay order.
pub async fn probe_custom_relay_health(relay_config: &RelayConfig) -> Vec<CustomRelayStatus> {
    let urls = relay_config.custom_urls();
    if urls.is_empty() {
        return Vec::new();
    }
    let client = match reqwest::Client::builder()
        .tls_backend_preconfigured(healthz_tls_config())
        .timeout(HEALTHZ_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            let err = format!("failed to build health-check client: {e}");
            return urls
                .iter()
                .map(|url| CustomRelayStatus {
                    url: url.to_string(),
                    working: None,
                    error: Some(err.clone()),
                })
                .collect();
        }
    };
    join_all(urls.iter().map(|url| probe_relay_healthz(&client, url))).await
}

/// The `/healthz` URL of a relay. `RelayUrl` always ends its path in `/`, so
/// the relative join keeps a path prefix instead of replacing its last segment.
fn relay_healthz_url(url: &RelayUrl) -> Result<reqwest::Url, String> {
    url.join(HEALTHZ_RELATIVE_PATH).map_err(|e| e.to_string())
}

/// Probe one relay's `/healthz`. `working` is `Some(true)` on a 2xx response,
/// `Some(false)` otherwise (unreachable, timeout, or non-2xx).
async fn probe_relay_healthz(client: &reqwest::Client, url: &RelayUrl) -> CustomRelayStatus {
    let healthz = match relay_healthz_url(url) {
        Ok(healthz) => healthz,
        Err(e) => {
            return CustomRelayStatus {
                url: url.to_string(),
                working: Some(false),
                error: Some(format!("invalid relay URL: {e}")),
            };
        }
    };
    match client.get(healthz).send().await {
        Ok(resp) if resp.status().is_success() => CustomRelayStatus {
            url: url.to_string(),
            working: Some(true),
            error: None,
        },
        Ok(resp) => CustomRelayStatus {
            url: url.to_string(),
            working: Some(false),
            error: Some(format!("/healthz returned HTTP {}", resp.status())),
        },
        Err(e) => CustomRelayStatus {
            url: url.to_string(),
            working: Some(false),
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn healthz_url_follows_the_relay_urls_path_prefix() {
        let healthz = |relay: &str| {
            let relay: RelayUrl = relay.parse().unwrap();
            relay_healthz_url(&relay).unwrap().to_string()
        };
        assert_eq!(healthz("https://relay.example.com"), "https://relay.example.com/healthz");
        assert_eq!(healthz("https://relay.example.com/"), "https://relay.example.com/healthz");
        assert_eq!(
            healthz("https://relay.example.com/vpn/"),
            "https://relay.example.com/vpn/healthz"
        );
        // `RelayUrl` adds the trailing slash a configured prefix lacks.
        assert_eq!(
            healthz("https://relay.example.com/vpn"),
            "https://relay.example.com/vpn/healthz"
        );
    }

    /// A one-request-per-connection HTTP server that answers 200 on the paths
    /// in `healthy` and 404 everywhere else. Returns its `http://` origin.
    async fn spawn_http_server(healthy: &'static [&'static str]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request);
                    let path = request.split_whitespace().nth(1).unwrap_or_default();
                    let status = if healthy.contains(&path) {
                        "200 OK"
                    } else {
                        "404 Not Found"
                    };
                    let response =
                        format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        origin
    }

    #[tokio::test]
    async fn default_relays_have_nothing_to_check() {
        assert!(probe_custom_relay_health(&RelayConfig::Default).await.is_empty());
    }

    #[tokio::test]
    async fn probes_each_relay_under_its_own_path_prefix() {
        // Healthy only under `/up/`: a probe of the host's root `/healthz`, or
        // of the other relay's prefix, gets a 404.
        let origin = spawn_http_server(&["/up/healthz"]).await;
        let up = format!("{origin}/up/");
        let down = format!("{origin}/down/");
        let config = RelayConfig::from_urls(&[up.clone(), down.clone()]).unwrap();

        let health = probe_custom_relay_health(&config).await;

        assert_eq!(
            health,
            vec![
                CustomRelayStatus {
                    url: up,
                    working: Some(true),
                    error: None,
                },
                CustomRelayStatus {
                    url: down,
                    working: Some(false),
                    error: Some("/healthz returned HTTP 404 Not Found".to_string()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_reported_as_not_working() {
        // Bind and drop a listener to get a port nothing listens on.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let origin = spawn_http_server(&["/healthz"]).await;
        let config = RelayConfig::from_urls(&[origin, format!("http://{closed}")]).unwrap();

        let health = probe_custom_relay_health(&config).await;

        assert_eq!(health[0].working, Some(true));
        assert_eq!(health[1].working, Some(false));
        assert!(health[1].error.is_some());
    }
}
