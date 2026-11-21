//! Endpoint construction shared by every FlexAccess program: the common
//! builder and the bind-and-come-online policy.
//!
//! Identity is the application's: it reads and decodes its own secret-key
//! file (or generates an ephemeral key) and binds the resulting
//! [`iroh::SecretKey`] on the builder itself.
//!
//! Applications layer their own ALPNs, hooks, identity, and QUIC transport
//! tuning onto the [`iroh::endpoint::Builder`] returned by
//! [`endpoint_builder`], then hand it to [`create_endpoint`].

use crate::relay::{RELAY_CONNECT_TIMEOUT, RelayConfig, probe_custom_relays};
use anyhow::{Context, Result};
use iroh::{
    Endpoint, RelayMode, RelayUrl,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, QuicTransportConfig, presets},
};
use log::{info, warn};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

/// Bound wait on the graceful close of an endpoint this crate bound and is
/// giving up on: one that never came online, or a relay probe's. iroh's close
/// has no deadline of its own, and both are closed exactly when the network
/// is not answering — a start must fail with its reason, and a probe report
/// its relay, not sit behind a teardown. The close runs as its own task and
/// is never cancelled by this wait; one that outlives it is kept in the
/// caller's [`PendingCloses`].
pub(crate) const ENDPOINT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The endpoint closes this crate stopped waiting for (see
/// [`ENDPOINT_CLOSE_TIMEOUT`]) and left running on the runtime.
///
/// Every caller of [`create_endpoint`] hands one in, and so decides what
/// becomes of them. A runtime that goes away takes the closes still running
/// on it along, so a caller whose runtime ends with its request waits for
/// [`PendingCloses::finished`] before letting it go. A process whose runtime
/// lasts has nothing to do with them — they finish by themselves — and can
/// drop the set, which leaves them running. Clones share one set.
#[derive(Debug, Clone, Default)]
pub struct PendingCloses(Arc<Mutex<Vec<JoinHandle<()>>>>);

impl PendingCloses {
    pub fn new() -> Self {
        Self::default()
    }

    fn keep(&self, close: JoinHandle<()>) {
        self.0.lock().expect("pending closes lock").push(close);
    }

    /// Wait until every close kept here has finished, those added meanwhile
    /// included. Returns at once when there are none.
    pub async fn finished(&self) {
        loop {
            let closes = std::mem::take(&mut *self.0.lock().expect("pending closes lock"));
            if closes.is_empty() {
                return;
            }
            for close in closes {
                // A close that panicked or was aborted is over all the same.
                let _ = close.await;
            }
        }
    }
}

/// Close `endpoint` gracefully, waiting at most [`ENDPOINT_CLOSE_TIMEOUT`]
/// for it. A slower close is left to finish in the background, and kept in
/// `closes` for whoever needs to wait for it.
///
/// Either way the close has begun by the time this returns, which is what a
/// bound endpoint needs before it is dropped: iroh aborts one that is dropped
/// without `close()` having been called (fatal under `panic = "abort"`), and
/// leaves alone one that is already closing.
pub(crate) async fn close_endpoint(endpoint: Endpoint, closes: &PendingCloses) {
    let id = endpoint.id();
    let close = closed_within(ENDPOINT_CLOSE_TIMEOUT, async move { endpoint.close().await });
    if let Some(close) = close.await {
        warn!(
            "Endpoint {id} is slow to close; leaving it to finish in the background"
        );
        closes.keep(close);
    }
}

/// Run `close` on a task of its own and wait up to `limit` for it. `None`
/// when it finished in time; otherwise the task, which keeps running.
async fn closed_within(
    limit: Duration,
    close: impl Future<Output = ()> + Send + 'static,
) -> Option<JoinHandle<()>> {
    let mut close = tokio::spawn(close);
    match tokio::time::timeout(limit, &mut close).await {
        Ok(_) => None,
        Err(_) => Some(close),
    }
}

/// What an application decides about every endpoint it builds.
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// The application's QUIC transport tuning (idle timeout, keep-alive, MTU,
    /// windows, congestion control), applied to every endpoint. This is
    /// product-specific by design — a VPN's datagram path and a proxy's
    /// stream path want different settings.
    pub transport_config: QuicTransportConfig,
    /// Whether to publish this endpoint's address to n0's pkarr DNS when on the
    /// default relays (a no-op with custom relays, where internet discovery is
    /// off). A server with a persistent identity publishes so clients can
    /// resolve it by id; a client that only dials out should not advertise
    /// itself.
    pub publish_address: bool,
    /// Reach peers **only** through the configured relays: the direct IP
    /// transports are dropped and no address lookup of any kind (n0 internet
    /// discovery, mDNS) is added, so nothing can ever produce a direct path.
    /// A testing and reference mode for a self-hosted relay deployment; only
    /// meaningful with custom relays (the default relays are rate-limited).
    pub relay_only: bool,
}

/// Create a base endpoint builder with the common configuration.
///
/// iroh *internet* discovery (n0 pkarr publishing + DNS-based lookup of
/// `_iroh.<endpoint-id>.dns.iroh.link`, see
/// <https://docs.iroh.computer/concepts/address-lookup>) follows the relay mode:
///
/// - [`RelayConfig::Default`]: the n0 lookup stack is enabled — DNS resolution
///   is always on, and pkarr publishing is added only when
///   [`EndpointOptions::publish_address`] is set.
/// - [`RelayConfig::Custom`]: n0 internet discovery is disabled — nothing is
///   published to or resolved from n0's public infrastructure. Dialers reach
///   peers through relay hints attached to the peer's `EndpointAddr`: iroh
///   sends QUIC Initials to every configured relay, so the handshake succeeds
///   via whichever relay the peer is homed on.
///
/// With the `mdns` feature, mDNS local-network discovery is added independent
/// of the relay mode (except on iOS, where it is compiled out).
///
/// [`EndpointOptions::relay_only`] overrides all of that: the IP transports
/// are cleared and no address lookup at all is added.
pub fn endpoint_builder(relay_config: &RelayConfig, options: EndpointOptions) -> EndpointBuilder {
    // iroh 1.x requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    let mut builder = Endpoint::builder(presets::Empty)
        .relay_mode(relay_config.relay_mode())
        .transport_config(options.transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));

    if options.relay_only {
        info!("Relay-only mode: no direct paths and no address lookup");
        return builder.clear_ip_transports();
    }

    if relay_config.is_custom() {
        info!("Internet discovery disabled (custom relays configured)");
    } else {
        if options.publish_address {
            builder = builder.address_lookup(PkarrPublisher::n0_dns());
        }
        builder = builder.address_lookup(DnsAddressLookup::n0_dns());
    }
    #[cfg(all(feature = "mdns", not(target_os = "ios")))]
    {
        builder = builder.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
    }

    builder
}

/// Wait for a freshly bound endpoint to come online (relay/discovery ready),
/// bounded by [`RELAY_CONNECT_TIMEOUT`]. Does not close the endpoint on
/// failure; the caller decides.
async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        RELAY_CONNECT_TIMEOUT.as_secs()
    );
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => Ok(()),
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// What [`create_endpoint`] hands back: the bound, online endpoint and the
/// custom relays it was bound without.
#[derive(Debug)]
pub struct CreatedEndpoint {
    pub endpoint: Endpoint,
    /// The configured custom relays that failed the startup probe and were
    /// left out of the endpoint's relay map (see [`create_endpoint`]). Empty
    /// with the default relays or when every custom relay probed fine. Hand
    /// them to [`crate::relay_failover::fail_over_home_relay`], which puts
    /// each one back into the relay map once it is connectable again; a
    /// process that does not run the failover keeps them out for its
    /// lifetime.
    pub relays_left_out: Vec<RelayUrl>,
}

/// Create an endpoint: log the relay setup, probe every custom relay (fail
/// only if none is reachable; see [`probe_custom_relays`]), bind **without**
/// the relays that failed the probe, and require the endpoint to come online.
///
/// Leaving a failed relay out of the relay map is what lets the endpoint come
/// online during that relay's outage: iroh picks its home relay by probe
/// latency, so a relay that still answers probes but cannot be connected (the
/// outage [`crate::relay_failover`] exists for) would otherwise be preferred,
/// never connect, and keep [`Endpoint::online`] pending until the timeout
/// here fails the whole start. The relay comes back through the failover's
/// restore probe; see [`CreatedEndpoint::relays_left_out`].
///
/// On failure after binding the endpoint is closed before the error
/// propagates (dropping a bound endpoint without `close()` is fatal under
/// `panic = "abort"`). The close is waited for up to
/// [`ENDPOINT_CLOSE_TIMEOUT`], so a slow teardown cannot keep the error back.
///
/// A close that outlives that wait — this endpoint's, or a relay probe's —
/// keeps running and is kept in `closes`, whether the endpoint was created
/// or not; see [`PendingCloses`] for what a caller owes them.
pub async fn create_endpoint(
    relay_config: &RelayConfig,
    builder: EndpointBuilder,
    closes: &PendingCloses,
) -> Result<CreatedEndpoint> {
    relay_config.log_status();
    let relays_left_out = probe_custom_relays(relay_config, closes).await?;
    let builder = if relays_left_out.is_empty() {
        builder
    } else {
        warn!(
            "Binding without {} of {} custom relays: {}",
            relays_left_out.len(),
            relay_config.custom_urls().len(),
            relays_left_out
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        builder.relay_mode(RelayMode::Custom(
            relay_config.relay_map_without(&relays_left_out),
        ))
    };
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    if let Err(e) = wait_online(&endpoint).await {
        close_endpoint(endpoint, closes).await;
        return Err(e);
    }
    Ok(CreatedEndpoint {
        endpoint,
        relays_left_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A close that takes its time is waited for up to the limit and no
    /// longer — and goes on by itself, rather than being cut off.
    #[tokio::test(start_paused = true)]
    async fn a_slow_close_is_waited_for_only_so_long() {
        assert!(closed_within(ENDPOINT_CLOSE_TIMEOUT, async {}).await.is_none());

        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let (done, mut finished) = tokio::sync::oneshot::channel::<()>();
        let started = tokio::time::Instant::now();
        let left_running = closed_within(ENDPOINT_CLOSE_TIMEOUT, async move {
            let _ = released.await;
            let _ = done.send(());
        })
        .await;
        assert!(left_running.is_some());
        assert_eq!(started.elapsed(), ENDPOINT_CLOSE_TIMEOUT);
        assert!(finished.try_recv().is_err(), "still closing");

        release.send(()).unwrap();
        finished.await.expect("the close ran to its end");
    }

    /// An endpoint handed over for closing is closed: nothing is left for its
    /// drop to abort.
    #[tokio::test]
    async fn an_endpoint_given_up_on_is_closed() {
        let endpoint = Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind()
            .await
            .unwrap();
        let handle = endpoint.clone();
        let closes = PendingCloses::new();
        close_endpoint(endpoint, &closes).await;
        assert!(handle.is_closed());
        // It closed within the wait, so there is nothing left to wait for.
        tokio::time::timeout(Duration::from_secs(1), closes.finished())
            .await
            .expect("no close is pending");
    }

    /// A close left running is kept, and waiting for the kept closes lasts
    /// until it is over — which is what a caller whose runtime is about to go
    /// away waits for.
    #[tokio::test(start_paused = true)]
    async fn a_close_left_running_can_be_waited_for() {
        let closes = PendingCloses::new();
        // Nothing kept: nothing to wait for.
        closes.finished().await;

        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let close = closed_within(ENDPOINT_CLOSE_TIMEOUT, async move {
            let _ = released.await;
        })
        .await
        .expect("left running");
        closes.keep(close);

        let waiting = closes.clone();
        let mut finished = tokio::spawn(async move { waiting.finished().await });
        assert!(
            tokio::time::timeout(Duration::from_secs(60), &mut finished).await.is_err(),
            "the close is still running"
        );
        release.send(()).unwrap();
        finished.await.unwrap();
        // And they are forgotten once finished.
        closes.finished().await;
    }
}
