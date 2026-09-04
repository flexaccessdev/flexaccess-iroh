//! Endpoint construction shared by every FlexAccess program: the common
//! builder, the creation-vs-rebuild policy, and a rebuildable endpoint handle.
//!
//! Identity is the application's: it reads and decodes its own secret-key
//! file (or generates an ephemeral key) and binds the resulting
//! [`iroh::SecretKey`] on the builder itself.
//!
//! Applications layer their own ALPNs, hooks, identity, and QUIC transport
//! tuning onto the [`iroh::endpoint::Builder`] returned by
//! [`endpoint_builder`], then hand it to [`create_endpoint`] (first creation:
//! strict) or [`rebuild_endpoint`] (mid-run replacement: tolerant).

use crate::relay::{RELAY_CONNECT_TIMEOUT, RelayConfig, probe_custom_relays};
use anyhow::{Context, Result};
use futures::future::BoxFuture;
use iroh::{
    Endpoint, EndpointId,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, QuicTransportConfig, presets},
};
use log::info;
use std::sync::Arc;
use std::time::Duration;

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
/// failure; the caller decides (creation closes and fails, a rebuild carries
/// on).
pub async fn wait_online(endpoint: &Endpoint) -> Result<()> {
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

/// First creation of an endpoint: log the relay setup, probe every custom
/// relay (fail if any is unreachable — configuration validation), bind, and
/// require the endpoint to come online. On failure after binding the endpoint
/// is closed before the error propagates (dropping a bound endpoint without
/// `close()` is fatal under `panic = "abort"`).
pub async fn create_endpoint(relay_config: &RelayConfig, builder: EndpointBuilder) -> Result<Endpoint> {
    relay_config.log_status();
    probe_custom_relays(relay_config).await?;
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    if let Err(e) = wait_online(&endpoint).await {
        endpoint.close().await;
        return Err(e);
    }
    Ok(endpoint)
}

/// Mid-run replacement of an endpoint, the recipe behind an
/// [`EndpointFactory`]. Differs from [`create_endpoint`] deliberately:
///
/// - **No per-relay probe.** At creation the probe validates the configuration
///   (fail fast if *any* relay is down); during an outage that strictness
///   would block recovery through the one relay that still answers.
/// - **The online wait is tolerated failing.** A fresh endpoint is no worse
///   than the wedged one it replaces — LAN peers can still find it over mDNS —
///   and whatever tripped the rebuild (the relay watchdog, a client's
///   reconnect escalation) trips again if the relays stay unreachable.
pub async fn rebuild_endpoint(builder: EndpointBuilder) -> Result<Endpoint> {
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    if let Err(e) = wait_online(&endpoint).await {
        log::warn!("Rebuilt endpoint: {e:#}; continuing (local discovery may still work)");
    }
    Ok(endpoint)
}

/// Recipe producing a fresh, fully bound endpoint — how a
/// [`RebuildableEndpoint`] replaces itself mid-session, or how a server
/// replaces a wedged endpoint when the relay watchdog gives up on it.
pub type EndpointFactory = Arc<dyn Fn() -> BoxFuture<'static, Result<Endpoint>> + Send + Sync>;

/// Bound wait on the old endpoint's graceful close during a rebuild. The close
/// runs as its own task and is never cancelled (dropping a bound endpoint
/// without `close()` is fatal under panic=abort); the bound only keeps the
/// caller's reconnect loop from stalling behind it, letting a slow close
/// finish in the background.
const REBUILD_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// An endpoint handle that can be **rebuilt** from scratch mid-session.
///
/// `Endpoint::network_change()` re-binds dead UDP transports, but a wedged
/// endpoint can be broken beyond what a rebind repairs: a relay link lost to a
/// ping timeout that never re-establishes, stale cached paths for the peer,
/// dead discovery state. A process restart always recovers because it builds a
/// brand-new endpoint; [`Self::rebuild`] gives a reconnect loop that same
/// remedy in-process — fresh sockets, fresh relay connections, fresh discovery
/// — without dropping anything else the process holds (bound listeners, a
/// control socket).
///
/// The handle is `Clone` and shared: a reconnect loop escalates to
/// [`Self::rebuild`] after repeated failures, while the embedder logs
/// [`Self::id`] and [`Self::close`]s whatever endpoint is current at teardown.
#[derive(Clone)]
pub struct RebuildableEndpoint {
    /// The live endpoint, swapped by [`Self::rebuild`]. Std lock: accessors
    /// clone the handle out synchronously and never hold it across an await.
    current: Arc<std::sync::RwLock<Current>>,
    factory: EndpointFactory,
    /// Serializes [`Self::rebuild`]'s build-and-swap: the handle is shared,
    /// and two callers noticing the same outage must not each build an
    /// endpoint and have the second discard (and close) the first's good one.
    rebuilding: Arc<tokio::sync::Mutex<()>>,
}

/// The installed endpoint plus how many rebuilds produced it, so a rebuild
/// caller can tell whether one already happened while it waited its turn.
struct Current {
    generation: u64,
    endpoint: Endpoint,
}

impl RebuildableEndpoint {
    /// Wrap a bound endpoint with the recipe that rebuilds it.
    pub fn from_parts(endpoint: Endpoint, factory: EndpointFactory) -> Self {
        Self {
            current: Arc::new(std::sync::RwLock::new(Current {
                generation: 0,
                endpoint,
            })),
            factory,
            rebuilding: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// A clone of the current endpoint handle. Take it fresh per use: a handle
    /// held across a [`Self::rebuild`] keeps pointing at the old, closed
    /// endpoint.
    pub fn endpoint(&self) -> Endpoint {
        self.current.read().expect("endpoint lock").endpoint.clone()
    }

    /// The current endpoint id. Changes on rebuild for an ephemeral identity;
    /// stable when the factory binds a fixed secret.
    pub fn id(&self) -> EndpointId {
        self.endpoint().id()
    }

    fn generation(&self) -> u64 {
        self.current.read().expect("endpoint lock").generation
    }

    /// Swap in a freshly built endpoint and close the old one. On error the
    /// current endpoint stays in place, so the caller can simply retry with it.
    ///
    /// Concurrent calls coalesce: a caller that arrives while another rebuild
    /// is in flight waits for it and, if it installed a fresh endpoint,
    /// returns `Ok` without building another — its trigger was the same dead
    /// endpoint, and [`Self::endpoint`] now yields the replacement. Only if
    /// the in-flight rebuild failed does the waiter build one itself.
    pub async fn rebuild(&self) -> Result<()> {
        let seen = self.generation();
        let old = {
            let _serialized = self.rebuilding.lock().await;
            if self.generation() != seen {
                info!(
                    "Endpoint already rebuilt by a concurrent caller; endpoint id: {}",
                    self.id()
                );
                return Ok(());
            }
            let fresh = (self.factory)().await?;
            let mut current = self.current.write().expect("endpoint lock");
            current.generation += 1;
            std::mem::replace(&mut current.endpoint, fresh)
        };
        // Graceful close on its own task: bounded wait here, but the task is
        // never cancelled (see [`REBUILD_CLOSE_TIMEOUT`]).
        let mut close = tokio::task::spawn(async move { old.close().await });
        if tokio::time::timeout(REBUILD_CLOSE_TIMEOUT, &mut close)
            .await
            .is_err()
        {
            log::warn!("Old endpoint's close is slow; leaving it to finish in the background");
        }
        info!("Endpoint rebuilt; endpoint id: {}", self.id());
        Ok(())
    }

    /// Close the current endpoint gracefully (session teardown).
    pub async fn close(&self) {
        self.endpoint().close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rebuildable_endpoint_swaps_and_closes_the_old_one() {
        // Hermetic: loopback-only endpoints, no relays, no discovery.
        fn loopback() -> EndpointBuilder {
            Endpoint::builder(presets::Empty)
                .relay_mode(iroh::RelayMode::Disabled)
                .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        }
        let first = loopback().bind().await.unwrap();
        let first_id = first.id();
        let handle = RebuildableEndpoint::from_parts(
            first.clone(),
            Arc::new(|| Box::pin(async { loopback().bind().await.map_err(Into::into) })),
        );
        assert_eq!(handle.id(), first_id);

        handle.rebuild().await.unwrap();
        assert_ne!(handle.id(), first_id, "an ephemeral rebuild gets a new id");
        assert!(first.is_closed(), "the replaced endpoint is closed");
        handle.close().await;
        assert!(handle.endpoint().is_closed());
    }

    #[tokio::test]
    async fn concurrent_rebuilds_coalesce_into_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn loopback() -> EndpointBuilder {
            Endpoint::builder(presets::Empty)
                .relay_mode(iroh::RelayMode::Disabled)
                .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        }
        let builds = Arc::new(AtomicUsize::new(0));
        let first = loopback().bind().await.unwrap();
        let handle = RebuildableEndpoint::from_parts(first.clone(), {
            let builds = builds.clone();
            Arc::new(move || {
                builds.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    // Hold the build long enough for the second caller to
                    // queue behind it.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    loopback().bind().await.map_err(Into::into)
                })
            })
        });

        let a = handle.clone();
        let b = handle.clone();
        let (ra, rb) = tokio::join!(a.rebuild(), async {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            b.rebuild().await
        });
        ra.unwrap();
        rb.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 1, "the second caller joined the first");
        assert!(first.is_closed());
        assert!(!handle.endpoint().is_closed(), "the one fresh endpoint is live");

        // A rebuild after the coalesced one is a new outage: it builds again.
        handle.rebuild().await.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        handle.close().await;
    }
}
