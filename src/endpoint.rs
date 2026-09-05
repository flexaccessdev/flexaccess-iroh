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

use crate::lookup::LookupConfig;
use crate::relay::{RELAY_CONNECT_TIMEOUT, RelayConfig, probe_custom_relays};
use anyhow::{Context, Result};
use futures::future::BoxFuture;
use iroh::{
    Endpoint, EndpointId, TransportAddr,
    address_lookup::{
        DEFAULT_PKARR_TTL, DnsAddressLookup, EndpointData, EndpointInfo, PkarrPublisher,
        PkarrRelayClient, PkarrResolver,
    },
    endpoint::{Builder as EndpointBuilder, QuicTransportConfig, presets},
};
use log::info;
use std::sync::Arc;
use std::time::Duration;

/// How long the first publish of a server's address record may take. It is a
/// single HTTP PUT to the lookup service; a Cloudflare-tunnelled service
/// answers in well under a second.
pub const LOOKUP_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

/// What an application decides about every endpoint it builds.
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// The application's QUIC transport tuning (idle timeout, keep-alive, MTU,
    /// windows, congestion control), applied to every endpoint. This is
    /// product-specific by design — a VPN's datagram path and a proxy's
    /// stream path want different settings.
    pub transport_config: QuicTransportConfig,
    /// Whether to publish this endpoint's address record: to n0's pkarr
    /// service on the default relays, to the configured lookup service with
    /// custom relays. A server with a persistent identity publishes so clients
    /// can resolve it by id; a client that only dials out should not
    /// advertise itself. Only the relay URL is ever published, never IP
    /// addresses.
    pub publish_address: bool,
    /// Reach peers **only** through the configured relays: the direct IP
    /// transports are dropped and no local-network discovery (mDNS) is added,
    /// so nothing can ever produce a direct path. The address lookup service
    /// stays, since it carries relay URLs only. A testing and reference mode
    /// for a self-hosted relay deployment; only meaningful with custom relays
    /// (the default relays are rate-limited).
    pub relay_only: bool,
}

/// Create a base endpoint builder with the common configuration.
///
/// Internet address lookup (pkarr publishing of the home relay and
/// resolution of a peer's, see
/// <https://docs.iroh.computer/concepts/address-lookup>) follows the relay
/// mode:
///
/// - [`RelayConfig::Default`]: the n0 lookup stack — DNS resolution of
///   `_iroh.<endpoint-id>.dns.iroh.link` is always on, and pkarr publishing
///   to n0 is added only when [`EndpointOptions::publish_address`] is set.
/// - [`RelayConfig::Custom`]: the configured self-hosted lookup service —
///   pkarr resolution over HTTP is always on, and pkarr publishing is added
///   only when `publish_address` is set. Nothing is published to or resolved
///   from n0's infrastructure. Dialers may still attach relay hints to the
///   peer's `EndpointAddr`; the lookup record is what reaches them once the
///   peer has moved to a relay the hints do not name.
///
/// With the `mdns` feature, mDNS local-network discovery is added independent
/// of the relay mode (except on iOS, where it is compiled out).
///
/// [`EndpointOptions::relay_only`] then clears the IP transports and skips
/// mDNS; the internet lookup stays.
pub fn endpoint_builder(relay_config: &RelayConfig, options: EndpointOptions) -> EndpointBuilder {
    // iroh 1.x requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    let mut builder = Endpoint::builder(presets::Empty)
        .relay_mode(relay_config.relay_mode())
        .transport_config(options.transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));

    match relay_config.lookup() {
        Some(lookup) => {
            let pkarr_url = lookup.pkarr_url();
            if options.publish_address {
                builder = builder.address_lookup(PkarrPublisher::builder(pkarr_url.clone()));
            }
            builder = builder.address_lookup(PkarrResolver::builder(pkarr_url));
            info!(
                "Address lookup via {} (custom relays; nothing goes to n0)",
                lookup.display_host()
            );
        }
        None => {
            if options.publish_address {
                builder = builder.address_lookup(PkarrPublisher::n0_dns());
            }
            builder = builder.address_lookup(DnsAddressLookup::n0_dns());
        }
    }

    if options.relay_only {
        info!("Relay-only mode: no direct paths and no local-network discovery");
        return builder.clear_ip_transports();
    }
    #[cfg(all(feature = "mdns", not(target_os = "ios")))]
    {
        builder = builder.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
    }

    builder
}

/// Publish the endpoint's address record to the lookup service now, in the
/// foreground, and fail if the service rejects it.
///
/// iroh's own publisher does the same in the background and keeps
/// republishing for the life of the endpoint, but it only logs failures and
/// retries forever. A server that cannot publish is unreachable to every
/// client that does not already know its relay, so the first publish is done
/// here where a wrong `lookup_secret` (a `404` from the reverse proxy), a
/// wrong host, or a service that is down stops the program with the reason.
/// The record carries the relay URLs only, never IP addresses, exactly like
/// the background publisher's.
///
/// Requires the endpoint to be online (it has a home relay to publish).
pub async fn publish_address_record(endpoint: &Endpoint, lookup: &LookupConfig) -> Result<()> {
    let addr = endpoint.addr();
    let relays: Vec<TransportAddr> = addr
        .relay_urls()
        .map(|url| TransportAddr::Relay(url.clone()))
        .collect();
    if relays.is_empty() {
        anyhow::bail!("Endpoint has no home relay to publish (is it online?)");
    }
    let relay_list: Vec<String> = addr.relay_urls().map(ToString::to_string).collect();
    let info = EndpointInfo::from_parts(endpoint.id(), EndpointData::new(relays));
    let packet = info
        .to_pkarr_signed_packet(endpoint.secret_key(), DEFAULT_PKARR_TTL)
        .map_err(|e| anyhow::anyhow!("{e:#}"))
        .context("Failed to sign the address record")?;
    let dns_resolver = endpoint
        .dns_resolver()
        .map_err(|e| anyhow::anyhow!("{e:#}"))
        .context("Endpoint has no DNS resolver")?
        .clone();
    let client = PkarrRelayClient::new(lookup.pkarr_url(), endpoint.tls_config().clone(), dns_resolver);
    let host = lookup.display_host();
    match tokio::time::timeout(LOOKUP_PUBLISH_TIMEOUT, client.publish(&packet)).await {
        Ok(Ok(())) => {
            info!(
                "Published address record to the lookup service at {host} (relay: {})",
                relay_list.join(", ")
            );
            Ok(())
        }
        Ok(Err(e)) => anyhow::bail!(
            "Failed to publish the address record to the lookup service at {host}: {e:#}. \
             Check lookup_url and lookup_secret, and that the service is up (a wrong secret is a 404)"
        ),
        Err(_) => anyhow::bail!(
            "Publishing the address record to the lookup service at {host} timed out after {}s",
            LOOKUP_PUBLISH_TIMEOUT.as_secs()
        ),
    }
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
/// relay (fail if any is unreachable — configuration validation), bind,
/// require the endpoint to come online, and — for an endpoint that publishes
/// its address (`publishes_address`, the same value the builder was given as
/// [`EndpointOptions::publish_address`]) on custom relays — publish its
/// record to the lookup service in the foreground, failing if the service
/// rejects it (see [`publish_address_record`]). On failure after binding the
/// endpoint is closed before the error propagates (dropping a bound endpoint
/// without `close()` is fatal under `panic = "abort"`).
pub async fn create_endpoint(
    relay_config: &RelayConfig,
    builder: EndpointBuilder,
    publishes_address: bool,
) -> Result<Endpoint> {
    relay_config.log_status();
    probe_custom_relays(relay_config).await?;
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    if let Err(e) = wait_online(&endpoint).await {
        endpoint.close().await;
        return Err(e);
    }
    if publishes_address && let Some(lookup) = relay_config.lookup()
        && let Err(e) = publish_address_record(&endpoint, lookup).await
    {
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
///   and the client's reconnect escalation retries if the relays stay unreachable.
/// - **No foreground publish.** A rebuilt endpoint that publishes leaves it
///   to iroh's background publisher, which retries until the service answers.
pub async fn rebuild_endpoint(builder: EndpointBuilder) -> Result<Endpoint> {
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    if let Err(e) = wait_online(&endpoint).await {
        log::warn!("Rebuilt endpoint: {e:#}; continuing (local discovery may still work)");
    }
    Ok(endpoint)
}

/// Recipe producing a fresh, fully bound endpoint — how a
/// [`RebuildableEndpoint`] replaces itself mid-session.
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
