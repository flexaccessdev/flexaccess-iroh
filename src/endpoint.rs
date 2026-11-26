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

use crate::relay::{EndpointSlot, RELAY_CONNECT_TIMEOUT, RelayConfig, RelayProbes, wait_online_beside};
use anyhow::{Context, Result};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared, join_all};
use iroh::{
    Endpoint,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, QuicTransportConfig, presets},
};
use log::{info, warn};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::{AbortHandle, JoinHandle};

/// Bound wait on the graceful close of an endpoint being given up on: one
/// that never came online, a relay probe's, or a consumer's on an error exit
/// (see [`close_endpoint`]). iroh's close has no deadline of its own, and
/// these are closed exactly when the network is not answering — a start must
/// fail with its reason, a probe report its relay, and a process exit with
/// its status, not sit behind a teardown. The close runs as its own task and
/// is never cancelled by this wait; one that outlives it is kept in the
/// caller's [`PendingCloses`].
pub const ENDPOINT_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The endpoint closes this crate stopped waiting for (after 5 s) and left
/// running on the runtime, and the startup relay probes still running beside
/// a created endpoint (see [`RelayProbes`]), whose probe endpoints must be
/// closed the same way.
///
/// Every caller of [`create_endpoint`] hands one in, and so decides what
/// becomes of them. A runtime that goes away takes the closes still running
/// on it along, so a caller whose runtime ends with its request waits for
/// [`PendingCloses::finished`] before letting it go. A process whose runtime
/// lasts has nothing to do with them — they finish by themselves — and can
/// drop the set, which leaves them running. Clones share one set.
#[derive(Debug, Clone, Default)]
pub struct PendingCloses(Arc<Mutex<Vec<KeptClose>>>);

/// A close left running, as every waiter can wait for it: it stays in the set
/// until it is over, whoever is waiting and whether they keep waiting. The
/// task's abort handle (never used to abort) tells whether it is over without
/// polling it.
type KeptClose = (AbortHandle, Shared<BoxFuture<'static, ()>>);

impl PendingCloses {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn keep(&self, close: JoinHandle<()>) {
        drop(self.kept(close));
    }

    /// Keep `close`, and return a future for it that the caller can wait on
    /// as every other waiter does.
    fn kept(&self, close: JoinHandle<()>) -> Shared<BoxFuture<'static, ()>> {
        let over = close.abort_handle();
        // A close that panicked or was aborted is over all the same.
        let close = async move { drop(close.await) }.boxed().shared();
        let mut kept = self.0.lock().expect("pending closes lock");
        // Forget those already over, so that a set kept for the life of the
        // process does not grow with every endpoint created.
        kept.retain(|(over, _)| !over.is_finished());
        kept.push((over, close.clone()));
        close
    }

    /// Wait until every close kept here has finished, those added meanwhile
    /// included. Returns at once when there are none.
    ///
    /// Any number of callers can wait at once, and a wait that is dropped
    /// loses nothing: a close leaves the set only once it is over, so the
    /// next wait still finds it.
    pub async fn finished(&self) {
        loop {
            let closes = {
                let mut kept = self.0.lock().expect("pending closes lock");
                kept.retain(|(over, _)| !over.is_finished());
                kept.iter().map(|(_, close)| close.clone()).collect::<Vec<_>>()
            };
            if closes.is_empty() {
                return;
            }
            join_all(closes).await;
        }
    }
}

/// Close `endpoint` gracefully, waiting at most [`ENDPOINT_CLOSE_TIMEOUT`]
/// for it. A slower close is left to finish in the background. The close is
/// kept in `closes` from the moment it starts, for whoever needs to wait for
/// it, so a caller cancelled during the wait leaves nothing untracked.
///
/// Either way the close has begun by the time this returns, which is what a
/// bound endpoint needs before it is dropped: iroh aborts one that is dropped
/// without `close()` having been called (logging an error, and tearing it
/// down without telling its peers), and leaves alone one that is already
/// closing.
///
/// For a consumer closing an endpoint on an error path, where the network
/// may be what failed and the caller has to report the error promptly. A
/// process that exits right after can drop `closes`: that only stops
/// tracking a close still running, which the exit (or the runtime shutting
/// down) then cuts short.
///
/// # Panics
///
/// Panics if polled outside a Tokio runtime, or on one built without the
/// time driver enabled.
pub async fn close_endpoint(endpoint: Endpoint, closes: &PendingCloses) {
    let id = endpoint.id();
    let closed = closed_within(
        ENDPOINT_CLOSE_TIMEOUT,
        async move { endpoint.close().await },
        closes,
    );
    if !closed.await {
        warn!(
            "Endpoint {id} is slow to close; leaving it to finish in the background"
        );
    }
}

/// Run `close` on a task of its own, kept in `closes` as it starts, and wait
/// up to `limit` for it. Whether it finished in time; a close that did not
/// keeps running, and stays in `closes` until it is over.
async fn closed_within(
    limit: Duration,
    close: impl Future<Output = ()> + Send + 'static,
    closes: &PendingCloses,
) -> bool {
    let close = closes.kept(tokio::spawn(close));
    tokio::time::timeout(limit, close).await.is_ok()
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

/// What [`create_endpoint`] hands back: the bound, online endpoint and the
/// startup probe of its custom relays.
#[derive(Debug)]
pub struct CreatedEndpoint {
    pub endpoint: Endpoint,
    /// The startup probe of the custom relays, which may still be running when
    /// the endpoint is handed back (see [`create_endpoint`]); it settles
    /// within [`RELAY_CONNECT_TIMEOUT`] plus a bounded close. Hand it to
    /// [`crate::relay_failover::fail_over_home_relay`], which waits for it and
    /// puts each relay it took out back into the relay map once it is
    /// connectable again; a process that does not run the failover keeps them
    /// out for its lifetime. Settled at once with the default relays.
    ///
    /// Until it settles, the probe holds a handle to the endpoint, which keeps
    /// its UDP sockets bound. A caller that closes the endpoint and then binds
    /// a new one on the same port awaits [`RelayProbes::released`] in between.
    pub relays: RelayProbes,
}

/// Create an endpoint: log the relay setup, bind with every configured relay,
/// probe each custom relay beside it, and require the endpoint to come
/// online. Returns as soon as it is: the probe goes on in the background and
/// fixes the live relay map up as its results land (see [`RelayProbes`]), so
/// on healthy relays it costs the start nothing.
///
/// A relay whose probe fails is taken out of the relay map, which is what
/// lets the endpoint come online during that relay's outage: iroh picks its
/// home relay by probe latency, so a relay that still answers probes but
/// cannot be connected (the outage [`crate::relay_failover`] exists for) would
/// otherwise be preferred, never connect, and keep [`Endpoint::online`]
/// pending. The wait for the endpoint is [`RELAY_CONNECT_TIMEOUT`] from the
/// latest such change, so taking that relay out gives it a full window to
/// re-home; the start fails when every relay fails its probe. The relay
/// comes back through the failover's restore probe; see
/// [`CreatedEndpoint::relays`].
///
/// The endpoint starts without QUIC address discovery on any custom relay,
/// and the probe turns it on for the relays that serve it: one that does not
/// would delay every start by iroh's 3 s probe timeout (see [`RelayProbes`]).
///
/// On failure after binding the endpoint is closed before the error
/// propagates (iroh aborts a bound endpoint dropped without `close()`). The
/// close is waited for up to 5 s, so a slow teardown cannot keep the error
/// back.
///
/// The probe's task, and any close that outlives that wait (this endpoint's,
/// or a probe endpoint's), keep running and are kept in `closes`, whether the
/// endpoint was created or not; see [`PendingCloses`] for what a caller owes
/// them.
///
/// Cancelled (the future dropped before it returns), it lets go of the
/// endpoint at once: the probe task's handle is taken from it then and there,
/// and the endpoint is closed on a task of its own, kept in `closes`, so its
/// UDP port is free again as soon as that close is done rather than when the
/// probes end. The probes still run to the end.
pub async fn create_endpoint(
    relay_config: &RelayConfig,
    builder: EndpointBuilder,
    closes: &PendingCloses,
) -> Result<CreatedEndpoint> {
    relay_config.log_status();
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    let (relays, probing) = RelayProbes::start(&endpoint, relay_config, closes);
    let mut cancelled = CloseIfCancelled {
        endpoint: Some(endpoint.clone()),
        runtime: tokio::runtime::Handle::try_current().ok(),
        slot: None,
        closes: closes.clone(),
    };
    if let Some((task, slot)) = probing {
        closes.keep(task);
        cancelled.slot = Some(slot);
    }
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        RELAY_CONNECT_TIMEOUT.as_secs()
    );
    let outcome = wait_online_beside(&endpoint, &relays).await;
    // Not cancelled: whatever follows is up to this function's own paths.
    cancelled.disarm(outcome.is_err());
    if let Err(e) = outcome {
        close_endpoint(endpoint, closes).await;
        return Err(e);
    }
    Ok(CreatedEndpoint { endpoint, relays })
}

/// Armed while [`create_endpoint`] waits for the endpoint, beside the probe
/// or not: if the wait is dropped unfinished, take the probe task's handle to
/// the endpoint and close the endpoint, so a cancelled start neither keeps the
/// endpoint's port bound for as long as the probes run nor drops it without
/// `close()`. It holds a handle of its own for the whole wait, since the
/// probe task's may be gone already, and the runtime the endpoint was bound
/// on, since it may be dropped outside it.
struct CloseIfCancelled {
    endpoint: Option<Endpoint>,
    runtime: Option<tokio::runtime::Handle>,
    slot: Option<EndpointSlot>,
    closes: PendingCloses,
}

impl CloseIfCancelled {
    /// The wait finished. A start that failed lets go of the endpoint at once
    /// too, before closing it, since the probes may run on for a while.
    fn disarm(&mut self, failed: bool) {
        self.endpoint = None;
        if let Some(slot) = self.slot.take()
            && failed
        {
            drop(slot.take());
        }
    }
}

impl Drop for CloseIfCancelled {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            drop(slot.take());
        }
        let Some(endpoint) = self.endpoint.take() else {
            return;
        };
        // Closed rather than dropped: iroh aborts an endpoint whose last
        // handle goes without `close()`, with an error logged.
        match &self.runtime {
            Some(runtime) => self
                .closes
                .keep(runtime.spawn(async move { endpoint.close().await })),
            None => drop(endpoint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::RelayMode;

    /// A close that takes its time is waited for up to the limit and no
    /// longer — and goes on by itself, rather than being cut off.
    #[tokio::test(start_paused = true)]
    async fn a_slow_close_is_waited_for_only_so_long() {
        let closes = PendingCloses::new();
        assert!(closed_within(ENDPOINT_CLOSE_TIMEOUT, async {}, &closes).await);

        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let (done, mut finished) = tokio::sync::oneshot::channel::<()>();
        let started = tokio::time::Instant::now();
        let in_time = closed_within(
            ENDPOINT_CLOSE_TIMEOUT,
            async move {
                let _ = released.await;
                let _ = done.send(());
            },
            &closes,
        )
        .await;
        assert!(!in_time);
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
        let in_time = closed_within(
            ENDPOINT_CLOSE_TIMEOUT,
            async move {
                let _ = released.await;
            },
            &closes,
        )
        .await;
        assert!(!in_time, "left running, and kept");

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

    /// A close is kept as it starts: a caller cancelled while it waits for the
    /// close leaves it for whoever waits on the set, not running untracked.
    #[tokio::test(start_paused = true)]
    async fn a_close_whose_wait_is_cancelled_is_still_kept() {
        let closes = PendingCloses::new();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let cancelled = tokio::time::timeout(
            ENDPOINT_CLOSE_TIMEOUT / 5,
            closed_within(
                ENDPOINT_CLOSE_TIMEOUT,
                async move {
                    let _ = released.await;
                },
                &closes,
            ),
        )
        .await;
        assert!(cancelled.is_err(), "the wait was cut short");
        let waiting = closes.clone();
        let mut finished = tokio::spawn(async move { waiting.finished().await });
        assert!(
            tokio::time::timeout(Duration::from_secs(60), &mut finished).await.is_err(),
            "the close is still running, and still kept"
        );
        release.send(()).unwrap();
        finished.await.unwrap();
    }

    /// A set that is never waited on forgets the closes that are over as new
    /// ones are kept, so it does not grow with every endpoint created.
    #[tokio::test]
    async fn closes_that_are_over_are_forgotten_as_new_ones_are_kept() {
        let closes = PendingCloses::new();
        for _ in 0..3 {
            let close = tokio::spawn(async {});
            while !close.is_finished() {
                tokio::task::yield_now().await;
            }
            closes.keep(close);
        }
        assert_eq!(closes.0.lock().unwrap().len(), 1, "only the latest is kept");

        let (release, released) = tokio::sync::oneshot::channel::<()>();
        closes.keep(tokio::spawn(async move {
            let _ = released.await;
        }));
        let done = tokio::spawn(async {});
        while !done.is_finished() {
            tokio::task::yield_now().await;
        }
        closes.keep(done);
        assert_eq!(closes.0.lock().unwrap().len(), 2, "the running close stays");
        release.send(()).unwrap();
        closes.finished().await;
        assert!(closes.0.lock().unwrap().is_empty());
    }

    /// A close still running is still there for whoever waits next: a second
    /// waiter beside the first, or a wait taken up again after one was given
    /// up on. Neither finds an empty set and reports the closes finished.
    #[tokio::test(start_paused = true)]
    async fn a_close_is_waited_for_by_every_waiter() {
        let slow_close = |closes: &PendingCloses| {
            let (release, released) = tokio::sync::oneshot::channel::<()>();
            closes.keep(tokio::spawn(async move {
                let _ = released.await;
            }));
            release
        };
        async fn still_waiting(finished: &mut JoinHandle<()>) -> bool {
            tokio::time::timeout(Duration::from_secs(60), finished).await.is_err()
        }

        // Two waiters at once.
        let closes = PendingCloses::new();
        let release = slow_close(&closes);
        let (first, second) = (closes.clone(), closes.clone());
        let mut first = tokio::spawn(async move { first.finished().await });
        let mut second = tokio::spawn(async move { second.finished().await });
        assert!(still_waiting(&mut first).await, "the close is still running");
        assert!(still_waiting(&mut second).await, "for the second waiter too");
        release.send(()).unwrap();
        first.await.unwrap();
        second.await.unwrap();

        // A wait given up on, and taken up again.
        let closes = PendingCloses::new();
        let release = slow_close(&closes);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), closes.finished()).await.is_err(),
            "the close is still running"
        );
        let again = closes.clone();
        let mut again = tokio::spawn(async move { again.finished().await });
        assert!(still_waiting(&mut again).await, "and still is for the next wait");
        release.send(()).unwrap();
        again.await.unwrap();
    }
}
