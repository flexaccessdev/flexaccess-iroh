//! Relay configuration, the shared relay auth token, and the per-relay startup
//! probe.
//!
//! The design is documented in this repository's
//! `docs/relays-and-address-lookup.md`; this module is its implementation.

use crate::endpoint::{CloseIfCancelled, PendingCloses};
use anyhow::{Context, Result};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use iroh::endpoint::{RelayStatus, presets};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, Watcher};
use log::{info, warn};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long a relay probe, or a freshly bound endpoint once its QUIC address
/// discovery (QAD) is done (see [`QAD_PROBES_TIMEOUT`]), may take to come
/// online before that is treated as a relay connectivity failure.
pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long iroh 1.5 waits for its QUIC address discovery (QAD) probes
/// (`PROBES_TIMEOUT` in its net_report, private to iroh): the longest a net
/// report holds an endpoint's home relay back on QAD.
///
/// The relay probes never run QAD (they have no IP transports), but an
/// endpoint that does picks no home relay, and so opens no relay connection,
/// until its net report's QAD probes are done or timed out. Its startup wait
/// adds this to [`RELAY_CONNECT_TIMEOUT`] once per net report that can come
/// before it homes on a relay that works: one from bind, and two after the
/// probe takes a relay out of the map, since iroh runs one report at a time
/// and queues the map change behind the report already running (later
/// changes join the queued one). Without it, a relay that connects late in
/// its probe's window would pass the probe and still fail the start.
pub const QAD_PROBES_TIMEOUT: Duration = Duration::from_secs(3);

/// How long each net report of `endpoint`, bound from `relay_config`, may
/// wait on QAD: [`QAD_PROBES_TIMEOUT`] when it probes the custom relays for
/// QAD, zero otherwise. With the default relays there is no probe to match.
pub(crate) fn qad_wait(relay_config: &RelayConfig, endpoint: &Endpoint) -> Duration {
    // iroh runs QAD only on an endpoint with IP transports, so a relay-only
    // one (no bound sockets) never waits for it.
    let qad = relay_config.quic_addr_discovery() == Some(true) && !endpoint.bound_sockets().is_empty();
    if qad { QAD_PROBES_TIMEOUT } else { Duration::ZERO }
}

/// How long `endpoint`, freshly bound from `relay_config` (with
/// [`crate::endpoint::endpoint_builder`]), may take to come online while its
/// relay map stays as bound: [`RELAY_CONNECT_TIMEOUT`] plus iroh's QAD probe
/// timeout when the endpoint runs QUIC address discovery on custom relays
/// (see [`QAD_PROBES_TIMEOUT`]). For a caller that binds an endpoint and waits
/// on [`Endpoint::online`] itself, without the startup probe of
/// [`crate::endpoint::create_endpoint`] (which also allows for the probe
/// taking relays out of the map).
pub fn online_timeout(relay_config: &RelayConfig, endpoint: &Endpoint) -> Duration {
    RELAY_CONNECT_TIMEOUT + qad_wait(relay_config, endpoint)
}

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
    /// Custom relay set (parsed, deduped, in configured order), never empty.
    /// A server keeps working through a relay outage only by moving onto
    /// another configured relay (see [`crate::relay_failover`]), so a single
    /// relay is reduced-redundancy mode (see [`Self::is_single_relay`]): it
    /// works, but there is no other relay to move onto. While that relay is
    /// down, new off-LAN dials and connections that run only through it fail;
    /// the endpoint keeps running and connections on a direct path continue.
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
    ///
    /// `quic_addr_discovery` says whether the relays serve QUIC address
    /// discovery, for all of them at once (see
    /// [`Self::with_quic_addr_discovery`]). On by default, as iroh has it.
    Custom {
        urls: Vec<RelayUrl>,
        auth_token: Option<String>,
        quic_addr_discovery: bool,
    },
}

/// Manual `Debug` so the relay auth token is never written to logs or error
/// messages: `Custom.auth_token` is shown only as a redacted marker (present
/// vs. absent), while `urls` keep their normal `Debug` formatting.
impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("Default"),
            Self::Custom {
                urls,
                auth_token,
                quic_addr_discovery,
            } => f
                .debug_struct("Custom")
                .field("urls", urls)
                .field("auth_token", &auth_token.as_ref().map(|_| RedactedToken))
                .field("quic_addr_discovery", quic_addr_discovery)
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
    /// use site. Exact duplicates are collapsed (listing the same relay twice
    /// counts once), so a list that names one relay, however often, is
    /// single-relay, reduced-redundancy mode, which [`Self::log_status`]
    /// warns about.
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
        Ok(Self::Custom {
            urls: parsed,
            auth_token,
            quic_addr_discovery: true,
        })
    }

    /// Say whether the custom relays serve QUIC address discovery (QAD), all
    /// of them or none: the application knows how its relays are deployed,
    /// and a relay cannot be asked. The iroh relay advertises QAD nowhere,
    /// and a relay that does not serve it is told apart from a slow one only
    /// by a timeout.
    ///
    /// On (the default), every relay is in the relay map exactly as iroh has
    /// it, QAD on UDP 7842 at the URL's host included, and iroh does the rest:
    /// a relay whose QAD is down for a while can hold a full net report back
    /// by up to iroh's own probe timeout (3 s on iroh 1.5), as it does in
    /// iroh.
    ///
    /// Off, no relay is probed for QAD at all. For relays that cannot serve
    /// it, such as relays behind a Cloudflare Tunnel or any other HTTP-only
    /// front: with QAD on, when too few probe replies come back, a full
    /// net report waits up to that timeout, the first one too, which delays
    /// the endpoint's start. No
    /// relay then reports the endpoint's public address to it.
    ///
    /// An error with the default relays, which are iroh's own and keep its
    /// settings, whichever value is given.
    pub fn with_quic_addr_discovery(self, enabled: bool) -> Result<Self> {
        match self {
            Self::Default => anyhow::bail!(
                "the QUIC address discovery setting requires custom relay_urls; the default iroh \
                 relays keep iroh's own"
            ),
            Self::Custom {
                urls, auth_token, ..
            } => Ok(Self::Custom {
                urls,
                auth_token,
                quic_addr_discovery: enabled,
            }),
        }
    }

    /// Whether the endpoint probes the custom relays for QUIC address
    /// discovery (see [`Self::with_quic_addr_discovery`]); `None` for
    /// [`RelayConfig::Default`], whose relays keep iroh's own settings.
    pub fn quic_addr_discovery(&self) -> Option<bool> {
        match self {
            Self::Default => None,
            Self::Custom {
                quic_addr_discovery,
                ..
            } => Some(*quic_addr_discovery),
        }
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

    /// Whether this is a single custom relay: reduced-redundancy mode, with no
    /// other relay to fail over to when it stops working.
    pub fn is_single_relay(&self) -> bool {
        self.custom_urls().len() == 1
    }

    /// The corresponding iroh [`RelayMode`]: every configured relay.
    ///
    /// For custom relays, an `auth_token` (when set) is applied to every relay in
    /// the map, which iroh sends as an `Authorization: Bearer <token>` header on
    /// the relay WebSocket upgrade, and each relay is probed for QUIC address
    /// discovery as [`Self::with_quic_addr_discovery`] says.
    pub fn relay_mode(&self) -> RelayMode {
        match self {
            Self::Default => RelayMode::Default,
            Self::Custom {
                urls,
                auth_token,
                quic_addr_discovery,
                ..
            } => RelayMode::Custom(
                urls.iter()
                    .map(|url| relay_entry(url, auth_token.as_deref(), *quic_addr_discovery))
                    .collect(),
            ),
        }
    }

    /// Log which relays are in use (silent for the default relays), with a
    /// warning for a single custom relay. Only ever reports *whether* an auth
    /// token is set — never the token itself.
    pub fn log_status(&self) {
        let auth = if self.relay_auth_token().is_some() {
            " (authenticated)"
        } else {
            ""
        };
        match self.custom_urls().len() {
            0 => {}
            1 => warn!(
                "Using a single custom relay server{auth}: reduced redundancy, no failover. While \
                 it is down there is no other relay to move onto, so new off-LAN dials and \
                 connections that run only through it fail (direct connections continue); \
                 configure another relay_url to ride out a relay outage"
            ),
            n => info!("Using {n} custom relay servers with failover{auth}"),
        }
        if self.quic_addr_discovery() == Some(false) {
            info!("QUIC address discovery is off for the custom relays (configured)");
        }
    }
}

/// The relay-map entry for one custom relay: `auth_token` (when set) on it,
/// and probed for QUIC address discovery on iroh's default port only when
/// `quic_addr_discovery` is set.
pub(crate) fn relay_entry(
    url: &RelayUrl,
    auth_token: Option<&str>,
    quic_addr_discovery: bool,
) -> iroh::RelayConfig {
    let mut relay = iroh::RelayConfig::from(url.clone());
    if !quic_addr_discovery {
        relay.quic = None;
    }
    match auth_token {
        Some(token) => relay.with_auth_token(token),
        None => relay,
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
/// needs the relay link to come up, never a data path. Without IP transports
/// iroh never probes QUIC address discovery, so the entry leaves it off.
fn probe_endpoint_builder(relay_url: &RelayUrl, auth_token: Option<&str>) -> iroh::endpoint::Builder {
    let map = RelayMap::from_iter([relay_entry(relay_url, auth_token, false)]);
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
/// describes the failure.
///
/// The probe endpoint is always closed before returning, with a bounded wait
/// for the close (see [`crate::endpoint::close_endpoint`]); a close that
/// outlives the wait is kept in `closes`. Dropped before it returns, the probe
/// closes it on a task of its own, kept in `closes` as well, rather than leave
/// iroh to abort it.
pub(crate) async fn probe_relay(
    relay_url: &RelayUrl,
    auth_token: Option<&str>,
    closes: &PendingCloses,
) -> Result<()> {
    let endpoint = probe_endpoint_builder(relay_url, auth_token)
        .bind()
        .await
        .with_context(|| format!("Failed to bind probe endpoint for relay {relay_url}"))?;
    let mut cancelled = CloseIfCancelled::new(&endpoint, closes);
    let outcome = tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await;
    // Read why before closing: the probe map holds this one relay, so its
    // status (if selected at all) carries the last connection failure.
    let failure = outcome.is_err().then(|| {
        endpoint
            .home_relay_status()
            .get()
            .first()
            .map_or_else(|| "no home relay selected".to_string(), relay_failure)
    });
    // Closed below, on this function's own path.
    cancelled.disarm(false);
    crate::endpoint::close_endpoint(endpoint, closes).await;
    match failure {
        None => Ok(()),
        Some(failure) => anyhow::bail!(
            "did not come online within {}s: {failure}",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Why a relay in `status` is not connected, for logs and errors (without the
/// URL). An authentication denial is called out on its own: unlike a
/// connection failure it does not clear up by retrying with the same token.
pub(crate) fn relay_failure(status: &RelayStatus) -> String {
    if let Some(reason) = status.auth_denied_reason() {
        format!("authentication denied by the relay ({reason}); check the relay auth token")
    } else if let Some(e) = status.last_error() {
        format!("disconnected ({e:#})")
    } else {
        "not connected".to_string()
    }
}

/// How far the startup probe has got.
#[derive(Debug, Clone, Default)]
struct ProbeProgress {
    /// Custom relays to probe.
    total: usize,
    /// Of those, how many have been probed.
    probed: usize,
    /// The relays that did not come online, with why.
    failures: Vec<(RelayUrl, String)>,
    /// The relays taken out of the endpoint's relay map.
    left_out: Vec<RelayUrl>,
}

impl ProbeProgress {
    fn settled(&self) -> bool {
        self.probed == self.total
    }

    fn all_failed(&self) -> bool {
        self.total > 0 && self.failures.len() == self.total
    }

    /// Why the start failed when [`Self::all_failed`].
    fn all_failed_error(&self) -> anyhow::Error {
        match self.total {
            1 => anyhow::anyhow!(
                "the single custom relay failed to come online (no other relay is configured):\n  {}",
                self.describe_failures()
            ),
            n => anyhow::anyhow!(
                "all {n} custom relays failed to come online:\n  {}",
                self.describe_failures()
            ),
        }
    }

    fn describe_failures(&self) -> String {
        self.failures
            .iter()
            .map(|(url, e)| format!("{url}: {e}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

/// The startup probe of an endpoint's custom relays, which runs beside the
/// endpoint rather than ahead of it (see
/// [`crate::endpoint::create_endpoint`]). Clones share one probe.
///
/// Every configured relay is probed individually, in parallel, and each
/// result is applied to the live endpoint as it lands:
///
/// - A relay that does not come online is **taken out of the relay map**,
///   unless it is the last one left. iroh picks its home relay by probe
///   latency, so a relay that answers probes but cannot be connected (the
///   outage shape of [`crate::relay_failover`]) would otherwise be preferred,
///   never connect, and keep the endpoint from ever coming online; with it out
///   of the map the endpoint re-homes on a relay that works. Probing each
///   relay on its own is also what names a dead *backup* relay: the
///   endpoint's own `online()` proves only that its home relay connected.
///
/// A relay that is down at startup does not stop the process: the other
/// configured relays carry it, and refusing to start would turn a survivable
/// relay outage into an outage of every client that restarts during it. Only
/// when every relay fails does the start fail, if the endpoint is not online
/// by then; with a single relay (reduced-redundancy mode) that is its own
/// failure.
#[derive(Debug, Clone)]
pub struct RelayProbes(watch::Receiver<ProbeProgress>);

impl RelayProbes {
    /// Nothing to probe: the default relays.
    fn none() -> Self {
        let (_, progress) = watch::channel(ProbeProgress::default());
        Self(progress)
    }

    /// Start probing `relay_config`'s custom relays for `endpoint`, on a task
    /// of its own. Returns the probe and that task, which the caller keeps in
    /// its [`PendingCloses`] (the probe endpoints must be closed before the
    /// runtime goes away), with the slot through which the task reaches the
    /// endpoint. `None` for the default relays.
    pub(crate) fn start(
        endpoint: &Endpoint,
        relay_config: &RelayConfig,
        closes: &PendingCloses,
    ) -> (Self, Option<(JoinHandle<()>, EndpointSlot)>) {
        if !relay_config.is_custom() {
            return (Self::none(), None);
        }
        let (tx, rx) = watch::channel(ProbeProgress {
            total: relay_config.custom_urls().len(),
            ..ProbeProgress::default()
        });
        let slot = EndpointSlot(Arc::new(Mutex::new(Some(endpoint.clone()))));
        let task = tokio::spawn(apply_relay_probes(
            endpoint.closed(),
            slot.clone(),
            relay_config.clone(),
            closes.clone(),
            tx,
        ));
        (Self(rx), Some((task, slot)))
    }

    /// Whether every custom relay has been probed and its result applied.
    /// Always true for the default relays.
    pub fn is_settled(&self) -> bool {
        self.0.borrow().settled()
    }

    /// Wait until every custom relay has been probed and its result applied
    /// to the endpoint, and return the relays it took out of the endpoint's
    /// relay map. Bounded by [`RELAY_CONNECT_TIMEOUT`] plus the probe
    /// endpoints' bounded close. A probe stopped by the endpoint's close
    /// returns those it had taken out by then.
    pub async fn settled(&self) -> Vec<RelayUrl> {
        let mut progress = self.0.clone();
        let settled = progress
            .wait_for(ProbeProgress::settled)
            .await
            .map(|progress| progress.left_out.clone());
        // The probe task sends its last result before it ends, so this is as
        // far as it got: only a task stopped by the endpoint's close, or
        // aborted, stops short.
        settled.unwrap_or_else(|_| progress.borrow().left_out.clone())
    }

    /// Wait for the next probe result. `None` once nothing more will come.
    async fn changed(&mut self) -> Option<ProbeProgress> {
        self.0.changed().await.ok()?;
        Some(self.0.borrow_and_update().clone())
    }
}

/// Where the probe task keeps its handle to the endpoint it fixes up. The task
/// borrows a clone only while it applies a result, so emptying the slot lets
/// go of the endpoint at once, from wherever that happens: the task itself
/// when the endpoint's close begins, or [`crate::endpoint::create_endpoint`]
/// when it is cancelled.
#[derive(Debug, Clone)]
pub(crate) struct EndpointSlot(Arc<Mutex<Option<Endpoint>>>);

impl EndpointSlot {
    /// A clone of the endpoint, unless it has been let go of or is closed.
    fn get(&self) -> Option<Endpoint> {
        let slot = self.0.lock().expect("endpoint slot lock");
        slot.as_ref().filter(|endpoint| !endpoint.is_closed()).cloned()
    }

    /// Let go of the endpoint, handing over the slot's handle to it.
    pub(crate) fn take(&self) -> Option<Endpoint> {
        self.0.lock().expect("endpoint slot lock").take()
    }
}

/// Whether `endpoint`'s home relay is connected through `url`.
fn home_relay_connected(endpoint: &Endpoint, url: &RelayUrl) -> bool {
    endpoint
        .home_relay_status()
        .get()
        .iter()
        .any(|status| status.is_connected() && status.url() == url)
}

/// The probe task behind [`RelayProbes`]: probe every relay in parallel,
/// apply each result to `endpoint` as it lands, and publish the progress.
///
/// The task lets go of the endpoint in `slot` as soon as its close begins
/// (`closed`, from [`Endpoint::closed`], which holds no handle to it): its
/// sockets are released only with its last handle, so a closed endpoint does
/// not keep its port bound while a relay that does not answer is still being
/// probed. Its close stops the probes still running as well: they are
/// dropped, which closes their endpoints on tasks kept in `closes` (see
/// [`probe_relay`]), so a process that shuts down right after its start
/// waits for those closes and not for a relay that does not answer. The probe
/// then ends unsettled.
async fn apply_relay_probes(
    closed: impl Future<Output = ()>,
    slot: EndpointSlot,
    relay_config: RelayConfig,
    closes: PendingCloses,
    progress: watch::Sender<ProbeProgress>,
) {
    let urls = relay_config.custom_urls();
    let auth_token = relay_config.relay_auth_token();
    tokio::pin!(closed);
    match urls.len() {
        1 => info!("Probing the custom relay for reachability..."),
        n => info!("Probing {n} custom relays for reachability..."),
    }
    let mut probes: FuturesUnordered<_> = urls
        .iter()
        .map(|url| {
            let closes = &closes;
            async move {
                let probe = probe_relay(url, auth_token, closes).await;
                (url, probe)
            }
        })
        .collect();
    let mut in_map = urls.len();
    loop {
        let next = tokio::select! {
            next = probes.next() => next,
            () = &mut closed => None,
        };
        let Some((url, result)) = next else {
            break;
        };
        let failure = result.err().map(|e| format!("{e:#}"));
        let mut left_out = false;
        let endpoint = slot.get();
        if let (Some(failure), Some(endpoint)) = (&failure, &endpoint) {
            // The probe is a connection of its own: it can fail on a relay
            // the endpoint is connected through all the same, and taking that
            // relay out would move the endpoint off a relay that works.
            if home_relay_connected(endpoint, url) {
                warn!(
                    "{url} did not come online for its probe ({failure}), but the endpoint is \
                     connected through it; keeping it in the relay map"
                );
            } else if in_map > 1 {
                endpoint.remove_relay(url).await;
                in_map -= 1;
                left_out = true;
                warn!(
                    "Took {url} out of the relay map: it did not come online ({failure}). The \
                     endpoint homes on a relay that works; the failover puts it back once it is \
                     connectable again"
                );
            } else {
                warn!("{url} did not come online ({failure}); it is the last relay in the map");
            }
        }
        progress.send_modify(|progress| {
            progress.probed += 1;
            if let Some(failure) = failure {
                progress.failures.push((url.clone(), failure));
            }
            if left_out {
                progress.left_out.push(url.clone());
            }
        });
    }
    drop(slot.take());
    if !probes.is_empty() {
        info!("Stopped probing the custom relays: the endpoint is closing");
        // Their endpoints close on tasks of their own, kept in `closes`.
        drop(probes);
        return;
    }
    let progress = progress.borrow();
    if !progress.failures.is_empty() && !progress.all_failed() {
        warn!(
            "{} of {} custom relays failed to come online; continuing with the rest, but a \
             further relay failure now has less to fail over to:\n  {}",
            progress.failures.len(),
            progress.total,
            progress.describe_failures()
        );
    }
}

/// Wait for `endpoint` to come online while `probes` runs beside it.
///
/// Fails when every custom relay failed its probe, or when the endpoint is
/// still offline [`RELAY_CONNECT_TIMEOUT`] plus `qad_wait` (see [`qad_wait`])
/// after the wait began, or plus twice `qad_wait` after the probe last took
/// a relay out of its map (see [`QAD_PROBES_TIMEOUT`] for why). Taking a
/// relay out restarts the wait, because that is what lets an endpoint stuck
/// on a relay that cannot be connected re-home on one that can. Nor does the
/// wait end while a probe is still running, which may yet take out the relay
/// that keeps it offline.
pub(crate) async fn wait_online_beside(
    endpoint: &Endpoint,
    probes: &RelayProbes,
    qad_wait: Duration,
) -> Result<()> {
    // Online means connected to a relay. A probe is a connection of its own
    // and can fail on a relay the endpoint is connected through, so every
    // failure is checked against the live connection first.
    let connected = || {
        endpoint
            .home_relay_status()
            .get()
            .iter()
            .any(|status| status.is_connected())
    };
    let mut probes = probes.clone();
    // What the probe found before this wait began is a change like any
    // other: it may have settled already, every relay failed included.
    probes.0.mark_changed();
    let mut window = RELAY_CONNECT_TIMEOUT + qad_wait;
    let timed_out = |window: Duration| {
        anyhow::anyhow!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            window.as_secs()
        )
    };
    let mut deadline = Some(Instant::now() + window);
    let mut left_out = 0;
    let mut probing = true;
    let online = endpoint.online();
    tokio::pin!(online);
    loop {
        tokio::select! {
            biased;
            () = &mut online => return Ok(()),
            () = sleep_until_opt(deadline) => {
                if connected() {
                    return Ok(());
                }
                if !probing {
                    return Err(timed_out(window));
                }
                deadline = None;
            }
            progress = probes.changed(), if probing => {
                let Some(progress) = progress else {
                    probing = false;
                    deadline.get_or_insert_with(Instant::now);
                    continue;
                };
                if connected() {
                    return Ok(());
                }
                if progress.all_failed() {
                    return Err(progress.all_failed_error());
                }
                probing = !progress.settled();
                if progress.left_out.len() > left_out {
                    left_out = progress.left_out.len();
                    window = RELAY_CONNECT_TIMEOUT + 2 * qad_wait;
                    deadline = Some(Instant::now() + window);
                } else if deadline.is_none() && !probing {
                    return Err(timed_out(window));
                }
            }
        }
    }
}

/// Sleep until `at`; pending forever when there is no deadline.
async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "https://relay.example.com./";
    const RELAY2: &str = "https://relay2.example.com./";

    fn two() -> [String; 2] {
        [RELAY.to_string(), RELAY2.to_string()]
    }

    /// The QUIC address discovery port iroh assumes for a relay given by URL
    /// alone (UDP 7842).
    fn iroh_default_qad_port(url: &RelayUrl) -> u16 {
        iroh::RelayConfig::from(url.clone())
            .quic
            .map(|quic| quic.port)
            .expect("iroh probes QAD on a relay given by URL")
    }

    #[test]
    fn the_relay_map_holds_every_custom_relay_with_the_token_and_iroh_s_quic_addr_discovery() {
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("secret".to_string())).unwrap();
        assert_eq!(cfg.quic_addr_discovery(), Some(true), "on by default, as in iroh");
        let RelayMode::Custom(map) = cfg.relay_mode() else {
            panic!("custom relays give a custom relay map");
        };
        assert_eq!(map.len(), 2);
        for url in [RELAY, RELAY2] {
            let url: RelayUrl = url.parse().unwrap();
            let relay = map.get(&url).unwrap();
            assert_eq!(relay.auth_token.as_deref(), Some("secret"));
            assert_eq!(relay.quic.as_ref().map(|quic| quic.port), Some(iroh_default_qad_port(&url)));
        }
        assert!(matches!(RelayConfig::Default.relay_mode(), RelayMode::Default));
    }

    #[test]
    fn quic_addr_discovery_off_leaves_it_off_on_every_custom_relay() {
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("secret".to_string()))
            .unwrap()
            .with_quic_addr_discovery(false)
            .unwrap();
        assert_eq!(cfg.quic_addr_discovery(), Some(false));
        let RelayMode::Custom(map) = cfg.relay_mode() else {
            panic!("custom relays give a custom relay map");
        };
        assert_eq!(map.len(), 2);
        for url in [RELAY, RELAY2] {
            let relay = map.get(&url.parse::<RelayUrl>().unwrap()).unwrap();
            assert!(relay.quic.is_none());
            assert_eq!(relay.auth_token.as_deref(), Some("secret"));
        }
        // And back on.
        let cfg = cfg.with_quic_addr_discovery(true).unwrap();
        let RelayMode::Custom(map) = cfg.relay_mode() else {
            panic!("custom relays give a custom relay map");
        };
        assert!(map.get(&RELAY.parse::<RelayUrl>().unwrap()).unwrap().quic.is_some());
    }

    #[test]
    fn the_quic_addr_discovery_setting_requires_custom_relays() {
        for enabled in [true, false] {
            let err = RelayConfig::Default
                .with_quic_addr_discovery(enabled)
                .expect_err("the default relays keep iroh's settings");
            assert!(
                err.to_string().contains("requires custom relay_urls"),
                "unexpected error: {err}"
            );
        }
        assert_eq!(RelayConfig::Default.quic_addr_discovery(), None);
    }

    #[test]
    fn a_relay_entry_carries_quic_addr_discovery_only_when_asked() {
        let url: RelayUrl = RELAY.parse().unwrap();
        let with = relay_entry(&url, Some("secret"), true);
        assert_eq!(with.quic.map(|quic| quic.port), Some(iroh_default_qad_port(&url)));
        assert_eq!(with.auth_token.as_deref(), Some("secret"));
        let without = relay_entry(&url, None, false);
        assert!(without.quic.is_none());
        assert!(without.auth_token.is_none());
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
    fn a_single_custom_url_is_reduced_redundancy_mode() {
        let cfg = RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("secret".to_string()))
            .expect("one custom relay is accepted");
        assert!(cfg.is_custom());
        assert!(cfg.is_single_relay());
        assert_eq!(cfg.relay_auth_token(), Some("secret"));
        let RelayMode::Custom(map) = cfg.relay_mode() else {
            panic!("one custom relay gives a custom relay map");
        };
        assert_eq!(map.len(), 1);
        // Repeats of one URL are still one relay.
        let cfg = RelayConfig::from_urls(&[RELAY.to_string(), RELAY.to_string()]).unwrap();
        assert!(cfg.is_single_relay());
        assert!(!RelayConfig::from_urls(&two()).unwrap().is_single_relay());
        assert!(!RelayConfig::Default.is_single_relay());
    }

    #[test]
    fn a_failed_single_relay_is_named_as_the_only_one() {
        let mut progress = ProbeProgress {
            total: 1,
            probed: 1,
            ..ProbeProgress::default()
        };
        progress.failures.push((RELAY.parse().unwrap(), "down".to_string()));
        assert!(progress.all_failed());
        let err = progress.all_failed_error().to_string();
        assert!(
            err.contains("the single custom relay failed to come online") && err.contains("down"),
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

        assert!(dbg.contains("quic_addr_discovery: true"), "unexpected Debug output: {dbg}");

        let no_token = RelayConfig::from_urls(&two()).unwrap();
        assert!(format!("{no_token:?}").contains("auth_token: None"));
        assert_eq!(format!("{:?}", RelayConfig::Default), "Default");
    }

    #[test]
    fn from_urls_carries_no_token() {
        let cfg = RelayConfig::from_urls(&two()).unwrap();
        assert_eq!(cfg.relay_auth_token(), None);
    }

    /// A probe that has already settled, every relay failed, when the wait
    /// begins: the start fails at once with why, not after the timeout.
    #[tokio::test]
    async fn a_probe_that_failed_before_the_wait_fails_the_start_at_once() {
        let endpoint = Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind()
            .await
            .unwrap();
        let (tx, rx) = watch::channel(ProbeProgress {
            total: 2,
            ..ProbeProgress::default()
        });
        tx.send_modify(|progress| {
            progress.probed = 2;
            for url in [RELAY, RELAY2] {
                progress.failures.push((url.parse().unwrap(), "down".to_string()));
            }
        });
        drop(tx);
        let err = tokio::time::timeout(
            Duration::from_secs(1),
            wait_online_beside(&endpoint, &RelayProbes(rx), Duration::ZERO),
        )
        .await
        .expect("no wait for the timeout")
        .expect_err("every relay failed");
        assert!(
            err.to_string().contains("all 2 custom relays failed to come online"),
            "unexpected error: {err}"
        );
        endpoint.close().await;
    }

    /// The startup wait runs to [`RELAY_CONNECT_TIMEOUT`] plus one QAD wait
    /// from its start, and plus two from the probe last taking a relay out.
    #[tokio::test(start_paused = true)]
    async fn the_startup_wait_allows_one_qad_wait_from_the_start_and_two_after_a_removal() {
        // No relays: never online, and no relay traffic.
        let endpoint = Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind()
            .await
            .unwrap();
        let qad = QAD_PROBES_TIMEOUT;
        // Timers fire to the millisecond.
        let assert_took = |started: Instant, expected: Duration| {
            let took = started.elapsed();
            assert!(
                took >= expected && took < expected + Duration::from_millis(10),
                "took {took:?}, expected {expected:?}"
            );
        };

        // Settled with nothing taken out: the window from the start.
        let (_tx, rx) = watch::channel(ProbeProgress {
            total: 1,
            probed: 1,
            ..ProbeProgress::default()
        });
        let started = Instant::now();
        let err = wait_online_beside(&endpoint, &RelayProbes(rx), qad)
            .await
            .expect_err("never online");
        assert_took(started, RELAY_CONNECT_TIMEOUT + qad);
        assert!(err.to_string().contains("after 13s"), "unexpected error: {err}");

        // A relay taken out at 5 s, the other relay probed fine at 6 s: the
        // window restarts at 5 s, two QAD waits wide.
        let (tx, rx) = watch::channel(ProbeProgress {
            total: 2,
            ..ProbeProgress::default()
        });
        let probe = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tx.send_modify(|progress| {
                let url: RelayUrl = RELAY.parse().unwrap();
                progress.probed = 1;
                progress.failures.push((url.clone(), "down".to_string()));
                progress.left_out.push(url);
            });
            tokio::time::sleep(Duration::from_secs(1)).await;
            tx.send_modify(|progress| progress.probed = 2);
            std::future::pending::<()>().await
        };
        let probes = RelayProbes(rx);
        let started = Instant::now();
        let err = tokio::select! {
            outcome = wait_online_beside(&endpoint, &probes, qad) => {
                outcome.expect_err("never online")
            }
            () = probe => unreachable!(),
        };
        assert_took(started, Duration::from_secs(5) + RELAY_CONNECT_TIMEOUT + 2 * qad);
        assert!(err.to_string().contains("after 16s"), "unexpected error: {err}");
        endpoint.close().await;
    }

    #[tokio::test]
    async fn default_relays_are_not_probed() {
        let endpoint = Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind()
            .await
            .unwrap();
        let (probes, task) = RelayProbes::start(&endpoint, &RelayConfig::Default, &PendingCloses::new());
        assert!(task.is_none(), "no probe task for the default relays");
        assert!(probes.is_settled());
        // Settled from the start, without touching the network.
        let left_out = tokio::time::timeout(Duration::from_millis(100), probes.settled())
            .await
            .expect("nothing to wait for");
        assert!(left_out.is_empty());
        endpoint.close().await;
    }

    /// A relay that accepts TCP and never answers, so a probe of it runs to
    /// [`RELAY_CONNECT_TIMEOUT`]. Its URL, and the task holding it up.
    async fn stalled_relay() -> (String, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                held.push(conn);
            }
        });
        (url, task)
    }

    /// Closing the endpoint stops the startup probe of a relay that does not
    /// answer, rather than leave its probe endpoints open until the timeout,
    /// and their closes are kept for the caller to wait on.
    #[tokio::test]
    async fn closing_the_endpoint_stops_its_probes() {
        let (url, stalled) = stalled_relay().await;
        let config = RelayConfig::from_urls(&[url]).unwrap();
        let endpoint = Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind()
            .await
            .unwrap();
        let closes = PendingCloses::new();
        let (probes, probing) = RelayProbes::start(&endpoint, &config, &closes);
        let (task, _slot) = probing.expect("a custom relay is probed");
        tokio::time::sleep(Duration::from_millis(300)).await;
        endpoint.close().await;
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .expect("stopped well before the relay timeout")
            .unwrap();
        assert!(!probes.is_settled(), "the relay was never probed to the end");
        assert!(closes.kept_count() >= 1, "the probe endpoint's close is kept");
        tokio::time::timeout(crate::endpoint::ENDPOINT_CLOSE_TIMEOUT, closes.finished())
            .await
            .expect("and finish");
        stalled.abort();
    }

    /// A relay probe dropped before it returns closes its endpoint, rather
    /// than leave iroh to abort it, and keeps that close.
    #[tokio::test]
    async fn a_dropped_probe_closes_its_endpoint() {
        let (url, stalled) = stalled_relay().await;
        let url: RelayUrl = url.parse().unwrap();
        let closes = PendingCloses::new();
        let probe = probe_relay(&url, None, &closes);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), probe).await.is_err(),
            "still probing when dropped"
        );
        assert_eq!(closes.kept_count(), 1, "the probe endpoint is closing");
        tokio::time::timeout(crate::endpoint::ENDPOINT_CLOSE_TIMEOUT, closes.finished())
            .await
            .expect("and its close finishes");
        stalled.abort();
    }
}
