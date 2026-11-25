//! Relay configuration, the shared relay auth token, and the per-relay startup
//! probe.
//!
//! The design is documented in this repository's
//! `docs/relays-and-address-lookup.md`; this module is its implementation.

use crate::endpoint::PendingCloses;
use anyhow::{Context, Result};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use iroh::endpoint::{NetReportConfig, PortmapperConfig, RelayStatus, presets};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, Watcher};
use log::{info, warn};
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

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

    /// The corresponding iroh [`RelayMode`]: every configured relay, before
    /// the startup probe has looked at any of them.
    ///
    /// For custom relays, an `auth_token` (when set) is applied to every relay in
    /// the map, which iroh sends as an `Authorization: Bearer <token>` header on
    /// the relay WebSocket upgrade. No relay is probed for QUIC address
    /// discovery yet: the startup probe turns it on, on the live endpoint, for
    /// the relays that serve it (see [`RelayProbes`]).
    pub fn relay_mode(&self) -> RelayMode {
        match self {
            Self::Default => RelayMode::Default,
            Self::Custom { urls, auth_token } => RelayMode::Custom(
                urls.iter()
                    .map(|url| relay_entry(url, auth_token.as_deref(), false))
                    .collect(),
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

/// What the startup probe found out about the custom relays (see
/// [`RelayProbes`]); empty for the default relays, which are not probed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbedRelays {
    /// The configured relays that did not come online, taken out of the
    /// endpoint's relay map.
    pub left_out: Vec<RelayUrl>,
    /// The configured relays that serve QUIC address discovery (QAD), the only
    /// ones the endpoint probes for it. See [`probe_relay`] for why the others
    /// must not be.
    pub quic_addr_discovery: Vec<RelayUrl>,
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
fn probe_endpoint_builder(
    relay_url: &RelayUrl,
    auth_token: Option<&str>,
) -> iroh::endpoint::Builder {
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

/// Build an endpoint that does nothing but probe one relay for QUIC address
/// discovery: IP transports (QAD runs over UDP), the relay entry with QAD on,
/// and none of the net report's other probes, so its report has UDP only when
/// the relay answered QAD. No portmapping either: the endpoint never carries
/// a connection.
fn qad_endpoint_builder(relay_url: &RelayUrl, auth_token: Option<&str>) -> iroh::endpoint::Builder {
    let map = RelayMap::from_iter([relay_entry(relay_url, auth_token, true)]);
    Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Custom(map))
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .net_report_config(NetReportConfig::minimal())
        .portmapper_config(PortmapperConfig::Disabled)
}

/// Resolves once `endpoint`'s net report shows UDP working, which with the
/// map and report of [`qad_endpoint_builder`] means the relay answered QUIC
/// address discovery. Pending otherwise.
async fn quic_addr_discovery_answered(endpoint: &Endpoint) {
    let mut reports = endpoint.net_report();
    loop {
        if reports.get().is_some_and(|report| report.has_udp()) {
            return;
        }
        if reports.updated().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Whether `relay_url` serves QUIC address discovery, answered within `limit`:
/// the check alone, without the relay probe whose connection cuts off the
/// startup check (see [`probe_relay`]). `limit` should stay well below iroh's
/// 3 s probe timeout, since an answer that slow holds the net report back
/// almost as much as none. `false` also when the check endpoint cannot bind.
/// Its endpoint is closed before returning, as in [`probe_relay`].
pub(crate) async fn quic_addr_discovery_served(
    relay_url: &RelayUrl,
    auth_token: Option<&str>,
    limit: Duration,
    closes: &PendingCloses,
) -> bool {
    let endpoint = match qad_endpoint_builder(relay_url, auth_token).bind().await {
        Ok(endpoint) => endpoint,
        Err(e) => {
            warn!("Cannot check {relay_url} for QUIC address discovery: {e:#}");
            return false;
        }
    };
    let served = tokio::time::timeout(limit, quic_addr_discovery_answered(&endpoint))
        .await
        .is_ok();
    crate::endpoint::close_endpoint(endpoint, closes).await;
    served
}

/// What [`probe_relay`] found out about a relay that came online.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayProbe {
    /// Whether the relay serves QUIC address discovery (QAD).
    pub(crate) quic_addr_discovery: bool,
}

/// Probe a single custom relay by binding a relay-only endpoint and waiting for
/// it to come online, bounded by [`RELAY_CONNECT_TIMEOUT`]. `Ok` means the
/// relay connected (and accepted the auth token, if any); otherwise the error
/// describes the failure.
///
/// Alongside, a second endpoint checks whether the relay serves QUIC address
/// discovery on iroh's default UDP port 7842, and the answer is whatever it
/// learned by the time the relay came online: the check adds no time of its
/// own. That cut-off is the point. iroh does not choose a home relay until
/// its QAD probes of every relay in the map finish, and a relay that does not
/// answer them (a relay behind a Cloudflare Tunnel or any other HTTP-only
/// front, which carries no UDP) holds each full net report back by the probe
/// timeout, 3 s on iroh 1.5, so every endpoint start would wait for it: 3.0 s
/// against 0.3 s for the first report, measured against two relays behind
/// Cloudflare Tunnels. A relay that serves QAD answers in about one round
/// trip, well before its relay connection is up. One whose answer is no
/// faster than that (a network that drops UDP, a broken IPv6 route) would
/// slow the report down as well, so it is counted as not serving QAD too.
///
/// The check runs only with `check_quic_addr_discovery`, which the caller
/// sets when its endpoint has IP transports (see [`has_ip_transports`]): a
/// relay-only endpoint never probes QAD, and the check would send UDP
/// datagrams it was configured not to send. Without the check the relay
/// counts as not serving QAD.
///
/// Both endpoints are always closed before returning, with a bounded wait for
/// the close (see [`crate::endpoint::close_endpoint`]); a close that outlives
/// the wait is kept in `closes`.
pub(crate) async fn probe_relay(
    relay_url: &RelayUrl,
    auth_token: Option<&str>,
    check_quic_addr_discovery: bool,
    closes: &PendingCloses,
) -> Result<RelayProbe> {
    let bind_qad = async {
        match check_quic_addr_discovery {
            true => Some(qad_endpoint_builder(relay_url, auth_token).bind().await),
            false => None,
        }
    };
    let (endpoint, qad_endpoint) = futures::join!(
        probe_endpoint_builder(relay_url, auth_token).bind(),
        bind_qad
    );
    // The QAD check is best effort: an endpoint that cannot bind UDP cannot
    // use QAD either.
    let qad_endpoint = qad_endpoint.and_then(|bound| {
        bound
            .inspect_err(|e| warn!("Cannot check {relay_url} for QUIC address discovery: {e:#}"))
            .ok()
    });
    let endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(e) => {
            if let Some(qad_endpoint) = qad_endpoint {
                crate::endpoint::close_endpoint(qad_endpoint, closes).await;
            }
            return Err(e)
                .with_context(|| format!("Failed to bind probe endpoint for relay {relay_url}"));
        }
    };
    let mut quic_addr_discovery = false;
    let outcome = {
        let online = tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online());
        let answered = async {
            match &qad_endpoint {
                Some(qad_endpoint) => quic_addr_discovery_answered(qad_endpoint).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(online, answered);
        loop {
            tokio::select! {
                outcome = &mut online => break outcome,
                () = &mut answered, if !quic_addr_discovery => quic_addr_discovery = true,
            }
        }
    };
    // A report that landed in the same poll as the relay coming online.
    quic_addr_discovery |= qad_endpoint.as_ref().is_some_and(|qad_endpoint| {
        qad_endpoint
            .net_report()
            .get()
            .is_some_and(|report| report.has_udp())
    });
    // Read why before closing: the probe map holds this one relay, so its
    // status (if selected at all) carries the last connection failure.
    let failure = outcome.is_err().then(|| {
        endpoint
            .home_relay_status()
            .get()
            .first()
            .map_or_else(|| "no home relay selected".to_string(), relay_failure)
    });
    let close_qad = async {
        if let Some(qad_endpoint) = qad_endpoint {
            crate::endpoint::close_endpoint(qad_endpoint, closes).await;
        }
    };
    futures::join!(crate::endpoint::close_endpoint(endpoint, closes), close_qad);
    match failure {
        None => Ok(RelayProbe {
            quic_addr_discovery,
        }),
        Some(failure) => anyhow::bail!(
            "did not come online within {}s: {failure}",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Whether `endpoint` has IP transports, and so can use QUIC address
/// discovery at all. A relay-only endpoint
/// ([`crate::endpoint::EndpointOptions::relay_only`]) binds no UDP socket.
pub(crate) fn has_ip_transports(endpoint: &Endpoint) -> bool {
    !endpoint.bound_sockets().is_empty()
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
    relays: ProbedRelays,
    /// Whether the probe task has let go of its handle to the endpoint.
    released: bool,
}

impl ProbeProgress {
    fn settled(&self) -> bool {
        self.probed == self.total
    }

    fn all_failed(&self) -> bool {
        self.total > 0 && self.failures.len() == self.total
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
/// - A relay that serves QUIC address discovery is put back with it turned on.
///   It starts off because iroh does not choose a home relay until its QAD
///   probes of every relay finish, and a relay that does not answer them holds
///   each full net report back by iroh's 3 s probe timeout (see
///   [`probe_relay`]).
///
/// A relay that is down at startup does not stop the process: with at least
/// [`MIN_CUSTOM_RELAYS`] distinct relays configured the others carry it, and
/// refusing to start would turn a survivable relay outage into an outage of
/// every client that restarts during it. Only when every relay fails does the
/// start fail, if the endpoint is not online by then.
#[derive(Debug, Clone)]
pub struct RelayProbes(watch::Receiver<ProbeProgress>);

impl RelayProbes {
    /// Nothing to probe: the default relays.
    fn none() -> Self {
        let (_, progress) = watch::channel(ProbeProgress {
            released: true,
            ..ProbeProgress::default()
        });
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
        let RelayConfig::Custom { urls, auth_token } = relay_config else {
            return (Self::none(), None);
        };
        let (tx, rx) = watch::channel(ProbeProgress {
            total: urls.len(),
            ..ProbeProgress::default()
        });
        let slot = EndpointSlot(Arc::new(Mutex::new(Some(endpoint.clone()))));
        let task = tokio::spawn(apply_relay_probes(
            endpoint.closed(),
            slot.clone(),
            urls.clone(),
            auth_token.clone(),
            has_ip_transports(endpoint),
            closes.clone(),
            tx,
        ));
        (Self(rx), Some((task, slot)))
    }

    /// What the probe has found so far. Final once [`Self::is_settled`].
    pub fn current(&self) -> ProbedRelays {
        self.0.borrow().relays.clone()
    }

    /// Whether every custom relay has been probed and its result applied.
    /// Always true for the default relays.
    pub fn is_settled(&self) -> bool {
        self.0.borrow().settled()
    }

    /// Wait until every custom relay has been probed and its result applied
    /// to the endpoint, and return what was found. Bounded by
    /// [`RELAY_CONNECT_TIMEOUT`] plus the probe endpoints' bounded close.
    pub async fn settled(&self) -> ProbedRelays {
        let mut progress = self.0.clone();
        let settled = progress
            .wait_for(ProbeProgress::settled)
            .await
            .map(|progress| progress.relays.clone());
        // The probe task sends its last result before it ends, so this is as
        // far as it got: only an aborted task stops short.
        settled.unwrap_or_else(|_| progress.borrow().relays.clone())
    }

    /// Wait until the probe task no longer holds a handle to the endpoint.
    ///
    /// An endpoint's UDP sockets are released only with its last handle, and
    /// the probe task keeps one while its probes run (up to
    /// [`RELAY_CONNECT_TIMEOUT`] for a relay that does not answer). It lets
    /// go as soon as the endpoint's close begins, but only when it next runs.
    /// A caller that closes the endpoint and binds a new one on the same port
    /// awaits this between the two; it returns as soon as the task has run,
    /// without waiting for the probes. Returns at once for the default relays.
    pub async fn released(&self) {
        let mut progress = self.0.clone();
        // An error means the task is gone, and its handle with it.
        let _ = progress.wait_for(|progress| progress.released).await;
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
/// (`closed`, from [`Endpoint::closed`], which holds no handle to it), and says so
/// ([`RelayProbes::released`]): its sockets are released only with its last
/// handle, and a caller that closes the endpoint and binds a new one on the
/// same port must not find it still taken by a probe of a relay that does not
/// answer. The probes themselves run to the end either way, so that their own
/// endpoints are closed. They check for QUIC address discovery only with
/// `check_quic_addr_discovery` (see [`probe_relay`]).
async fn apply_relay_probes(
    closed: impl Future<Output = ()>,
    slot: EndpointSlot,
    urls: Vec<RelayUrl>,
    auth_token: Option<String>,
    check_quic_addr_discovery: bool,
    closes: PendingCloses,
    progress: watch::Sender<ProbeProgress>,
) {
    tokio::pin!(closed);
    let mut watching_close = true;
    info!("Probing {} custom relays for reachability...", urls.len());
    let mut probes: FuturesUnordered<_> = urls
        .iter()
        .map(|url| {
            let (token, closes) = (auth_token.as_deref(), &closes);
            async move {
                let probe = probe_relay(url, token, check_quic_addr_discovery, closes).await;
                (url, probe)
            }
        })
        .collect();
    let mut in_map = urls.len();
    loop {
        let next = tokio::select! {
            next = probes.next() => next,
            () = &mut closed, if watching_close => {
                watching_close = false;
                drop(slot.take());
                progress.send_modify(|progress| progress.released = true);
                continue;
            }
        };
        let Some((url, result)) = next else {
            break;
        };
        let (failure, quic_addr_discovery) = match result {
            Ok(probe) => (None, probe.quic_addr_discovery),
            Err(e) => (Some(format!("{e:#}")), false),
        };
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
        if let (true, Some(endpoint)) = (quic_addr_discovery, &endpoint) {
            let entry = relay_entry(url, auth_token.as_deref(), true);
            endpoint.insert_relay(url.clone(), Arc::new(entry)).await;
        }
        progress.send_modify(|progress| {
            progress.probed += 1;
            if let Some(failure) = failure {
                progress.failures.push((url.clone(), failure));
            }
            if left_out {
                progress.relays.left_out.push(url.clone());
            }
            if quic_addr_discovery {
                progress.relays.quic_addr_discovery.push(url.clone());
            }
        });
    }
    drop(slot.take());
    progress.send_modify(|progress| progress.released = true);
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
    let online = progress.total - progress.failures.len();
    if !check_quic_addr_discovery {
        return;
    }
    match progress.relays.quic_addr_discovery.len() {
        0 => info!("None of the {online} reachable custom relays serves QUIC address discovery"),
        n => info!(
            "{n} of the {online} reachable custom relays serve QUIC address discovery: {}",
            progress
                .relays
                .quic_addr_discovery
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Wait for `endpoint` to come online while `probes` runs beside it.
///
/// Fails when every custom relay failed its probe, or when the endpoint is
/// still offline [`RELAY_CONNECT_TIMEOUT`] after the latest change to its relay
/// map: taking a relay out restarts the wait, because that is what lets an
/// endpoint stuck on a relay that cannot be connected re-home on one that
/// can. Nor does the wait end while a probe is still running, which may yet
/// take out the relay that keeps it offline.
pub(crate) async fn wait_online_beside(endpoint: &Endpoint, probes: &RelayProbes) -> Result<()> {
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
    let timed_out = || {
        anyhow::anyhow!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            RELAY_CONNECT_TIMEOUT.as_secs()
        )
    };
    let mut deadline = Some(Instant::now() + RELAY_CONNECT_TIMEOUT);
    let mut left_out = probes.0.borrow().relays.left_out.len();
    let mut probing = !probes.is_settled();
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
                    return Err(timed_out());
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
                    anyhow::bail!(
                        "all {} custom relays failed to come online:\n  {}",
                        progress.total,
                        progress.describe_failures()
                    );
                }
                probing = !progress.settled();
                if progress.relays.left_out.len() > left_out {
                    left_out = progress.relays.left_out.len();
                    deadline = Some(Instant::now() + RELAY_CONNECT_TIMEOUT);
                } else if deadline.is_none() && !probing {
                    return Err(timed_out());
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

    #[test]
    fn the_relay_map_holds_every_custom_relay_with_the_token_and_no_quic_addr_discovery() {
        let cfg = RelayConfig::from_urls_with_token(&two(), Some("secret".to_string())).unwrap();
        let RelayMode::Custom(map) = cfg.relay_mode() else {
            panic!("custom relays give a custom relay map");
        };
        assert_eq!(map.len(), 2);
        for url in [RELAY, RELAY2] {
            let relay = map.get(&url.parse::<RelayUrl>().unwrap()).unwrap();
            assert_eq!(relay.auth_token.as_deref(), Some("secret"));
            assert!(relay.quic.is_none(), "QAD stays off until the probe finds it");
        }
        assert!(matches!(RelayConfig::Default.relay_mode(), RelayMode::Default));
    }

    #[test]
    fn a_relay_entry_carries_quic_addr_discovery_only_when_asked() {
        let url: RelayUrl = RELAY.parse().unwrap();
        // What iroh assumes for a relay given by URL alone (UDP 7842).
        let default_port = iroh::RelayConfig::from(url.clone())
            .quic
            .map(|quic| quic.port)
            .expect("iroh probes QAD on a relay given by URL");
        let with = relay_entry(&url, Some("secret"), true);
        assert_eq!(with.quic.map(|quic| quic.port), Some(default_port));
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
    async fn a_relay_only_endpoint_has_no_ip_transports() {
        // A relay-only endpoint needs a relay to bind at all; it is never
        // connected to here.
        let relay_only = probe_endpoint_builder(&RELAY.parse().unwrap(), None)
            .bind()
            .await
            .unwrap();
        assert!(!has_ip_transports(&relay_only));
        let direct = Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .bind()
            .await
            .unwrap();
        assert!(has_ip_transports(&direct));
        futures::join!(relay_only.close(), direct.close());
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
        let probed = tokio::time::timeout(Duration::from_millis(100), probes.settled())
            .await
            .expect("nothing to wait for");
        assert_eq!(probed, ProbedRelays::default());
        tokio::time::timeout(Duration::from_millis(100), probes.released())
            .await
            .expect("no probe task holds the endpoint");
        endpoint.close().await;
    }
}
