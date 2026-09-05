//! Server-side home-relay failover.
//!
//! A server configured with custom relays is reachable to off-LAN clients
//! *only* through its home relay: with n0 discovery off, clients dial with
//! relay hints, and a relay forwards QUIC Initials only to endpoints currently
//! registered on it. iroh keeps that registration alive on its own and, when
//! the home relay stops answering its net-report probe, moves to another
//! configured relay within a re-probe cycle (20–26 s). What it does **not**
//! recover from on its own is a home relay that still answers probes while
//! the relay connection cannot be (re-)established: every net report keeps
//! preferring that relay, the relay actor keeps failing to connect to it, and
//! the server is dialable from nowhere. That is the shape of the incident
//! observed on iroh 1.0.3 (relays behind Cloudflare Tunnels that reset idle
//! WebSockets roughly hourly): no registration on any relay until the process
//! was restarted, while LAN clients that find it over mDNS kept working and
//! masked the outage.
//!
//! [`fail_over_home_relay`] observes [`Endpoint::home_relay_status`] and,
//! after [`RELAY_OUTAGE_FAILOVER`] without a connected home relay, takes the
//! wedged relay **out of the endpoint's relay map**
//! ([`Endpoint::remove_relay`]). A relay-map change forces a full net report,
//! the report can only prefer a relay that is still in the map, the endpoint
//! homes there, and clients dialing with the full relay list as hints reach
//! it through that relay. Nothing is torn down: the endpoint, its identity,
//! its direct paths, and every established connection stay as they are; a
//! connection whose only path ran through the dead relay times out on its own
//! and that client redials. This is why a custom relay set is required to hold
//! at least [`crate::relay::MIN_CUSTOM_RELAYS`] distinct relays.
//!
//! The removed relay is put back once a probe (the same relay-only probe used
//! at startup) shows it connectable again, checked every
//! [`RELAY_RESTORE_INTERVAL`]. Putting it back unprobed would let a relay that
//! answers HTTP but refuses relay connections be re-selected — and fail
//! again — every few minutes. iroh drops a demoted relay's actor after 60 s
//! idle, so a relay that comes back is dialed by a fresh actor.
//!
//! Several relays can be out of the map at once: if the relay the endpoint
//! moved onto wedges too while the first is still unconnectable, it is removed
//! as well. The last relay left in the map is never removed. When there is
//! nothing to remove (no home relay selected, or the home relay is the last
//! one), the endpoint is nudged with a no-op relay-map change instead, which
//! forces a fresh report the same way.
//!
//! Only the *home* relay matters: non-home relays are connected on demand and
//! dropped after a minute idle, which is normal and not an outage. With the
//! default relays the future never resolves and never acts: there
//! reachability rests on n0 publishing and resolution, not on one relay
//! registration.

use crate::relay::{RelayConfig, probe_relay};
use iroh::endpoint::RelayStatus;
use iroh::{Endpoint, RelayMap, RelayUrl, Watcher};
use std::time::Duration;
use tokio::time::Instant;

/// How long the endpoint may go without a connected home relay before the
/// wedged relay is taken out of the relay map. Long enough to ride out a
/// routine relay reconnect (iroh's own reconnect backoff caps at 16 s) plus
/// the 20–26 s cadence of its periodic net report, which on its own re-homes
/// the endpoint when the relay is *really* down.
pub const RELAY_OUTAGE_FAILOVER: Duration = Duration::from_secs(60);

/// How long an outage must last before it is reported. A home-relay change
/// publishes the new relay as connecting before it connects, so a healthy
/// move would otherwise log as a momentary outage.
const RELAY_OUTAGE_LOG_GRACE: Duration = Duration::from_secs(5);

/// How often a relay that was taken out of the map is probed for
/// restoration. Longer than iroh's 60 s idle cleanup of a demoted relay
/// actor, so a relay that comes back is dialed by a fresh actor rather than
/// the one that was stuck on it.
pub const RELAY_RESTORE_INTERVAL: Duration = Duration::from_secs(90);

/// Watch `endpoint`'s home relay and fail over in place when it is lost for
/// [`RELAY_OUTAGE_FAILOVER`]; see the module docs. Never resolves: run it
/// alongside the accept loop and drop it with the endpoint. Pending forever
/// with the default relays.
pub async fn fail_over_home_relay(endpoint: &Endpoint, relay_config: &RelayConfig) {
    let RelayConfig::Custom { urls, auth_token } = relay_config else {
        std::future::pending().await
    };
    if urls.is_empty() {
        log::error!("Custom relay set is empty; home-relay failover has nothing to work with");
        std::future::pending().await
    }
    let mut relays = EndpointRelays {
        endpoint,
        configured: relay_config.relay_mode().relay_map(),
        urls: urls.clone(),
        auth_token: auth_token.clone(),
    };
    run_failover(
        endpoint.home_relay_status(),
        |statuses| describe_statuses(statuses),
        &mut relays,
    )
    .await
}

/// What the home-relay status amounts to for failover purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HomeRelay {
    /// Some home relay is connected.
    Connected(RelayUrl),
    /// No home relay is connected. `home` is the relay the endpoint is
    /// trying to use (`None` when it has not selected one).
    Down {
        home: Option<RelayUrl>,
        reason: String,
    },
}

/// Classify a home-relay status vector for the failover loop.
fn describe_statuses(statuses: &[RelayStatus]) -> HomeRelay {
    if let Some(connected) = statuses.iter().find(|s| s.is_connected()) {
        return HomeRelay::Connected(connected.url().clone());
    }
    let Some(home) = statuses.first() else {
        return HomeRelay::Down {
            home: None,
            reason: "no home relay selected".into(),
        };
    };
    let reason = statuses
        .iter()
        .map(|s| match s.last_error() {
            Some(e) => format!("{} disconnected ({e:#})", s.url()),
            None => format!("{} not connected", s.url()),
        })
        .collect::<Vec<_>>()
        .join("; ");
    HomeRelay::Down {
        home: Some(home.url().clone()),
        reason,
    }
}

/// The relay-map operations the failover loop performs, abstracted so the
/// loop can be driven by a test double.
trait FailoverRelays {
    /// The configured relays, in configured order.
    fn configured(&self) -> &[RelayUrl];

    /// Take `url` out of the map so the next net report must choose another.
    /// Returns whether it was in the map.
    async fn remove(&mut self, url: &RelayUrl) -> bool;

    /// Re-insert `url`, which is still in the map, unchanged: a relay-map
    /// change forces a fresh net report without changing the choice on offer.
    async fn nudge(&mut self, url: &RelayUrl);

    /// Put a removed relay back if it is connectable again. Returns whether
    /// it is back in the map.
    async fn restore(&mut self, url: &RelayUrl) -> bool;
}

/// The real endpoint's relay map.
struct EndpointRelays<'a> {
    endpoint: &'a Endpoint,
    /// The configured relay map, kept as the source of each relay's
    /// configuration (URL, auth token) for re-insertion.
    configured: RelayMap,
    /// The configured relay URLs, in configured order.
    urls: Vec<RelayUrl>,
    auth_token: Option<String>,
}

impl FailoverRelays for EndpointRelays<'_> {
    fn configured(&self) -> &[RelayUrl] {
        &self.urls
    }

    async fn remove(&mut self, url: &RelayUrl) -> bool {
        if self.endpoint.remove_relay(url).await.is_none() {
            log::warn!("{url} is not in the relay map");
            return false;
        }
        log::warn!(
            "Removed {url} from the relay map so the next net report homes this endpoint on \
             another configured relay"
        );
        true
    }

    async fn nudge(&mut self, url: &RelayUrl) {
        let Some(config) = self.configured.get(url) else {
            log::error!("{url} is not a configured relay; cannot re-insert it");
            return;
        };
        log::warn!("Re-inserting {url} into the relay map unchanged to force a fresh net report");
        self.endpoint.insert_relay(url.clone(), config).await;
    }

    async fn restore(&mut self, url: &RelayUrl) -> bool {
        match probe_relay(url, self.auth_token.as_deref()).await {
            Ok(()) => {
                let Some(config) = self.configured.get(url) else {
                    log::error!(
                        "{url} is connectable but not a configured relay; cannot put it back in \
                         the relay map"
                    );
                    return false;
                };
                self.endpoint.insert_relay(url.clone(), config).await;
                true
            }
            Err(e) => {
                log::warn!(
                    "{url} is still not connectable ({e:#}); leaving it out of the relay map, \
                     next check in {}s",
                    RELAY_RESTORE_INTERVAL.as_secs()
                );
                false
            }
        }
    }
}

/// Outage bookkeeping shared by the loop and its status observer.
#[derive(Default)]
struct Outage {
    /// When the current outage began; `None` while a home relay is connected.
    since: Option<Instant>,
    /// When to report the outage, unless it ends first; `None` once reported.
    report_at: Option<Instant>,
    /// Why the home relay is down, for the report.
    reason: String,
    /// When to fail over if the outage lasts; `None` while connected or
    /// while a failover is in progress.
    fail_over_at: Option<Instant>,
    /// The last home relay seen connected, to log only changes.
    last_connected: Option<RelayUrl>,
}

impl Outage {
    /// Log and record a status observation.
    fn observe(&mut self, state: &HomeRelay) {
        match state {
            HomeRelay::Connected(url) => {
                match self.since.take() {
                    // Reported outages end loudly; a blip that ended within
                    // the grace period is just a home change.
                    Some(since) if self.report_at.is_none() => log::info!(
                        "Home relay connection restored on {url} after {:.0}s",
                        since.elapsed().as_secs_f64()
                    ),
                    _ if self.last_connected.as_ref() != Some(url) => {
                        log::info!("Home relay: {url} connected")
                    }
                    _ => {}
                }
                self.report_at = None;
                self.fail_over_at = None;
                self.last_connected = Some(url.clone());
            }
            HomeRelay::Down { reason, .. } => {
                if self.since.is_none() {
                    let now = Instant::now();
                    self.since = Some(now);
                    self.report_at = Some(now + RELAY_OUTAGE_LOG_GRACE);
                    self.fail_over_at = Some(now + RELAY_OUTAGE_FAILOVER);
                }
                self.reason = reason.clone();
            }
        }
    }

    /// Report the outage once it has outlasted the grace period.
    fn report(&mut self) {
        self.report_at = None;
        log::warn!(
            "No connected home relay ({}); off-LAN clients cannot reach this server until \
             it reconnects. Failing over to another relay in {}s unless it does",
            self.reason,
            RELAY_OUTAGE_FAILOVER.as_secs()
        );
    }
}

/// Wait for the next status value; pending forever once the watcher is
/// disconnected (the endpoint is gone).
async fn next_value<W: Watcher>(watcher: &mut W) -> W::Value {
    match watcher.updated().await {
        Ok(value) => value,
        Err(_disconnected) => std::future::pending().await,
    }
}

/// Sleep until `at`; pending forever when there is no deadline.
async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Act on a home relay that has been down for the whole window: remove it
/// from the map, or nudge the endpoint when there is nothing to remove.
/// Returns the URL that is now out of the map, if any.
async fn fail_over<R: FailoverRelays>(
    relays: &mut R,
    home: Option<RelayUrl>,
    removed: &[RelayUrl],
) -> Option<RelayUrl> {
    let in_map: Vec<RelayUrl> = relays
        .configured()
        .iter()
        .filter(|u| !removed.contains(u))
        .cloned()
        .collect();
    let home = home.filter(|home| !removed.contains(home));
    match home {
        // Never remove the last relay left in the map.
        Some(home) if in_map.len() > 1 => {
            if relays.remove(&home).await {
                return Some(home);
            }
            if let Some(url) = in_map.first() {
                relays.nudge(url).await;
            }
        }
        Some(home) => relays.nudge(&home).await,
        None => {
            if let Some(url) = in_map.first() {
                relays.nudge(url).await;
            }
        }
    }
    None
}

/// The failover loop proper, generic over the status source and the relay
/// map so tests can drive it with doubles.
async fn run_failover<W, D, R>(mut watcher: W, describe: D, relays: &mut R)
where
    W: Watcher,
    D: Fn(&W::Value) -> HomeRelay,
    R: FailoverRelays,
{
    let mut outage = Outage::default();
    // Relays taken out of the map, each with when it is next probed for
    // restoration.
    let mut removed: Vec<(RelayUrl, Instant)> = Vec::new();
    let mut value = watcher.get();
    outage.observe(&describe(&value));
    loop {
        let check_at = removed.iter().map(|(_, at)| *at).min();
        let out: Vec<RelayUrl> = removed.iter().map(|(url, _)| url.clone()).collect();
        tokio::select! {
            () = sleep_until_opt(outage.report_at) => outage.report(),
            () = sleep_until_opt(outage.fail_over_at) => {
                outage.fail_over_at = None;
                let HomeRelay::Down { home, .. } = describe(&value) else {
                    continue;
                };
                log::warn!(
                    "Still no connected home relay after {:.0}s; failing over",
                    outage
                        .since
                        .map(|since| since.elapsed().as_secs_f64())
                        .unwrap_or_default()
                );
                if let Some(url) = fail_over(relays, home, &out).await {
                    removed.push((url, Instant::now() + RELAY_RESTORE_INTERVAL));
                }
                // Still down after that (the status watcher clears this if
                // not): the next failover is a full window away, not
                // immediate.
                outage.fail_over_at = Some(Instant::now() + RELAY_OUTAGE_FAILOVER);
            }
            () = sleep_until_opt(check_at) => {
                let now = Instant::now();
                for (url, at) in std::mem::take(&mut removed) {
                    if at > now {
                        removed.push((url, at));
                    } else if relays.restore(&url).await {
                        log::info!("{url} is connectable again and back in the relay map");
                    } else {
                        removed.push((url, now + RELAY_RESTORE_INTERVAL));
                    }
                }
            }
            next = next_value(&mut watcher) => {
                value = next;
                outage.observe(&describe(&value));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0_watcher::Watchable;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// The home-relay status as a test double sees it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Status {
        /// Connected on relay A.
        UpOnA,
        /// Connected on relay B.
        UpOnB,
        /// Home relay A selected but not connected.
        DownOnA,
        /// Home relay B selected but not connected.
        DownOnB,
        /// Home relay C selected but not connected.
        DownOnC,
        /// No home relay selected at all.
        NoHome,
    }

    fn relay_a() -> RelayUrl {
        "https://a.example.com./".parse().unwrap()
    }

    fn relay_b() -> RelayUrl {
        "https://b.example.com./".parse().unwrap()
    }

    fn relay_c() -> RelayUrl {
        "https://c.example.com./".parse().unwrap()
    }

    fn down_on(url: RelayUrl) -> HomeRelay {
        HomeRelay::Down {
            home: Some(url),
            reason: "down".into(),
        }
    }

    fn describe(status: &Status) -> HomeRelay {
        match status {
            Status::UpOnA => HomeRelay::Connected(relay_a()),
            Status::UpOnB => HomeRelay::Connected(relay_b()),
            Status::DownOnA => down_on(relay_a()),
            Status::DownOnB => down_on(relay_b()),
            Status::DownOnC => down_on(relay_c()),
            Status::NoHome => HomeRelay::Down {
                home: None,
                reason: "no home relay selected".into(),
            },
        }
    }

    /// What the loop did, with the (paused-clock) time since the test began.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Action {
        Remove { url: RelayUrl, at: Duration },
        Nudge { url: RelayUrl, at: Duration },
        Restore { url: RelayUrl, restored: bool, at: Duration },
    }

    #[derive(Clone)]
    struct FakeRelays {
        started: Instant,
        configured: Vec<RelayUrl>,
        actions: Arc<Mutex<Vec<Action>>>,
        /// Whether a restore probe succeeds.
        connectable: Arc<AtomicBool>,
        status: Watchable<Status>,
        /// What the status flips to once the loop has acted on the relay
        /// map (`None` = stays as it is).
        after_fail_over: Option<Status>,
    }

    impl FakeRelays {
        fn new(status: &Watchable<Status>, after_fail_over: Option<Status>) -> Self {
            Self {
                started: Instant::now(),
                configured: vec![relay_a(), relay_b(), relay_c()],
                actions: Arc::new(Mutex::new(Vec::new())),
                connectable: Arc::new(AtomicBool::new(true)),
                status: status.clone(),
                after_fail_over,
            }
        }

        fn actions(&self) -> Vec<Action> {
            self.actions.lock().unwrap().clone()
        }

        fn acted(&self, action: Action) {
            self.actions.lock().unwrap().push(action);
            if let Some(status) = self.after_fail_over {
                self.status.set(status).ok();
            }
        }
    }

    impl FailoverRelays for FakeRelays {
        fn configured(&self) -> &[RelayUrl] {
            &self.configured
        }

        async fn remove(&mut self, url: &RelayUrl) -> bool {
            self.acted(Action::Remove {
                url: url.clone(),
                at: self.started.elapsed(),
            });
            true
        }

        async fn nudge(&mut self, url: &RelayUrl) {
            self.acted(Action::Nudge {
                url: url.clone(),
                at: self.started.elapsed(),
            });
        }

        async fn restore(&mut self, url: &RelayUrl) -> bool {
            let restored = self.connectable.load(Ordering::SeqCst);
            self.actions.lock().unwrap().push(Action::Restore {
                url: url.clone(),
                restored,
                at: self.started.elapsed(),
            });
            restored
        }
    }

    /// Run the loop against `status` for `bound` of paused time.
    async fn run_for(status: &Watchable<Status>, relays: &mut FakeRelays, bound: Duration) {
        let _ = tokio::time::timeout(bound, run_failover(status.watch(), describe, relays)).await;
    }

    const SEC: Duration = Duration::from_secs(1);

    #[tokio::test(start_paused = true)]
    async fn healthy_relay_never_acts() {
        let status = Watchable::new(Status::UpOnA);
        let mut relays = FakeRelays::new(&status, None);
        run_for(&status, &mut relays, RELAY_OUTAGE_FAILOVER * 5).await;
        assert!(relays.actions().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_outage_removes_the_home_relay_and_restores_it_once_connectable() {
        let status = Watchable::new(Status::DownOnA);
        let mut relays = FakeRelays::new(&status, Some(Status::UpOnB));
        relays.connectable.store(false, Ordering::SeqCst);
        let connectable = relays.connectable.clone();
        let flipper = async move {
            // The relay comes back between the first and second restore checks.
            tokio::time::sleep(RELAY_OUTAGE_FAILOVER + RELAY_RESTORE_INTERVAL + 5 * SEC).await;
            connectable.store(true, Ordering::SeqCst);
        };
        tokio::join!(
            run_for(
                &status,
                &mut relays,
                RELAY_OUTAGE_FAILOVER + RELAY_RESTORE_INTERVAL * 3
            ),
            flipper
        );
        assert_eq!(
            relays.actions(),
            vec![
                Action::Remove {
                    url: relay_a(),
                    at: RELAY_OUTAGE_FAILOVER,
                },
                Action::Restore {
                    url: relay_a(),
                    restored: false,
                    at: RELAY_OUTAGE_FAILOVER + RELAY_RESTORE_INTERVAL,
                },
                Action::Restore {
                    url: relay_a(),
                    restored: true,
                    at: RELAY_OUTAGE_FAILOVER + RELAY_RESTORE_INTERVAL * 2,
                },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_before_the_deadline_resets_the_clock() {
        let status = Watchable::new(Status::UpOnA);
        let mut relays = FakeRelays::new(&status, None);
        let flipper = {
            let status = status.clone();
            async move {
                // Drop out for half the window, recover, drop out again for
                // half a window: never long enough to act.
                tokio::time::sleep(5 * SEC).await;
                status.set(Status::DownOnA).ok();
                tokio::time::sleep(RELAY_OUTAGE_FAILOVER / 2).await;
                status.set(Status::UpOnA).ok();
                tokio::time::sleep(RELAY_OUTAGE_FAILOVER / 2 + 5 * SEC).await;
                status.set(Status::DownOnA).ok();
                tokio::time::sleep(RELAY_OUTAGE_FAILOVER / 2).await;
                status.set(Status::UpOnA).ok();
            }
        };
        tokio::join!(
            run_for(&status, &mut relays, RELAY_OUTAGE_FAILOVER * 4),
            flipper
        );
        assert!(relays.actions().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_stays_down_is_nudged_while_out_and_removed_again_after_restore() {
        // Removing A changes nothing (status stays down on A): while A is
        // out, each further window only nudges a relay still in the map;
        // once A is restored, the next window removes it again.
        let status = Watchable::new(Status::DownOnA);
        let mut relays = FakeRelays::new(&status, None);
        run_for(&status, &mut relays, 290 * SEC).await;
        assert_eq!(
            relays.actions(),
            vec![
                Action::Remove {
                    url: relay_a(),
                    at: 60 * SEC,
                },
                Action::Nudge {
                    url: relay_b(),
                    at: 120 * SEC,
                },
                Action::Restore {
                    url: relay_a(),
                    restored: true,
                    at: 150 * SEC,
                },
                Action::Remove {
                    url: relay_a(),
                    at: 180 * SEC,
                },
                Action::Nudge {
                    url: relay_b(),
                    at: 240 * SEC,
                },
                Action::Restore {
                    url: relay_a(),
                    restored: true,
                    at: 270 * SEC,
                },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_home_relay_selected_only_nudges() {
        let status = Watchable::new(Status::NoHome);
        let mut relays = FakeRelays::new(&status, Some(Status::UpOnB));
        run_for(&status, &mut relays, RELAY_OUTAGE_FAILOVER * 3).await;
        assert_eq!(
            relays.actions(),
            vec![Action::Nudge {
                url: relay_a(),
                at: RELAY_OUTAGE_FAILOVER,
            }],
            "nothing was removed, so nothing is restored"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_outage_after_recovery_gets_its_own_window() {
        let status = Watchable::new(Status::DownOnA);
        let mut relays = FakeRelays::new(&status, Some(Status::UpOnB));
        let flipper = {
            let status = status.clone();
            async move {
                // Failover at 60 s homes on B; restore of A at 150 s. Then
                // B is lost at 200 s: a fresh window, failover at 260 s.
                tokio::time::sleep(200 * SEC).await;
                status.set(Status::DownOnA).ok();
            }
        };
        tokio::join!(
            run_for(&status, &mut relays, 300 * SEC),
            flipper
        );
        assert_eq!(
            relays.actions(),
            vec![
                Action::Remove {
                    url: relay_a(),
                    at: 60 * SEC,
                },
                Action::Restore {
                    url: relay_a(),
                    restored: true,
                    at: 150 * SEC,
                },
                Action::Remove {
                    url: relay_a(),
                    at: 260 * SEC,
                },
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_wedged_relay_is_removed_while_the_first_is_still_out_but_never_the_last() {
        // A is removed at 60 s and stays unconnectable. The endpoint moves to
        // B, which wedges too: B is removed at 120 s while A is still out.
        // Then C wedges, but it is the last relay in the map, so at 180 s it
        // is only nudged.
        let status = Watchable::new(Status::DownOnA);
        let mut relays = FakeRelays::new(&status, None);
        relays.connectable.store(false, Ordering::SeqCst);
        let flipper = {
            let status = status.clone();
            async move {
                tokio::time::sleep(61 * SEC).await;
                status.set(Status::DownOnB).ok();
                tokio::time::sleep(60 * SEC).await;
                status.set(Status::DownOnC).ok();
            }
        };
        tokio::join!(run_for(&status, &mut relays, 200 * SEC), flipper);
        assert_eq!(
            relays.actions(),
            vec![
                Action::Remove {
                    url: relay_a(),
                    at: 60 * SEC,
                },
                Action::Remove {
                    url: relay_b(),
                    at: 120 * SEC,
                },
                Action::Restore {
                    url: relay_a(),
                    restored: false,
                    at: 150 * SEC,
                },
                Action::Nudge {
                    url: relay_c(),
                    at: 180 * SEC,
                },
            ]
        );
    }
}
