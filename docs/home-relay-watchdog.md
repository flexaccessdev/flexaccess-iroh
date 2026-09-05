# The Home-Relay Watchdog

A server configured with custom relays is reachable to off-LAN clients *only*
through its home relay: with n0 discovery off, clients dial with relay hints,
and a relay forwards QUIC Initials only to endpoints currently registered on
it. iroh keeps that registration alive on its own, but it has been observed
(v1.0.3, relays behind Cloudflare Tunnels that reset idle WebSockets roughly
hourly) to silently lose its home relay for good after one such reset: no dial
retries, no warnings, no registration on any relay. The server just stops being
dialable until the process restarts, while LAN clients that find it over mDNS
keep working and mask the outage. Relay-only clients see connect timeouts.

The watchdog is `flexaccess_iroh::relay_watchdog::watch_home_relay`; each
program's server serve loop drives it. It is armed for **custom relays only**:
with the default relays reachability rests on n0 publishing and resolution,
not on one relay registration.

## Why it is still here on iroh 1.1.0

That observation was made on iroh 1.0.3. All three programs now run iroh 1.1.0
(ezvpn through its `ezvpn-send-backpressure-1.1.0` fork), and **1.1.0 does not
fix this**. Checked against the released sources on 2026-09-04:

- `iroh-relay`'s client — the WebSocket layer the reset happens in — is
  byte-identical between 1.0.3 and 1.1.0.
- The reconnect machinery in `iroh/src/socket/transports/relay/actor.rs` is
  unchanged: `build_backoff()` still uses `.without_max_times()` so retries can
  never exhaust, the 15 s `PING_INTERVAL` and its ping-tracker timeout,
  `is_home_relay` exempting the home relay from inactive cleanup, and
  `reap_active_relays` re-spawning it.
- On disconnect the actor only marks the relay `Disconnected` and retries the
  *same* URL. Nothing triggers a fresh net report, so no new home relay is ever
  chosen.
- The one relay fix that did land, [#4444], keeps priority messages answered
  during reconnect backoff. It is a fragment split out of [#4435] (whose
  description reads "Includes #4444"), not a fix for this — it changes no
  reconnect decision.

[#4435] is the upstream work in this area, and it is **not** a fix for this
either. It is a *failover* design: when the home relay dies it forces a net
report, picks a **different** relay as home, republishes the endpoint address,
and has clients re-resolve the server through DNS/pkarr and open a path over
the new relay, keeping existing connections and their LAN paths. Ported onto
1.1.0 for evaluation on 2026-09-04, it does not apply to these programs:

- It changes no reconnect decision. The stall is the reconnect loop going
  quiet, with the server registered on *neither* relay; the PR relies on that
  loop to come back on its own.
- With a single custom relay the forced report re-picks the same relay, which
  the relay actor treats as "no change" and ignores. It never reconnects the
  relay it already has.
- Custom relays turn internet address lookup off (clients dial with static
  relay hints), and the PR's client-side re-resolve stops when no lookup
  service is configured.
- What is left is a forced net report 2 s after loss: the watchdog's 60 s
  nudge, earlier, and without the nudge's socket rebind and relay ping.

It is also an open `[wip]` draft, untouched since 2026-07-27, based on
`tests/patchbay-relay` rather than `main`, and pinned to an unreleased `noq`
branch (n0-computer/noq#770; without it, data in flight on a dead relay path
stalls until noq's timers fire). Its patchbay test is a two-relay, DNS-lookup
failover, not this failure.

So the watchdog stays. Nothing released or pending upstream addresses the
stall, and upgrading alone is not evidence: the reconnect loop already claimed
to retry forever on 1.0.3, yet the server stopped retrying, so the root cause
was never established. Removing the watchdog needs the original failure
reproduced and cleared without it. Whether the 60 s nudge alone ever recovers
it is equally unknown, so the rebuild step stays too.

[#4444]: https://github.com/n0-computer/iroh/pull/4444
[#4435]: https://github.com/n0-computer/iroh/pull/4435

## Escalation

The watchdog observes `Endpoint::home_relay_status()` and escalates like a
client's reconnect loop:

1. **Nudge** — after `RELAY_OUTAGE_NUDGE` (60 s) without a connected home
   relay it calls `Endpoint::network_change()`, which forces a fresh net
   report and relay re-selection. Enough when only iroh's bookkeeping went
   stale. The 60 s rides out a routine relay reconnect (iroh's own backoff
   caps at 16 s) plus the ~25 s cadence of its periodic net report.
2. **Rebuild** — at the caller's rebuild deadline (`RELAY_OUTAGE_REBUILD`,
   180 s from the outage start, by default) it resolves with a `RelayOutage`,
   telling the serve loop to replace the endpoint: the in-process equivalent
   of the restart known to fix it. The loop closes the wedged endpoint
   (bounded wait, a slow close finishes in the background), binds a fresh one
   with the **same identity** so the id clients dial never changes, and
   accepts on it. Everything else the process holds — listeners, address
   pools, client registries, status sockets — carries over; the old
   endpoint's connections end with it and those clients reconnect on their
   own. A failed rebuild is retried every 30 s.

A reconnect at any point resets the clock. Only the *home* relay matters:
non-home relays are connected on demand and dropped after a minute idle, which
is normal and never counts as an outage.

## Creation is strict, rebuild is tolerant

The rebuild recipe (`flexaccess_iroh::endpoint::rebuild_endpoint`, wrapped by
each program's `server_rebuild_factory`) deliberately differs from first
creation (`create_endpoint`):

- **No per-relay probe.** At creation the probe validates the configuration
  and fails fast if *any* relay is down. Mid-outage that strictness would
  block recovery through the one relay that still answers.
- **The online wait may fail.** A fresh endpoint is no worse than the wedged
  one it replaces — LAN peers can still find it over mDNS — and the watchdog
  trips again if the relays stay unreachable.

## Backing off when the relay itself is down

A rebuild only helps when iroh's bookkeeping went stale. When the relay is
really unreachable the fresh endpoint never registers either, and rebuilding
again every three minutes would keep dropping the LAN clients that still work.
So the watchdog reports whether the endpoint held a home relay at *any* point
of the watch (`RelayOutage::relay_seen`), and the serve loop doubles the
rebuild deadline for each consecutive endpoint that never did: 180 s, 6 m,
12 m, 24 m, then capped at 30 m. An endpoint that registers resets the
escalation. The 60 s nudge is unaffected.

## Clients

A client has no home-relay registration to lose, but the same wedge (a relay
link lost to a ping timeout that never re-establishes, stale cached paths,
dead discovery state) can hit its endpoint. flextunnel's client reconnect loop
escalates to `RebuildableEndpoint::rebuild` after repeated failures: a shared
`Clone` handle whose concurrent rebuild calls coalesce, so two tasks noticing
the same dead endpoint produce one replacement.

## Where this lives

| Repo | Watchdog + rebuild policy | Serve loop (closes, rebuilds, backs off) |
|---|---|---|
| [flexaccess-iroh] | `src/relay_watchdog.rs`, `src/endpoint.rs` | — |
| [flextunnel] | crate | `crates/flextunnel-cli/src/main.rs`; clients use `RebuildableEndpoint` |
| [ezvpn] | crate | `VpnServer::run` in `src/tunnel/server.rs` |
| [tunnel-rs] | crate | `run_multi_source_server` in `src/iroh_mode/multi_source.rs` |

[flexaccess-iroh]: https://github.com/flexaccessdev/flexaccess-iroh
[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
