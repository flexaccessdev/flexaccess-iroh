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
