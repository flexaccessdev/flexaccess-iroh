# Relay Failover

How a server on custom relays stays reachable when the relay it is homed on
stops working, and why that takes **at least two custom relays** and no
teardown of anything. This replaces the home-relay watchdog that rebuilt the
endpoint; see [History](#history) for what that was and why it is gone.

A server configured with custom relays is reachable to off-LAN clients *only*
through its home relay: with n0 discovery off, clients dial with relay hints,
and a relay forwards QUIC Initials only to endpoints currently registered on
it. Everything below is about keeping that one registration somewhere useful.

The implementation is `flexaccess_iroh::relay_failover::fail_over_home_relay`;
each program's server runs it alongside its accept loop. It is armed for
**custom relays only**: with the default relays reachability rests on n0
publishing and resolution, not on one relay registration. Since v0.0.8 the
same outage is also survived by a process that *starts* while it lasts: the
startup probe leaves a relay it cannot connect out of the relay map, and the
failover puts it back once it is connectable (see
[Starting during an outage](#starting-during-an-outage)).

## What iroh 1.1.0 does on its own

Checked against the released sources on 2026-09-04.

- **A dead relay is survivable without help.** net_report probes every relay
  in the map every 20–26 s. A relay that stops answering its `/ping` probe
  drops out of the latency table, the report prefers another relay, the
  endpoint homes there, and clients dialing with the full relay list as hints
  reach it. This is Phase B of the crate's failover suite and needs nothing
  from us.
- **A re-home tears nothing down.** After the home moves from relay A to
  relay B, the actor for A stays up as a non-home relay while traffic flows
  through it (it is dropped only after 60 s idle), and a relay forwards to
  any connected endpoint, home or not. Connections through a still-working A
  are untouched. A QUIC path over a relay is identified by the relay URL and
  the remote id, not by the WebSocket, so even a relay reconnect keeps the
  path.
- **What it cannot recover from** is a home relay that keeps answering the
  probe while the relay connection cannot be (re-)established. Every report
  keeps preferring that relay (it has the best latency, and a preferred relay
  that is still probe-reachable is sticky), the relay actor keeps failing to
  connect to it, and the server is registered nowhere. That is the shape of
  the incident observed on iroh 1.0.3 (relays behind Cloudflare Tunnels that
  reset idle WebSockets roughly hourly): no registration on any relay until
  the process was restarted, while LAN clients that find it over mDNS kept
  working and masked the outage. 1.1.0 changed nothing here; the reconnect
  machinery in `iroh/src/socket/transports/relay/actor.rs` is the same.
- **Nor can a process that starts during that outage come online.** The
  same preference applies to a fresh endpoint: net_report picks the wedged
  relay as home relay, the relay actor never connects, and
  `Endpoint::online()` (which since 0.98.0 waits for a *connected* home relay)
  never resolves. Address lookup does not enter into it: `online()` watches
  the home-relay status only, checked in the sources and confirmed
  empirically with n0 DNS lookup and pkarr publishing switched on. So with
  the relay left in the map, every client that restarts during the outage
  fails to start even though the other relay works and the server has
  already failed over to it. This is the failure the crate's startup
  exclusion (below) exists for.
- **An established connection does not follow a server to a new relay.**
  This is true with or without an address lookup service. The in-connection
  candidate exchange carries only direct IP addresses; address lookup runs
  only at dial time, and only until a path is selected; and a client re-adds
  hinted relay paths after the handshake only when its first path was direct.
  Mid-connection relay migration is upstream's open [#4435] and is not
  released. So a connection whose only path ran through a relay that dies
  times out (30 s relay-path idle, then the QUIC idle timeout) and the client
  redials. A connection that already holepunched a direct path is unaffected:
  Phase D of the suite below watches one whose paths are `relay1 + direct`
  through a relay1 wedge and a server re-home; it keeps echoing over the
  direct path throughout and ends up direct-only (the wedged relay path is
  dropped, and the new home relay is never added). The re-home shows on the
  paths of a *new* connection, which is how the suite confirms it.
- **Relay hints carry failover for new dials.** A dial whose address names
  both relays inserts both as known paths, and until a path is selected every
  datagram, the QUIC Initial included, goes to all of them. Whichever relay
  the server is homed on delivers it. No publish path is involved, which is
  why the address lookup service is not part of this design.

## The failover

`fail_over_home_relay` watches `Endpoint::home_relay_status()`.

1. **60 s without a connected home relay** (`RELAY_OUTAGE_FAILOVER`): long
   enough to ride out a routine relay reconnect (iroh's own backoff caps at
   16 s) plus the net-report cycle that re-homes on its own when the relay is
   really down. If iroh has not recovered by then, the wedged relay is taken
   **out of the endpoint's relay map** with `Endpoint::remove_relay`. The
   relay map is one shared handle, so the removal is seen by net_report and
   the relay actor alike; a relay-map change is a "major" update and forces
   a full report; the report can only prefer a relay still in the map; the
   endpoint homes there and logs `Home relay connection restored on <url>`.
   The endpoint, its identity, its direct paths and its established
   connections are untouched.
2. **The removed relay is put back only once it is connectable.** Every 90 s
   (`RELAY_RESTORE_INTERVAL`) it is probed with the same relay-only probe
   used at startup, and re-inserted with `Endpoint::insert_relay` when the
   probe succeeds. Restoring it unprobed would let a relay that answers HTTP
   but refuses relay connections be re-selected and fail again every few
   minutes. The interval is longer than iroh's 60 s idle cleanup of a
   demoted relay actor, so a relay that comes back is dialed by a fresh actor
   rather than the one that was stuck on it. Once it is back the next report
   is free to move home again (with net_report's latency hysteresis).
3. **No home relay selected at all** (a report that found none): there is
   nothing to remove, so the first configured relay is re-inserted unchanged,
   which forces a fresh report the same way. Nothing is removed and nothing
   needs restoring.
4. **Relays left out at startup are treated as removed.** `create_endpoint`
   hands back the configured relays it bound without
   (`CreatedEndpoint::relays_left_out`); `fail_over_home_relay` takes that
   list and restore-probes each one on the same 90 s cycle as a relay it
   removed itself. Restoring a relay that is *not* in the configuration is
   refused, so a caller cannot smuggle an extra relay in this way.

If the endpoint is still without a home relay after a cycle, the next failover
comes a full 60 s window later, not immediately. A reconnect at any point
resets the clock. Only the *home* relay matters: non-home relays are connected
on demand and dropped after a minute idle, which is normal and never counts as
an outage.

## Consequences for configuration

- **At least two custom relays.** `RelayConfig::from_urls_with_token`
  rejects fewer than two distinct custom relay URLs
  (`relay::MIN_CUSTOM_RELAYS`): with one relay there is nothing to fail over
  to, and that is a configuration error caught at startup rather than an
  outage discovered later. The default relay map is n0's and is not subject
  to this.
- **The startup probe fails only when no relay is reachable**, and the
  relays that fail it are left out of the relay map (next section). Every
  custom relay is still probed individually, and each unreachable one is a
  loud warning, but with failover being the point of the second relay a
  client that restarts during a relay outage must still start on the
  surviving one. Requiring every relay at startup would turn a survivable
  relay outage into an outage of every client that restarts during it.
- **Both sides list the full relay set**, as before: the server may be homed
  on any of them.

## Starting during an outage

A relay that fails the startup probe is not merely warned about; it is **left
out of the relay map the endpoint is bound with**. Leaving it in would put the
process into the stall described above whenever the relay answers probes but
refuses relay connections: iroh would prefer it by latency, never connect, and
`online()` would never resolve, so `create_endpoint` would time out after
10 s. With it out of the map the endpoint homes on a relay that works, and
the server's clients, which dial with every configured relay as a hint, reach
it through whichever relay it is homed on.

The exclusion is temporary where the failover runs. `create_endpoint` returns
`CreatedEndpoint { endpoint, relays_left_out }`, and the server passes
`relays_left_out` to `fail_over_home_relay`, which restore-probes them every
90 s and re-inserts each once it is connectable. A process that does not run
the failover (a client) keeps them out for its lifetime, which is the right
call for something that lives one connection; a long-lived client that must
follow a relay back would have to run the failover too.

Which relays were left out is logged at bind time
(`Binding without 1 of 2 custom relays: <url>`), and restoration logs as it
does for a relay the failover removed.

## Verification

The crate's own suite, `e2e/run_relay_failover.sh` in [flexaccess-iroh]
(it took over from tunnel-rs in 2026-09; see the crate's `e2e/README.md`),
runs fully offline against two local `iroh-relay --dev` instances, driving a
minimal harness (`examples/e2e`) that uses every module of the crate and
nothing of any product. Phases A–C run relay-only; Phase D allows direct
paths, with the harness built **without** the `mdns` feature so the handshake
still has to go through a relay and the direct path is learned through it, as
off-LAN:

| Phase | Scenario |
|---|---|
| A | Startup: both relays down fails; one relay down starts with a warning and the client connects through the other; a single custom relay is rejected as configuration |
| B | A relay dies at runtime: the server re-homes on its own within a net-report cycle, a restarted client with both relays connects; both down fails; both back reconnects |
| C | The home relay is replaced by a fake that answers `/ping` but refuses relay connections, with the other relay behind a latency-adding proxy so net_report keeps preferring the fake: nothing re-homes on its own, the failover removes the fake from the relay map after 60 s, the server homes on the other relay in place (same process, same endpoint) and a client connects; when the real relay returns, the restore probe puts it back and the server moves back onto it |
| D | The same wedge with direct paths allowed and a client holding a live connection, logging every path of it with its RTT and selected flag (the view flextunnel's connection-path status shows). Its paths are `relay1 + direct`; through the wedge it keeps echoing over the direct path and ends up direct-only; the failover still moves the server onto relay2 in the background; a new relay-only client's connection path shows relay2 as the home relay. Then a client with the same two-relay configuration redials during the outage, as a LAN client that restarts would: its probe finds relay1 not connectable, it binds without relay1, comes online on relay2, reaches the server, and goes direct again |

Phases C and D exercise this document (the last step of D, the redial, is the
startup exclusion; it fails without it); Phases A and B are iroh's own behavior
and the configuration rules. The suite takes about eight minutes and runs in
the crate's CI on every push.

## Where this lives

| Repo | Failover | Serve loop |
|---|---|---|
| [flexaccess-iroh] | `src/relay_failover.rs`; `MIN_CUSTOM_RELAYS` and the tolerant probe in `src/relay.rs`; the startup exclusion and `CreatedEndpoint` in `src/endpoint.rs`; the e2e suite above in `e2e/` | — |
| [tunnel-rs] | crate, on v0.0.7: in-place failover, not yet the startup exclusion (needs the v0.0.8 bump, which changes `create_endpoint`'s return type and adds `relays_left_out` to `fail_over_home_relay`) | `run_multi_source_server` in `src/iroh_mode/multi_source.rs`, selected alongside the accept loop. **First consumer** |
| [ezvpn] | still on v0.0.3, i.e. the watchdog; both the failover and the startup exclusion arrive with the bump | `VpnServer::run` in `src/tunnel/server.rs` |
| [flextunnel] | still on v0.0.3, i.e. the watchdog; both arrive with the bump | `crates/flextunnel-cli/src/main.rs` |

## History

Until flexaccess-iroh v0.0.7 this was a **watchdog** with two steps: a "nudge"
at 60 s that called `Endpoint::network_change()`, and a **rebuild** at 180 s
that closed the endpoint and bound a fresh one with the same identity, dropping
every connection. Both are gone:

- The nudge never did anything on a stable host. `network_change()` only asks
  iroh's network monitor to re-read the interfaces, and it reports "no
  changes detected" when nothing changed; no net report was forced and the
  relay actor never heard of it.
- The rebuild was the only step that ever recovered anything, at the cost of
  every connection and a deadline that doubled each time it did not help.
  Removing the wedged relay from the map gets the recovery without the cost,
  because a re-home in iroh 1.1.0 tears nothing down.

Until v0.0.8 the startup probe only *warned* about a relay it could not
connect and bound the endpoint with it still in the map, so a process that
started during the wedge above never came online (the stall the watchdog was
written against, seen from a process that starts mid-outage rather than one
that is already up). v0.0.8 leaves such a relay out of the map and has the
failover restore it. Enabling iroh's DNS discovery was checked as an
alternative first and does not help, because `online()` does not consult
address lookup at all.

Two branches from that period are superseded by this design:
`native-relay-recovery` (watchdog removed with nothing in its place) and
`mandatory-lookup` (a self-hosted address lookup service required with custom
relays, on the premise that failover needed a publish path; it does not, see
above).

[#4435]: https://github.com/n0-computer/iroh/pull/4435
[flexaccess-iroh]: https://github.com/flexaccessdev/flexaccess-iroh
[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
