# Relays and Address Lookup (Default vs Custom)

How a dialer finds a peer depends on the relay mode. This is the single most
important shared decision across [tunnel-rs], [ezvpn], and [flextunnel], and
one implementation serves all three: the `relay` and `endpoint` modules of
[`flexaccess-iroh`](../README.md).

The default-vs-custom distinction is resolved **once**, at config time, into a
`RelayConfig` enum — `Default` vs `Custom` — and it selects **both** which relay
map iroh uses **and** whether iroh internet discovery (n0 pkarr publish + DNS
lookup) is enabled. Discovery is *not* independently configurable; it strictly
follows the relay mode: on for the default relays, off for custom relays.

| | Relay map | n0 pkarr publish | n0 DNS lookup | How the dialer finds the peer |
|---|---|---|---|---|
| **Default** | n0 public relays | with persistent identity only | yes | resolve the published record by endpoint ID |
| **Custom** | configured relays | never | never | relay hints attached to the peer's `EndpointAddr` |

Whether an endpoint publishes at all is the program's call
(`EndpointOptions::publish_address`): a server with a persistent identity does,
a client that only dials out never advertises its ephemeral id.

mDNS is deliberately left out of that table: unlike the n0 lookup stack it does
**not** follow the relay mode, and it is the one piece of address lookup the
three programs do not enable alike. See [mDNS](#mdns) below.

## Background: iroh address lookup

Dialing an iroh endpoint by `EndpointId` alone works because of [address
lookup](https://docs.iroh.computer/concepts/address-lookup): each endpoint signs
a pkarr record containing its **home relay** URL (and optionally direct
addresses) and publishes it to n0's `iroh-dns-server`; a dialer resolves
`_iroh.<z32-endpoint-id>.dns.iroh.link TXT` to learn `relay=<url>` / `addr=<addr>`
and knows where to reach the peer. Two facts matter:

1. An endpoint has **one home relay** at a time — it holds a persistent
   connection to exactly one relay, so that relay is its only *relay* route for
   inbound connections. It is not necessarily the only route: when direct
   connectivity is available, a dialer can also reach the endpoint through the
   direct addresses in its published record.
2. Relay servers are **stateless and independent** — they do not sync who is
   connected where and do not forward to each other. Traffic sent to a relay the
   peer is not connected to goes nowhere.

## Default relays

The full lookup stack is enabled (`DnsAddressLookup`, plus `PkarrPublisher` when
the endpoint has a persistent identity): the server publishes its current home
relay, the client resolves it by endpoint ID, and iroh's relay failover works —
if the server's home relay dies, it re-homes to another relay from the default
map and republishes; dialers find the new record. The client has no relay hints
to add, so findability relies entirely on n0's public lookup (`dns.iroh.link`).

Pkarr publishing is gated on having a secret key so that an ephemeral endpoint
(a client with no persistent identity) resolves peers but never advertises
itself.

## Custom relays

Internet discovery is **disabled** — nothing is published to or resolved from
n0's `dns.iroh.link`. Instead the dialer attaches every configured relay URL to
the peer's `EndpointAddr` as transport-address hints. iroh sends QUIC Initials to
every configured relay, so the handshake succeeds via whichever relay the peer is
currently homed on, and hole punching is still attempted for a direct P2P path.

Here the hints are **required** for connectivity, not just an optimization: with
discovery off there is no published record to fall back on.

> [!WARNING]
> Configure **both sides with the full relay list.** Relay failover only works as
> long as the dialer lists the relay the peer re-homes onto, so a client
> configured with a subset of the server's relays can reach it only while the
> server's home relay is in that subset. After its home relay goes offline, an
> endpoint re-homes onto another configured relay within ~30 seconds (net_report
> re-probes every 20–26 s); when the relay is lost in a way iroh does not
> recover from, the shared failover moves it after 60 s. See
> [relay-failover.md](relay-failover.md).

A custom relay set should hold **at least two distinct relays**: failover is
the reason the relay list exists. A single relay is accepted as
**reduced-redundancy mode** (`RelayConfig::is_single_relay`), for deployments
that run only one: it works, and `RelayConfig::log_status` warns at startup,
but there is nothing to fail over to. While that relay is down, new off-LAN
dials and connections that run only through it fail; the endpoint keeps
running, connections on a direct path continue, and a process that starts
during the outage fails to start.

A deployment that runs custom relays contacts **no public iroh infrastructure at
all**. See [relay-discovery-findings.md](relay-discovery-findings.md) for the
full analysis of why discovery is safe to disable here — iroh internals, the
failure-mode caveats, and the e2e verification.

## mDNS

mDNS local-network discovery is independent of the relay mode: where it is
enabled at all, it stays on in **both** default and custom mode. It is the
crate's `mdns` feature (which the crate itself compiles out on iOS), and unlike
the rest of the lookup stack it is not uniform across the three programs:

| Repo | mDNS |
|---|---|
| [tunnel-rs] | on in both relay modes; **disabled under `--relay-only`**, which drops every address lookup |
| [ezvpn] | **never enabled** — the `mdns` feature is off |
| [flextunnel] | on in both relay modes; **compiled out on iOS**, where raw multicast needs the `com.apple.developer.networking.multicast` entitlement |

So the only place mDNS is switched off *by mode* is tunnel-rs's relay-only mode
(see below); everywhere else it is a fixed per-program property.

## Optional shared relay token

A private relay deployment can require a shared bearer token (iroh-relay's
`IROH_RELAY_ACCESS_TOKEN` / `access.shared_token`). When `relay_auth_token` is
configured it is carried on the `RelayConfig::Custom` variant and applied to
every entry in the custom relay map (`RelayMap::with_auth_token`), which iroh
sends as an `Authorization: Bearer <token>` header on each relay WebSocket
upgrade.

It is **strictly gated to custom relays**: `RelayConfig::from_urls_with_token`
rejects a token supplied without relay URLs, so the default n0 relays never
receive one and the feature is inert in default mode. Blank/whitespace-only
tokens normalize to "no token" rather than erroring. Server and clients sharing a
private relay must configure the same token.

## QUIC address discovery on custom relays

QUIC address discovery (QAD) is a QUIC endpoint a relay can run on UDP 7842
that tells an iroh endpoint its public address, one of the signals hole
punching uses. iroh assumes every relay given by URL serves it, and at the
start of each full network report probes it on up to five relays in the map,
over IPv4 and, where the endpoint has it, IPv6. It stops early once it has
enough replies (three, or as many as there are relays when the map holds
fewer, counting a relay's IPv4 and IPv6 replies separately) and at least one
probe has finished in each address family it tried.

Probing a relay that does not serve it is not free. iroh does not pick a home
relay until its QAD probes finish, and a probe to a relay with nothing on UDP
7842 waits out the probe timeout: **3 s on iroh 1.5** (`PROBES_TIMEOUT`,
net_report). When too few replies come back to stop early (none of the relays
serves QAD, say, or one of two does not and the other replies over IPv4
alone), or when no IPv6 probe finishes although enough IPv4 replies are in,
the report waits up to that 3 s. An endpoint is not online until it has a home relay, so such a delay
lands on its start, and can again on later full reports (network changes,
every 5 minutes). Measured on 2026-11-25 against two relays behind a
Cloudflare Tunnel: the first report took 3.0 s with QAD probed and 0.3 s
without.

A relay serves QAD only when it terminates TLS itself, runs
`enable_quic_addr_discovery = true`, and has UDP 7842 reachable. A relay behind
a Cloudflare Tunnel (see [self-hosting.md](self-hosting.md)) or any other
HTTP-only front never does.

A relay cannot be asked whether it serves QAD: the iroh relay advertises it
nowhere (its `/healthz` reports only status and version), and a relay with
nothing on UDP 7842 is told apart from a slow one only by waiting out a
timeout, which is the delay to avoid. Nor does the answer belong to the relay
alone: a network that drops UDP turns a relay that serves QAD into one that
does not, for that endpoint.

So the application **says it, for all custom relays at once**:
`RelayConfig::with_quic_addr_discovery(bool)`, on by default. The application
knows how its relays are deployed, and a deployment's relays are normally all
alike: all behind Cloudflare Tunnels, or all terminating TLS themselves.

- **On** (the default): every relay is in the relay map exactly as iroh has it
  (`iroh::RelayConfig::from(url)`, QAD on UDP 7842 at the URL's host), and iroh
  does the rest. A relay whose QAD is down for a while can hold a full report
  back by up to iroh's 3 s timeout, as it does in iroh; the crate only widens
  its startup window to cover it (see the
  [startup probe](#custom-relay-validation-the-per-relay-startup-probe)).
- **Off**: no relay is probed for QAD (`quic: None` on every entry), so no
  report waits for it, and no relay reports the endpoint's public address.
  For relays behind a Cloudflare Tunnel or any other HTTP-only front.

The setting goes everywhere the crate puts a relay into a map: the endpoint's
relay map (`RelayConfig::relay_mode`), and the failover's re-insertions and
restores. An application that replaces its endpoint mid-session builds the
replacement from the same `RelayConfig`, and so gets the same setting. It is an error with the default relays, whichever value is given:
n0's relays serve QAD, and iroh uses it there as it always does.

Measured on 2026-11-26 with `e2e/run_quic_addr_discovery.sh --n0`, time from
bind to online:

| Relays | QAD on | QAD off |
|---|---|---|
| two local relays, neither serving QAD | 3009 ms | 210 ms |
| n0's `use1-1` and `euc1-1`, both serving QAD | 1160 ms | 1132 ms |

In these two setups, leaving QAD on costs nothing on relays that all serve it,
and the full timeout on relays where none does. Other mixes fall between, as
above.

A relay-only endpoint (`EndpointOptions::relay_only`) has no IP transports,
so iroh never probes QAD on it whatever the setting.

## Custom relay validation: the per-relay startup probe

`flexaccess_iroh::endpoint::create_endpoint` binds the real endpoint with
every configured relay at once and probes each relay **individually** beside
it (`relay::RelayProbes`): a throwaway, relay-only endpoint
(`clear_ip_transports`, ephemeral identity) for just that one URL, waiting on
`endpoint.online()`, bounded by a 10 s `RELAY_CONNECT_TIMEOUT`. All probes run
in parallel, and each result is applied to the live endpoint as it lands.
**Each relay whose probe fails is reported as a warning and taken out of the
endpoint's relay map**, unless the endpoint is connected through it or it is
the last relay left. A probe is a connection of its own, so its result and the
endpoint's can differ: a probe can fail on a relay the endpoint is connected
through, which stays, and the endpoint can fail to come online on relays that
passed. **Startup fails when every probe fails and the endpoint is not
connected, or when the endpoint is still not online within its startup window
after the wait began or a probe last took a relay out of the map**, so a
startup timeout does not by itself mean that every relay failed its probe.
Only taking a relay out restarts the window. A probe still running when the
window is up is waited for, since it may yet take out the relay that keeps the
endpoint offline. The probe checks relay connectivity only; QUIC address
discovery is the application's setting (see
[above](#quic-address-discovery-on-custom-relays)).

The window is the probes' 10 s, plus iroh's 3 s QAD probe timeout
(`relay::QAD_PROBES_TIMEOUT`) for each net report that can come before the
endpoint homes on a relay that works, when the endpoint runs QAD: QAD on and
IP transports present. The probes never run QAD, but such an endpoint opens no
relay connection until its net report's QAD probes are done, so on 10 s alone
a relay that connects late in its probe's window would pass the probe and
still fail the start. From the start that is one report (13 s). After a relay
is taken out it is two (16 s): iroh runs one report at a time, so the map
change waits behind the report already running, which may still home the
endpoint on a relay just taken out, and any later change joins the one
queued. A relay-only endpoint, or one with QAD off, gets 10 s. An application
that binds an endpoint itself and waits on `online()` without the probe (a
mid-session rebuild, say) gets the one-report window from
`relay::online_timeout`. The default relays serve QAD too, so an endpoint on
them with IP transports also gets 13 s, at startup as well.

**Known limitation (iroh 1.5).** iroh's queue holds one pending report and
keeps only the latest reason for it, so a port-mapping update (or the
periodic refresh) that lands while a report is running replaces a queued
relay-map change. The report that then runs is incremental, not full, and
neither of its outcomes is checked against the relay map. With QAD on, it
keeps the QAD connections it already has (on an IPv4-only host it may probe
nothing else), so a relay the probe just took out stays preferred while it
still answers QAD. With QAD off, it plans no probes at all once an earlier
report has latencies, and an empty report keeps the current home relay.
Either way the endpoint can stay homed on the relay just taken out, and the
start times out although a remaining relay passed its probe. It re-homes
later: with QAD off at the next periodic report (every 20–26 s), which probes
the map again after an empty one, and with QAD on at the next full report,
about 5 minutes later. A longer window does not help, and QAD off
does not avoid it. The fix belongs in iroh's report queue, which should not
let a later reason replace a queued full refresh; as of 2026-11-26 that is
unreported upstream, and iroh's `main` still queues this way.

iroh commit [`4c12b0f`](https://github.com/n0-computer/iroh/commit/4c12b0f7bc8560117beb4940d3fbea94a0f88680)
("give up the home relay when it leaves the relay map", on `main` after
v1.5.0 and not yet released) narrows this without closing it: a report no
longer prefers a relay outside the map, and an empty one no longer falls back
to a home relay that has left it. With it, the endpoint no longer homes on
the relay just taken out, but an overwritten refresh still leaves it without
a home relay, and offline, until the same later report.

`create_endpoint` returns as soon as the endpoint is online, so on healthy
relays the probe costs the start nothing: it used to run ahead of the bind and
added a relay connection's worth of time (about 1.5 s through Cloudflare
Tunnels) to every start. The probe's task carries on in the background, is
kept in the caller's `PendingCloses` like a slow close, and settles within
the probe timeout plus the probe endpoints' bounded close
(`RelayProbes::settled`). The task holds a handle to the endpoint while it
runs, which keeps its UDP sockets bound; it lets go when the endpoint's close
begins. That close also stops the probes still running, whose endpoints are closed on tasks
kept in `PendingCloses`: a process that shuts down right after its start,
while a relay that does not answer is still being probed, drains those closes
and does not wait out the probe timeout. A probe that fails on a relay the endpoint is connected through leaves that
relay in the map, and never fails a start that is already connected.

Probing each relay on its own is what makes those warnings possible: a single
endpoint-wide `online()` wait only proves that *one* relay (the eventual home
relay) connected and says nothing about the others, so a backup relay that is
silently dead would give false confidence in a failover path that does not
exist. Because the auth token rides the relay WebSocket upgrade, the probe also
validates the token: a relay that rejects it never comes online.

Startup does not require every relay, deliberately. Failover is the reason for
the second relay, and a client that restarts during a relay outage has to be
able to start on the surviving one; requiring every relay at startup would turn
a survivable relay outage into an outage of every client that restarts during
it. Nor may a relay that failed the probe stay in the map: iroh picks its home
relay by probe latency, so a relay that answers probes but refuses relay
connections would be preferred, never connect, and keep `online()` from ever
resolving. The probe therefore takes it out of the live map (never the last
relay left), which forces a fresh net report that re-homes the endpoint, and
the wait for the endpoint restarts its window from that change, so the endpoint
gets a full window on the relays that work. The relays taken out are handed
on (`CreatedEndpoint::relays`, `RelayProbes::settled`) for the failover to
restore once they are connectable, using this same probe; a process that does
not run the failover keeps them out for its lifetime. See
[relay-failover.md](relay-failover.md#starting-during-an-outage).

`clear_ip_transports()` on the probe endpoint is what makes `online()` a *pure
relay* reachability signal: a holepunched direct path can never mask a dead or
auth-rejecting relay.

## Relay-only mode

Relay-only (`EndpointOptions::relay_only`) drops the direct IP transports and
every address lookup (including mDNS) on the *real* endpoint, so it is
reachable only over the configured relays. It requires a custom relay set — the
rate-limited default relays cannot serve it. Because a relay-only dialer tries
the relays one at a time, `RelayConfig` keeps the configured order (deduping
only exact repeats): the first URL is the preferred relay.

**[tunnel-rs] is the reference program for relay-only setup.** It is the only one
of the three that exposes relay-only as a first-class user-facing mode
(`--relay-only` on both `server` and `client`, CLI-only so it cannot be switched
on accidentally from a config file), and it carries the matching sequential
per-relay failover dial path. The fully offline two-relay e2e suites for the
relay layer itself live with the crate (`e2e/` in [flexaccess-iroh], see
[relay-failover.md](relay-failover.md#verification)). Use tunnel-rs to
validate a self-hosted relay end to end before pointing other programs at it —
see [self-hosting.md](self-hosting.md). ezvpn and flextunnel keep
`clear_ip_transports()` only inside the startup probe described above.

## Connect path

With custom relays, all three attach every configured relay URL to the peer's
`EndpointAddr` and dial **once**, letting iroh fan the QUIC Initials out across
the hints. Relay-only is the exception: with no direct path to fall back on,
tunnel-rs dials the relays **one at a time** so a dead relay fails fast and the
next is tried.

Every dial is wrapped in a timeout — an untimed `endpoint.connect` can hang
indefinitely when no path is reachable.

## Where this lives in each repo

The shared part is one crate; each program keeps a thin layer over its
builder.

| Repo | Implementation | Notes |
|---|---|---|
| [flexaccess-iroh] | `src/relay.rs`, `src/endpoint.rs`, `src/relay_failover.rs`, `src/relay_health.rs`, `e2e/` | `RelayConfig` (two or more custom relays, or one in reduced-redundancy mode), the per-relay probe, the base builder (`endpoint_builder` + `EndpointOptions`), `create_endpoint` (binds with every relay, runs the probe beside the endpoint and takes the relays that fail it out of the live relay map, returns the probe in `CreatedEndpoint`), the in-place home-relay failover (restores them), the e2e suites for all of it, and the on-demand `/healthz` relay health check (feature `relay-health`) |
| [tunnel-rs] | `src/iroh_mode/endpoint.rs` | `mf/4` ALPN, transport tuning, user-facing `--relay-only` + sequential relay failover dial; `mdns` on |
| [ezvpn] | `src/transport/endpoint.rs`, `src/transport/paths.rs` | VPN ALPN, transport tuning, bounded connect; `mdns` off; iroh fork via `[patch.crates-io]`; shows the crate's `/healthz` relay health check in its status UIs |
| [flextunnel] | `crates/flextunnel-core/src/transport/endpoint.rs`, `.../transport/paths.rs` | three ALPNs + native allowlist hook; the client's rebuildable endpoint (`ClientEndpoint`, its own since the crate dropped rebuilds); `mdns` on (crate compiles it out on iOS); outbound bridges attach the same relay hints; shows the crate's `/healthz` relay health check in its status UIs |

The `/healthz` status check (`relay_health`, used by ezvpn and flextunnel) is a
*different* thing from the startup probe: it runs only when a status snapshot is
requested, hits the relay's **unauthenticated** HTTP health endpoint, and so
confirms the relay is *up*, not that the token is accepted. Token validation is
the startup probe's job. It asks for `healthz` under the relay URL's path, the
way iroh joins `relay` to dial it, so a relay served under a path prefix
(`https://relay.example.com/prefix/`) is checked at `/prefix/healthz`.

[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
