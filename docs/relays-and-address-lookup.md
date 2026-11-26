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
punching uses. iroh assumes every relay given by URL serves it, and probes it
on every relay in the map at the start of each full network report.

Probing a relay that does not serve it is not free. iroh does not pick a home
relay until its QAD probes finish, and a probe to a relay with nothing on UDP
7842 waits out the probe timeout: **3 s on iroh 1.5** (`PROBES_TIMEOUT`,
net_report). An endpoint is not online until it has a home relay, so that 3 s
lands on every start of every program, and again on each later full report
(network changes, every 5 minutes). Measured on 2026-11-25 against two relays
behind a Cloudflare Tunnel: the first report took 3.0 s with QAD probed and
0.3 s without.

A relay serves QAD only when it terminates TLS itself, runs
`enable_quic_addr_discovery = true`, and has UDP 7842 reachable. A relay behind
a Cloudflare Tunnel (see [self-hosting.md](self-hosting.md)) or any other
HTTP-only front never does.

So the crate **detects it per relay** instead of assuming it, as part of the
startup probe (next section). The endpoint is bound with QAD off on every
custom relay, and the probe turns it on, on the live endpoint, for each relay
that answered (`ProbedRelays::quic_addr_discovery`). Next to each relay's probe endpoint, a second
throwaway endpoint with UDP transports and QAD on runs a net report with only
the QAD probes (`NetReportConfig::minimal`); its report shows UDP working
only if the relay answered. The answer is whatever that endpoint learned by
the time the relay probe came online, so the check adds no time of its own: a
relay that serves QAD answers in about one round trip (85–150 ms against n0's
relays, whose relay probes took 380–520 ms). A relay whose QAD answer is no
faster than its relay connection (a network that drops UDP, a broken IPv6
route) would hold the report back as well, so it counts as not serving QAD.

Reading the report needs iroh's `unstable-net-report` feature
(`Endpoint::net_report`), which the crate enables. The failover's restore
probe makes the same check, so a relay put back into the map gets QAD exactly
when it answered then; a relay re-inserted unchanged keeps what it had. The
default relays are not probed: n0's relays serve QAD, and iroh uses it there
as before.

The startup answer holds only for the network the process started on, so
the failover (servers) probes the relays in the map that were not found
serving QAD again every 10 minutes (`QUIC_ADDR_DISCOVERY_RECHECK_INTERVAL`),
with the same probe and the same rule as at startup, and turns QAD on for any
that serve it now. The recheck runs inside the failover loop, as a restore
probe does, so the relay map does not change under it. A process without the
failover (a client) keeps its startup result. Until a recheck finds it, a
miss costs only the address that relay's QAD would have reported; any other
relay that serves QAD still reports it.

A relay-only endpoint (`EndpointOptions::relay_only`) has no IP transports
and cannot use QAD, so neither the startup probe nor the failover checks for
it: those probes send no UDP at all.

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
connected, or when the endpoint is still not online 10 s after the wait began
or a probe last took a relay out of the map**, so a startup timeout does not
by itself mean that every relay failed its probe. Only taking a relay out
restarts the 10 s: turning QUIC address discovery on for a relay changes the
map too, but leaves the deadline where it was. A probe still running when the
10 s are up is waited for, since it may yet take out the relay that keeps the
endpoint offline. Each probe
also checks its relay for QUIC address discovery, within the time the probe
takes anyway (see [above](#quic-address-discovery-on-custom-relays)).

`create_endpoint` returns as soon as the endpoint is online, so on healthy
relays the probe costs the start nothing: it used to run ahead of the bind and
added a relay connection's worth of time (about 1.5 s through Cloudflare
Tunnels) to every start. The probe's task carries on in the background, is
kept in the caller's `PendingCloses` like a slow close, and settles within
the probe timeout plus the probe endpoints' bounded close
(`RelayProbes::settled`). The task holds a handle to the endpoint while it
runs, which keeps its UDP sockets bound; it lets go when the endpoint's close
begins, so a caller that rebinds the same port right after closing awaits
`RelayProbes::released` in between, which does not wait for the probes. A
probe that fails on a relay the endpoint is connected through leaves that
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
the wait for the endpoint restarts its 10 s from that change, so the endpoint
gets a full window on the relays that work. The relays taken out are handed
on (`CreatedEndpoint::relays`, `ProbedRelays::left_out`) for the failover to
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
