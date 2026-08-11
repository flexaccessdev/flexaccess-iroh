# Relays and Address Lookup (Default vs Custom)

How a dialer finds a peer depends on the relay mode. This is the single most
important shared decision across [tunnel-rs], [ezvpn], and [flextunnel], and all
three implement it identically.

The default-vs-custom distinction is resolved **once**, at config time, into a
`RelayConfig` enum — `Default` vs `Custom` — and it selects **both** which relay
map iroh uses **and** whether iroh internet discovery (n0 pkarr publish + DNS
lookup) is enabled. Discovery is *not* independently configurable; it strictly
follows the relay mode: on for the default relays, off for custom relays.

| | Relay map | n0 pkarr publish | n0 DNS lookup | How the dialer finds the peer |
|---|---|---|---|---|
| **Default** | n0 public relays | with persistent identity only | yes | resolve the published record by endpoint ID |
| **Custom** | configured relays | never | never | relay hints attached to the peer's `EndpointAddr` |

mDNS is deliberately left out of that table: unlike the n0 lookup stack it does
**not** follow the relay mode, and it is the one piece of address lookup the
three programs do not implement alike. See [mDNS](#mdns) below.

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
> re-probes every 20–26 s).

A deployment that runs custom relays contacts **no public iroh infrastructure at
all**. See [relay-discovery-findings.md](relay-discovery-findings.md) for the
full analysis of why discovery is safe to disable here — iroh internals, the
failure-mode caveats, and the e2e verification.

## mDNS

mDNS local-network discovery is independent of the relay mode: where it is
enabled at all, it stays on in **both** default and custom mode. Unlike the rest
of the lookup stack, though, it is not uniform across the three programs:

| Repo | mDNS |
|---|---|
| [tunnel-rs] | on in both relay modes; **disabled under `--relay-only`**, which drops every address lookup |
| [ezvpn] | **never enabled** — the endpoint builder installs no mDNS lookup at all |
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

## Custom relay validation: the per-relay startup probe

Before binding the real endpoint, each configured relay is probed
**individually** by binding a throwaway, relay-only endpoint
(`clear_ip_transports`, ephemeral identity) for just that one URL and waiting on
`endpoint.online()`, bounded by a 10 s `RELAY_CONNECT_TIMEOUT`. All probes run in
parallel. **Startup fails if any relay does not come online.**

This is stricter than — and replaces — a single endpoint-wide `online()` wait,
which only proved that *one* relay (the eventual home relay) connected and so
gave a misleading all-clear when a backup relay was down. Because the auth token
rides the relay WebSocket upgrade, this probe also validates the token: a relay
that rejects it never comes online and startup fails.

The strictness is deliberate. A configured backup relay that is silently dead is
worse than a startup failure: it gives false confidence in a failover path that
does not exist. **Startup is strict; runtime is not** — once a process is
running, losing a relay is survivable and the endpoint re-homes onto a surviving
one.

`clear_ip_transports()` on the probe endpoint is what makes `online()` a *pure
relay* reachability signal: a holepunched direct path can never mask a dead or
auth-rejecting relay.

## Relay-only mode

Relay-only drops the direct IP transports and every address lookup (including
mDNS) on the *real* endpoint, so it is reachable only over the configured
relays. It requires a custom relay set — the rate-limited default relays cannot
serve it.

**[tunnel-rs] is the reference program for relay-only setup.** It is the only one
of the three that exposes relay-only as a first-class user-facing mode
(`--relay-only` on both `server` and `client`, CLI-only so it cannot be switched
on accidentally from a config file), and it carries the matching sequential
per-relay failover dial path and a fully offline two-relay e2e suite
(`test-scripts/run_relay_failover_e2e.sh`). Use it to validate a self-hosted
relay end to end before pointing other programs at it — see
[self-hosting.md](self-hosting.md). ezvpn and flextunnel keep
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

| Repo | Implementation | Notes |
|---|---|---|
| [tunnel-rs] | `src/iroh_mode/endpoint.rs` | Adds user-facing `--relay-only` + sequential relay failover dial; mDNS gated off under relay-only |
| [ezvpn] | `src/transport/endpoint.rs`, `src/transport/paths.rs` | No mDNS at all; also exposes an on-demand `/healthz` per-relay health check for status UIs |
| [flextunnel] | `crates/flextunnel-core/src/transport/endpoint.rs`, `.../transport/paths.rs` | mDNS on except iOS; outbound bridges attach the same relay hints; on-demand `/healthz` health check |

The `/healthz` status check in ezvpn/flextunnel is a *different* thing from the
startup probe: it runs only when a status snapshot is requested, hits the relay's
**unauthenticated** HTTP health endpoint, and so confirms the relay is *up*, not
that the token is accepted. Token validation is the startup probe's job.

[tunnel-rs]: https://github.com/andrewtheguy/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
