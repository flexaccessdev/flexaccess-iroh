# Relays and Address Lookup (Default vs Custom)

How a dialer finds a peer depends on the relay mode. This is the single most
important shared decision across [tunnel-rs], [ezvpn], and [flextunnel], and
one implementation serves all three: the `relay` and `endpoint` modules of
[`flexaccess-iroh`](https://github.com/flexaccessdev/flexaccess-iroh).

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

A custom relay set must hold **at least two distinct relays**
(`relay::MIN_CUSTOM_RELAYS`); `RelayConfig::from_urls_with_token` rejects one.
Failover is the reason the relay list exists, and one relay leaves nothing to
fail over to.

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

## Custom relay validation: the per-relay startup probe

Before binding the real endpoint (`flexaccess_iroh::endpoint::create_endpoint`),
each configured relay is probed **individually** (`relay::probe_custom_relays`)
by binding a throwaway, relay-only endpoint
(`clear_ip_transports`, ephemeral identity) for just that one URL and waiting on
`endpoint.online()`, bounded by a 10 s `RELAY_CONNECT_TIMEOUT`. All probes run in
parallel. **Startup fails only if no relay comes online; each relay that does
not is reported as a warning and left out of the relay map the endpoint is
bound with.**

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
resolving. `create_endpoint` therefore binds without those relays and hands
them back (`CreatedEndpoint::relays_left_out`) for the failover to restore
once they are connectable, using this same probe; a process that does not run
the failover keeps them out for its lifetime. See
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
| [flexaccess-iroh] | `src/relay.rs`, `src/endpoint.rs`, `src/relay_failover.rs`, `e2e/` | `RelayConfig` (at least two custom relays), the per-relay probe, the base builder (`endpoint_builder` + `EndpointOptions`), `create_endpoint` (binds without the relays that failed the probe, returns them in `CreatedEndpoint`), the in-place home-relay failover (restores them), and the e2e suites for all of it |
| [tunnel-rs] | `src/iroh_mode/endpoint.rs` | `mf/4` ALPN, transport tuning, user-facing `--relay-only` + sequential relay failover dial; `mdns` on |
| [ezvpn] | `src/transport/endpoint.rs`, `src/transport/paths.rs` | VPN ALPN, transport tuning, bounded connect; `mdns` off; iroh fork via `[patch.crates-io]`; on-demand `/healthz` per-relay health check for status UIs |
| [flextunnel] | `crates/flextunnel-core/src/transport/endpoint.rs`, `.../transport/paths.rs` | three ALPNs + native allowlist hook; `mdns` on (crate compiles it out on iOS); outbound bridges attach the same relay hints; on-demand `/healthz` health check |

The `/healthz` status check in ezvpn/flextunnel is a *different* thing from the
startup probe: it runs only when a status snapshot is requested, hits the relay's
**unauthenticated** HTTP health endpoint, and so confirms the relay is *up*, not
that the token is accepted. Token validation is the startup probe's job.

[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
