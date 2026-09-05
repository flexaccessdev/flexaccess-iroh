# iroh Common Architecture

Shared design notes and operational guides for the iroh-based programs in this
org. These three ship different products but share one transport foundation —
iroh endpoints, relays, address lookup, and NAT traversal — so that layer is
documented once, here, instead of drifting across three repos.

| Repo | What it is |
|---|---|
| [tunnel-rs] | TCP/UDP port forwarding over iroh. **Reference program for relay-only setups** |
| [ezvpn] | Full VPN (TUN device, IP routing) over iroh |
| [flextunnel] | SOCKS5/HTTP proxy and port forwarding over iroh |

## The shared crate

Since 2026-09 this design is also **code**, once:
[`flexaccess-iroh`](https://github.com/flexaccessdev/flexaccess-iroh), a Rust
crate all three programs depend on by git tag. It carries `RelayConfig` (at
least two custom relays) and the per-relay startup probe, the common endpoint
builder (and relay-only mode), the server-side in-place home-relay failover,
and the endpoint-bound public-key auth transcript over
[`flexaccess-keys`](https://github.com/flexaccessdev/flexaccess-keys). A fix to
any of that lands in the crate and reaches every program on its next tag bump,
instead of being ported by hand three times.

What stays in each program is what makes it that program: ALPNs, handshake
formats, QUIC transport tuning, identity and key *files* (the crate takes
values, never paths), connection-path status UIs, and the serve loops that
run the failover alongside their accept loops. ezvpn, which builds on a fork of iroh, redirects the
crate's `iroh` to that fork with `[patch.crates-io]` so the graph holds one
`iroh`.

## Contents

- **[relays-and-address-lookup.md](relays-and-address-lookup.md)** — the core
  shared design. Default vs custom relays, how that single choice also decides
  whether n0 internet discovery is on, relay hints, the shared relay auth token,
  the strict per-relay startup probe, and relay-only mode. **Start here.**
- **[relay-failover.md](relay-failover.md)** — how a custom-relay server
  stays reachable when its home relay stops working: what iroh 1.1.0 recovers
  on its own, the in-place failover for the case it does not (take the wedged
  relay out of the relay map, restore it once connectable), why that needs at
  least two custom relays and no address lookup service, and the tunnel-rs
  e2e suite that proves it.
- **[nat-traversal-and-transport.md](nat-traversal-and-transport.md)** — what the
  three programs get from `iroh::Endpoint` and never implement themselves:
  connection establishment, hole punching and relay fallback, NAT traversal by
  NAT type (including symmetric NAT, and why Kubernetes networking depends on the
  CNI rather than on Kubernetes itself), the QUIC/TLS 1.3 encryption stack, and
  performance characteristics.
- **[self-hosting.md](self-hosting.md)** — running your own iroh relay: local
  dev, production with TLS, the single-port Cloudflare Tunnel setup, relay access
  tokens, and how to verify a relay end to end.
- **[relay-discovery-findings.md](relay-discovery-findings.md)** — the analysis
  (against iroh 1.0.2 internals) behind making internet discovery
  non-configurable and tying it to the relay mode.
- **[iroh-relay-connection-trace.md](iroh-relay-connection-trace.md)** — what
  actually happens on `endpoint.online()`, the relay WebSocket upgrade, and how
  to troubleshoot a relay by hand with `curl`.

## Relay-only and tunnel-rs

[tunnel-rs] is the reference implementation for relay-only deployments: it is the
only one of the three exposing relay-only as a first-class user-facing mode
(`--relay-only`), it carries the sequential per-relay failover dial path, it is
the first consumer of the shared relay failover, and it ships the fully offline
two-relay e2e suite that exercises it. When bringing up a self-hosted relay,
validate it with tunnel-rs first — the relay it proves out serves all three
programs. See [self-hosting.md](self-hosting.md#verifying-a-relay).

## Scope

In scope: anything about the iroh transport layer that is (or should be) the same
in all three — **relay configuration and validation**, address lookup and
discovery, NAT traversal behavior, relay operations.

Out of scope: each program's own architecture, protocol, authentication, and
**product-specific configuration** (tunnel sources and targets, VPN addressing,
proxy listeners, and every other setting that is not the iroh transport). Those
stay in their own repos. The app-independent Ed25519 key format and tooling used
by those product-specific authentication protocols lives separately in
[`flexaccess-keys`](https://github.com/flexaccessdev/flexaccess-keys).

## Keeping this in sync

The three repos link here rather than duplicating this material, and they
depend on [`flexaccess-iroh`](https://github.com/flexaccessdev/flexaccess-iroh)
rather than carrying their own copies of the code. When the shared
relay/discovery behavior changes, change it in the crate, tag a release, bump
the tag in each program, and update this repo in the same change. Note any
deliberate per-repo divergence in the "Where this lives in each repo" table in
[relays-and-address-lookup.md](relays-and-address-lookup.md#where-this-lives-in-each-repo).

[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
