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

## Contents

- **[relays-and-address-lookup.md](relays-and-address-lookup.md)** — the core
  shared design. Default vs custom relays, how that single choice also decides
  whether n0 internet discovery is on, relay hints, the shared relay auth token,
  the strict per-relay startup probe, and relay-only mode. **Start here.**
- **[nat-traversal-and-transport.md](nat-traversal-and-transport.md)** — what the
  three programs get from `iroh::Endpoint` and never implement themselves:
  connection establishment, hole punching and relay fallback, NAT traversal by
  NAT type (including why symmetric NAT and container overlays stay relayed), the
  QUIC/TLS 1.3 encryption stack, and performance characteristics.
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
(`--relay-only`), it carries the sequential per-relay failover dial path, and it
ships a fully offline two-relay e2e suite. When bringing up a self-hosted relay,
validate it with tunnel-rs first — the relay it proves out serves all three
programs. See [self-hosting.md](self-hosting.md#verifying-a-relay).

## Scope

In scope: anything about the iroh transport layer that is (or should be) the same
in all three — relay configuration and validation, address lookup and discovery,
NAT traversal behavior, relay operations.

Out of scope: each program's own architecture, protocol, authentication, and
configuration. Those stay in their own repos.

## Keeping this in sync

The three repos link here rather than duplicating this material. When the shared
relay/discovery behavior changes in one repo, update it here in the same change
and note any deliberate per-repo divergence in the "Where this lives in each
repo" table in
[relays-and-address-lookup.md](relays-and-address-lookup.md#where-this-lives-in-each-repo).

[tunnel-rs]: https://github.com/andrewtheguy/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
