# flexaccess-iroh

Shared iroh transport layer for FlexAccess applications, as a Rust crate.

The programs built on iroh in this org — [tunnel-rs], [ezvpn], [flextunnel] —
share one transport foundation. Its design is documented once in
[`docs/`](docs/README.md); this crate is that design as code, so a fix to the
relay failover or the relay probe lands here once, together with its
documentation, instead of being ported by hand into every repo.

[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel

## What is in it

| Module | Contents |
|---|---|
| `relay` | `RelayConfig` (default vs custom relays, which also decides whether n0 internet discovery is on; duplicate custom relays are collapsed, and a single one runs in reduced-redundancy mode, with a startup warning and no failover), the shared relay auth token, the per-relay startup probe, run beside the endpoint (fails only when no relay is reachable, and reports which relays did not come online; also detects which relays serve QUIC address discovery, the only ones the endpoint probes for it, since a relay that does not serve it delays every endpoint start by 3 s) |
| `endpoint` | the common endpoint builder and `create_endpoint`, which binds with every relay and returns once the endpoint is online, while the startup probe runs beside it and takes each relay that fails it out of the live relay map (a relay that answers probes but cannot be connected would otherwise be preferred as home relay and keep the endpoint from ever coming online, so every client restarting during such an outage would fail to start) and hands them on for the failover to restore. An endpoint it gives up on, or a relay probe's, is closed with a bounded wait; a close that outlives the wait, and the probe's own task, keep running and are kept in the caller's `PendingCloses`, which a caller whose runtime ends with its request waits for |
| `relay_failover` | the server-side home-relay failover: after 60 s without a connected home relay, take the wedged relay out of the relay map so the forced net report homes the endpoint on another configured relay, in place; put it back once a probe shows it connectable (likewise for relays left out at startup) |
| `relay_health` (feature `relay-health`) | the on-demand `/healthz` check of the custom relays that status UIs show: unauthenticated, so it confirms a relay is up rather than that the token is accepted, and made under each relay URL's path prefix, where iroh dials the relay |
| `auth` | the endpoint-bound public-key auth transcript over the [flexaccess-keys] format; each application passes its own domain-separation context |

Deliberately **not** in it: ALPNs, handshake wire formats, QUIC transport
tuning, connection-path status UIs, and anything else product-specific. Those
stay in each application. Nor does it load anything: identity and auth key
files — paths, formats, error hints, permissions — are the application's
(client key files come through [flexaccess-keys]' own loaders), and the crate
takes the resulting `iroh::SecretKey` / `flexaccess_keys` values.

[flexaccess-keys]: https://github.com/flexaccessdev/flexaccess-keys

## Depending on it

```toml
[dependencies]
flexaccess-iroh = { git = "https://github.com/flexaccessdev/flexaccess-iroh", tag = "v0.0.20" }
# or, with mDNS local-network discovery on every endpoint (compiled out on iOS):
flexaccess-iroh = { git = "...", tag = "v0.0.20", features = ["mdns"] }
# or, with the custom-relay `/healthz` check for a status view:
flexaccess-iroh = { git = "...", tag = "v0.0.20", features = ["relay-health"] }
```

The `flexaccess_keys` crate is re-exported so a consumer signs and verifies
with exactly the version this crate does.

## iroh version policy

This crate requires `iroh` as a **range** — currently `>=1.5.0, <1.6.0` —
never an exact pin. Cargo resolves one `iroh` 1.5.x per consumer workspace and
this crate compiles against whatever that is. The obligation on this side is
to only use APIs present in the minimum version; CI builds against it.

The crate turns on iroh's `unstable-net-report` feature (for
`Endpoint::net_report`, which the startup probe reads to detect QUIC address
discovery on custom relays). iroh does not keep that API stable across minor
releases, so moving the upper bound past 1.5 means checking it still exists.
Cargo unifies features, so a consumer's `iroh` gets the feature too.

### Consumers on a fork of iroh

A consumer that depends on a git fork of iroh must redirect this crate's
`iroh` to that fork too, otherwise the graph contains two distinct `iroh`
packages and their `Endpoint` types do not unify. Do it with a patch entry in
the consumer's **root** manifest, and depend on the crates.io version:

```toml
[dependencies]
iroh = "1.5.0"

[patch.crates-io]
iroh = { git = "https://github.com/<you>/iroh.git", branch = "<fork-branch>" }
```

The fork's own `version` must satisfy this crate's range. If the fork also
changes `iroh-base` or `iroh-relay`, patch those too. `Cargo.lock` still pins
the fork commit exactly as a direct git dependency would.

### Raising the minimum

Bump the lower bound only when this crate starts using an API introduced in
that version; bump the upper bound once every consumer has moved past it.
Either is a release of this crate.

## Design notes and operating guides

[`docs/`](docs/README.md) holds the design of this layer and the guides for
operating it:

| Document | What it covers |
|---|---|
| [relays-and-address-lookup.md](docs/relays-and-address-lookup.md) | default vs custom relays, how that choice also decides n0 internet discovery, relay hints, the relay auth token, the startup probe, relay-only mode — start here |
| [relay-failover.md](docs/relay-failover.md) | how a custom-relay server stays reachable when its home relay stops working, and the e2e suite that proves it |
| [nat-traversal-and-transport.md](docs/nat-traversal-and-transport.md) | what the programs get from `iroh::Endpoint`: hole punching, relay fallback, NAT types, the QUIC/TLS 1.3 stack, performance |
| [self-hosting.md](docs/self-hosting.md) | running your own iroh relay, from local dev to production, and verifying it |
| [relay-discovery-findings.md](docs/relay-discovery-findings.md) | the analysis behind tying internet discovery to the relay mode |
| [iroh-relay-connection-trace.md](docs/iroh-relay-connection-trace.md) | what happens on `endpoint.online()`, and troubleshooting a relay by hand |

## Development

```sh
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

### End-to-end tests

The e2e tests for the shared iroh layer live in [`e2e/`](e2e/README.md), run
against real relays through a minimal harness (`examples/e2e`) rather than
through a product: `run_e2e.sh` covers the auth transcript and connectivity
(default relays, custom relays, relay-only), `run_relay_failover.sh` covers
the startup probe and the in-place home-relay failover against two local
`iroh-relay` instances, fully offline. CI runs the offline suites.

```sh
cargo install iroh-relay --features server   # one-time
./e2e/run_e2e.sh --local-relays --relay-only
./e2e/run_relay_failover.sh
```

To iterate against a consumer before tagging, point the consumer at a local
checkout without committing it:

```toml
[patch."https://github.com/flexaccessdev/flexaccess-iroh"]
flexaccess-iroh = { path = "../flexaccess-iroh" }
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for what is under consideration, including
folding [flexaccess-keys] into this repository as a subcrate.

## Releasing

Bump `version` in `Cargo.toml`, merge, and run the **Release** workflow: it
tags `v<version>` from `Cargo.toml` and publishes a GitHub release. Consumers
depend on the tag.

## License

MIT — see [LICENSE](LICENSE).
