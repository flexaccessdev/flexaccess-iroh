# flexaccess-iroh

Shared iroh transport layer for FlexAccess applications, as a Rust crate.

The programs built on iroh in this org — [tunnel-rs], [ezvpn], [flextunnel] —
share one transport foundation. Its design is documented once in
[iroh-common-architecture]; this crate is that design as code, so a fix to the
relay watchdog or the relay probe lands here once instead of being ported by
hand into every repo.

[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
[iroh-common-architecture]: https://github.com/flexaccessdev/iroh-common-architecture

## What is in it

| Module | Contents |
|---|---|
| `relay` | `RelayConfig` (default vs custom relays, which also decides whether n0 internet discovery is on), the shared relay auth token, the strict per-relay startup probe |
| `endpoint` | the common endpoint builder, `create_endpoint` (strict first creation) vs `rebuild_endpoint` (tolerant mid-run replacement), `RebuildableEndpoint`, the persistent secret-key file loader |
| `relay_watchdog` | the server-side home-relay watchdog: nudge with `network_change()`, then ask for a rebuild |
| `auth` | the endpoint-bound public-key auth transcript over the [flexaccess-keys] format; each application passes its own domain-separation context |

Deliberately **not** in it: ALPNs, handshake wire formats, QUIC transport
tuning, connection-path status UIs, and anything else product-specific. Those
stay in each application.

[flexaccess-keys]: https://github.com/flexaccessdev/flexaccess-keys

## Depending on it

```toml
[dependencies]
flexaccess-iroh = { git = "https://github.com/flexaccessdev/flexaccess-iroh", tag = "v0.0.1" }
# or, with mDNS local-network discovery on every endpoint (compiled out on iOS):
flexaccess-iroh = { git = "...", tag = "v0.0.1", features = ["mdns"] }
```

The `flexaccess_keys` crate is re-exported so a consumer signs and verifies
with exactly the version this crate does.

## iroh version policy

This crate requires `iroh` as a **range** — currently `>=1.1.0, <1.2.0` —
never an exact pin. Cargo resolves one `iroh` 1.1.x per consumer workspace and
this crate compiles against whatever that is. The obligation on this side is
to only use APIs present in the minimum version; CI builds against it.

### Consumers on a fork of iroh

A consumer that depends on a git fork of iroh must redirect this crate's
`iroh` to that fork too, otherwise the graph contains two distinct `iroh`
packages and their `Endpoint` types do not unify. Do it with a patch entry in
the consumer's **root** manifest, and depend on the crates.io version:

```toml
[dependencies]
iroh = "1.1.0"

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

## Development

```sh
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

To iterate against a consumer before tagging, point the consumer at a local
checkout without committing it:

```toml
[patch."https://github.com/flexaccessdev/flexaccess-iroh"]
flexaccess-iroh = { path = "../flexaccess-iroh" }
```

## Releasing

Bump `version` in `Cargo.toml`, merge, and run the **Release** workflow: it
tags `v<version>` from `Cargo.toml` and publishes a GitHub release. Consumers
depend on the tag.
