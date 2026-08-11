# Self-Hosting Iroh Infrastructure

How to self-host iroh relay servers for fully independent operation. This
applies to [tunnel-rs], [ezvpn], and [flextunnel] alike — they share the relay
design described in
[relays-and-address-lookup.md](relays-and-address-lookup.md).

Configuring any custom relay disables internet discovery automatically, so a
self-hosted relay is all the infrastructure you need: **no discovery service, no
contact with public iroh infrastructure.**

> **Reference program: [tunnel-rs].** It is the only one of the three with a
> first-class relay-only mode (`--relay-only`) and a fully offline two-relay e2e
> suite, which makes it the fastest way to prove a freshly deployed relay
> actually works before pointing a VPN or proxy at it. The verification commands
> below use it for that reason; the resulting relay serves all three programs.

## Before you start: the startup contract

Every configured custom relay is probed **individually** at startup and **all**
of them must come online, or the process refuses to start. A dead backup relay
is a startup failure, not a silent degradation. Plan your relay list
accordingly, and configure **both sides with the full list** — see the warning
in [relays-and-address-lookup.md](relays-and-address-lookup.md#custom-relays).

## Quick start: local relay

```bash
cargo install iroh-relay --version 1.0.2
iroh-relay --dev  # local testing on http://localhost:3340
```

> **Ports (verified against iroh-relay 1.0.2):** `--dev` runs the relay over
> plain HTTP on port **3340** (`http_bind_addr`) and starts a Prometheus
> **metrics** server on **9090** (`metrics_bind_addr`); it does **not** start a
> QUIC endpoint, because QUIC address discovery requires TLS, which `--dev`
> ignores. If port 9090 is already in use (e.g. by Cockpit), turn the metrics
> server off with `enable_metrics = false` in a config file, or move it with
> `metrics_bind_addr = "127.0.0.1:9099"` — `--dev` still honors non-TLS config
> fields. For production with TLS the relay serves HTTP on **80**, HTTPS on
> **443**, and QUIC address discovery on **7842** (`quic_bind_addr`) when
> `enable_quic_addr_discovery = true`.

> [!NOTE]
> **Endpoint-ID allowlisting is usually the wrong tool here.** iroh-relay 1.0.2
> *does* support `access.allowlist` and `access.denylist` (lists of
> `EndpointId`s), alongside `access.http` for an external authorization endpoint.
> But all three programs give clients **ephemeral** endpoint identities that
> change on every run, so a static allowlist cannot enumerate them and would
> reject legitimate clients — only long-lived identities (a server's
> `secret_file`) are stable enough to list.
>
> Primary access control therefore belongs to each program's own application
> authentication — Ed25519 public-key auth in tunnel-rs and flextunnel, the VPN
> handshake in ezvpn — with the [shared bearer token](#relay-access-token) below
> gating the relay itself. `access.allowlist` / `access.denylist` remain useful as
> defense in depth where the identities *are* stable (pinning a known set of
> servers, or blocking a specific abusive endpoint).

## Production relay with TLS

```bash
cargo install iroh-relay --version 1.0.2
iroh-relay --config-path relay.toml   # -c is the short form; there is no --config
```

Example `relay.toml`:

```toml
# Enable QUIC address discovery
enable_quic_addr_discovery = true

# TLS configuration (required for production)
[tls]
cert_mode = "Manual"
manual_cert_path = "/etc/letsencrypt/live/relay.example.com/fullchain.pem"
manual_key_path = "/etc/letsencrypt/live/relay.example.com/privkey.pem"

# Alternative: use Let's Encrypt automatic certificates
# [tls]
# cert_mode = "LetsEncrypt"
# hostname = "relay.example.com"
```

## Simple production setup: relay behind Cloudflare Tunnel (single TCP port)

If you don't want to manage TLS certificates or open inbound ports, run the
relay over **plain HTTP on a single TCP port** and let Cloudflare Tunnel
terminate TLS at the edge and forward decrypted HTTP to it. Only outbound
connectivity is needed on the relay host — no public IP, no 443, no QUIC/UDP.

**How it works:** omitting the `[tls]` section makes iroh-relay serve *all*
services (the `/relay` WebSocket and the `healthz` routes) over plain HTTP on
`http_bind_addr`. QUIC address discovery defaults to off, so no TLS is required
and the relay starts cleanly without `--dev`. This is the non-`--dev` equivalent
of the local dev config — verified against iroh-relay 1.0.2.

```toml
# Plain-HTTP relay on 3340 (the non-dev default is port 80). Must match the
# cloudflared ingress service and the relay URL the clients use.
http_bind_addr = "[::]:3340"

# Metrics server defaults to port 9090 and often collides with other services;
# turn it off (or move it to a private address you do NOT expose via the tunnel).
enable_metrics = false
# metrics_bind_addr = "127.0.0.1:9099"

# Recommended for a publicly reachable relay: require a bearer token.
# Generate a real one before starting (see "Relay access token" below) — never
# ship the literal placeholder:
# access.shared_token = ["<paste output of: openssl rand -base64 32>"]
```

**1. Run the relay** (no `--dev`):

```bash
iroh-relay -c relay-prod.toml
```

**2. Point cloudflared at it.** The tunnel's ingress must forward the hostname
to `http://localhost:3340`. With a token-based (dashboard-managed) tunnel this
is one line in the dashboard; for a locally-managed tunnel, `config.yml`:

```yaml
tunnel: <tunnel-uuid>
credentials-file: /root/.cloudflared/<tunnel-uuid>.json

ingress:
  - hostname: relay.example.com
    service: http://localhost:3340
  - service: http_status:404
```

```bash
# Locally-managed tunnel:
cloudflared tunnel run <tunnel-name>
# Or dashboard/token-managed tunnel:
cloudflared tunnel run --token <token>
```

**3. Verify** end to end (see [Verifying a relay](#verifying-a-relay) below).

> [!NOTE]
> No paid Cloudflare plan or HTTP/1.1 override is needed — the iroh relay client
> sends no TLS ALPN, so Cloudflare's edge negotiates HTTP/1.1 and the WebSocket
> upgrade works through both quick and named tunnels. A bare
> `curl https://relay.example.com/relay` returning `400` is expected (the relay
> answers 400 to any non-WebSocket request); it is not a tunnel problem. See
> [iroh-relay-connection-trace.md](iroh-relay-connection-trace.md) for the full
> trace.

> **Trade-off:** this routes all relayed traffic through Cloudflare and, because
> there is no QUIC endpoint, disables QUIC address discovery (one of the signals
> iroh uses to help peers hole-punch to a direct connection). For a relay whose
> job is a pure relay-only fallback this is fine; if you want to maximize direct
> P2P success, use the TLS + QUIC production config above instead.

## Relay access token

For a publicly reachable relay, require a shared bearer token so only your
deployments can use it. **Generate a unique secret before first start** — a
guessable or copy-pasted token is the same as having no access control:

```bash
openssl rand -base64 32   # or: head -c 32 /dev/urandom | base64
```

Put it in the config file:

```toml
access.shared_token = ["<the generated secret>"]
```

…or keep it out of the config entirely by setting the environment variable, which
**takes precedence over `access.shared_token`** and sets a single allowed token:

```bash
IROH_RELAY_ACCESS_TOKEN="<the generated secret>" iroh-relay -c relay-prod.toml
```

Either way the relay refuses to start if the token list is empty or contains an
empty string, so a misconfigured token fails loudly rather than silently
disabling access control. Use the config-file form (which accepts a *list*) when
you need to rotate: serve both the old and new token, migrate the clients, then
drop the old one.

Then configure the same token on **both** sides of every program. It is only
ever accepted alongside custom relay URLs — supplying it without them is a hard
configuration error in all three programs.

| Repo | Config key | CLI | Env |
|---|---|---|---|
| [tunnel-rs] | `[iroh].relay_auth_token` | `--relay-auth-token` | `TUNNEL_RS_RELAY_AUTH_TOKEN` |
| [ezvpn] | `[iroh].relay_auth_token` | — | — |
| [flextunnel] | `relay_auth_token` | `--relay-auth-token` | — |

The token rides the relay WebSocket upgrade as `Authorization: Bearer <token>`,
which means the per-relay startup probe validates it: a relay that rejects the
token never comes online and startup fails with that relay named.

## Verifying a relay

**End to end, with tunnel-rs** (the reference relay-only path — this exercises a
real tunnel over the relay with direct P2P disabled, so a pass means the relay
alone is carrying traffic):

```bash
# From a tunnel-rs checkout
./test-scripts/run_e2e.sh --relay-url https://relay.example.com --relay-only
```

> The snippets in this section assume a **tokenless** relay. If the relay has
> `access.shared_token` set, the token must also be supplied — for tunnel-rs, via
> `TUNNEL_RS_RELAY_AUTH_TOKEN` or `--relay-auth-token` (see the table above);
> without it the relay rejects the connection and startup fails.

**Two-relay failover behavior**, fully offline, against local
`iroh-relay --dev` instances:

```bash
./test-scripts/run_relay_failover_e2e.sh
```

**Just the HTTP/WebSocket upgrade**, without running a tunnel. `--no-alpn`
disables the TLS ALPN extension, matching what the iroh relay client sends:

```bash
# Should return 101 Switching Protocols
curl -v --no-alpn \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1" \
  -H "Authorization: Bearer $IROH_RELAY_TOKEN" \
  https://relay.example.com/relay
```

> [!IMPORTANT]
> **A 101 does not mean your token was accepted.** This checks the HTTP and
> WebSocket upgrade only — that the relay (and anything proxying it) is reachable
> and speaks the upgrade correctly. In iroh-relay 1.0.2 the server returns `101
> Switching Protocols` *before* the relay handshake runs, and the access-control
> check (`access.shared_token`, `allowlist`, `denylist`, `http`) happens after
> that, inside the relay protocol handshake. A relay with a token configured
> answers `101` to this request even with the `Authorization` header omitted or
> wrong; the connection is dropped a moment later.
>
> Validating the token needs a relay-protocol-aware client configured with it —
> which is exactly what the per-relay startup probe is, so **the end-to-end
> tunnel-rs run above is the real token check.** Include the header here anyway,
> so the command matches what a genuine client sends.

A bare `curl https://relay.example.com/relay` returns `400 Bad Request` — that is
the relay answering any non-WebSocket request, not a proxy problem. Only the full
upgrade request above is a meaningful reachability check. The relay's `/healthz`
route is likewise unauthenticated, so it too confirms the relay is *up* and
nothing more.

## Using your infrastructure

Point both sides at the relay. Exact flags differ per program; the shape is the
same:

```bash
# tunnel-rs
tunnel-rs server --relay-url https://relay.example.com \
  --secret-file ./server.key --allowed-tcp 127.0.0.0/8 \
  --authorized-keys-file ./authorized_keys

tunnel-rs client --relay-url https://relay.example.com \
  --server-node-id <ID> --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222 --private-key-file ./client.key
```

For ezvpn and flextunnel, set `relay_urls` (plus `relay_auth_token` if used) in
the server and client config files. See each repo's own configuration docs.

## Relay behavior

The relay is used for both **signaling/coordination** and as a **data transport
fallback**:

1. The initial connection goes through the relay for signaling.
2. iroh attempts coordinated hole punching (similar to libp2p's DCUtR).
3. If it succeeds, traffic flows directly between peers. How often that happens
   varies with network conditions — NAT type and filtering behavior on both
   sides, address family, and any upstream CGNAT all matter; see
   [nat-traversal-and-transport.md](nat-traversal-and-transport.md#nat-traversal-capability-by-nat-type).
4. If hole punching fails, **traffic continues through the relay**.

> [!NOTE]
> **Bandwidth:** signaling-only coordination *without* relay data fallback is not
> supported by iroh. The relay always acts as fallback when a direct connection
> cannot be established. Size relay bandwidth for the traffic of peers that
> cannot hole-punch.

[tunnel-rs]: https://github.com/andrewtheguy/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
