# flexaccess-iroh end-to-end tests

The e2e tests for the shared iroh layer live here, with the crate they test,
so a change to the relay probe, the endpoint builder, the home-relay failover,
or the auth transcript is verified against real relays in the same PR. They
used to run against tunnel-rs; now a product's e2e suite only has to cover
what the product adds.

## The harness

`examples/e2e` is the smallest program that puts every module of this crate
through real relays — deliberately not an application. Built with
`cargo build --example e2e` (the scripts do it), it offers:

| Subcommand | Role |
|---|---|
| `server` | binds an endpoint with the shared builder (`--relay-url`, `--relay-only`, an optional `E2E_SERVER_SECRET` identity), runs `relay_failover::fail_over_home_relay` beside its accept loop, and answers each connection: the endpoint-bound auth transcript from `flexaccess_iroh::auth` against `--authorized-keys`, then an echo of the client's message, then an echo of every further stream the client opens. Logs `EndpointId: …` and `Waiting for clients to connect` when ready. |
| `client` | builds an ephemeral endpoint the same way, dials `--server-id` through the configured relays (every custom relay as a hint), proves `--private-key-file`, checks the echo. Logs how long the endpoint took to come online (`Endpoint online after N ms`); with `--qad-wait-secs N` it logs whether its net report saw QUIC address discovery answer within N s (`Endpoint: QUIC address discovery answered` / `… did not answer …`). `--no-quic-addr-discovery` (server or client) turns QUIC address discovery off on every custom relay. Exits `0` on `Echo OK`, `3` when the server rejects the key, `1` otherwise. Logs the selected path it connected over (`via Relay <url>` / `via Direct <addr>`) followed by every path of the connection with its RTT and whether it is selected (`[paths: …]`), the same view flextunnel's connection-path status shows. With `--hold-secs N` it then keeps the connection open, echoing every `--echo-interval-secs` on a fresh stream and logging `Echo #n OK via <path> [paths: …]`, so a script can watch a live connection's paths through a relay outage. |
| `keygen` | writes a client key in the shared flexaccess-keys format (mode 0600) and its `authorized_keys` entry |
| `fake-relay` | a relay that answers the net-report probe (`GET /ping`) but refuses relay connections — the outage shape the failover exists for |
| `delay-proxy` | a TCP proxy adding latency to each new connection, so the relay behind it always measures slower |
| `pick-port` | free localhost ports |

Everything a product adds — its ALPN, QUIC tuning, config files, forwarding —
is left out, so a failure here is a failure of this crate or of iroh.

The harness is built **without** the crate's `mdns` feature, and refuses to
run with direct paths allowed if it was built with it: every process here is
on one host, so mDNS would hand a client the server's address directly and
the relays would never be exercised. Without it, the handshake goes through
the relay and a direct path is learned through it, exactly as off-LAN.

## Suites

| Script | What it checks | Needs |
|---|---|---|
| `run_e2e.sh` | **Auth + connectivity.** An unlisted key is rejected (exit 3, explicit rejection, server logs why); an authorized client authenticates and gets its echo; a second client on the *same* key uses a *distinct* ephemeral iroh identity; under `--relay-only`, every connection ran through a relay. | internet for the default relays; or `--local-relays` / `--relay-url` (one or more) for a fully offline run |
| `run_quic_addr_discovery.sh` | **QUIC address discovery, on or off for all custom relays.** Offline against two local `iroh-relay --dev` instances, neither serving QAD, as relays behind a Cloudflare Tunnel: with QAD on, the client's endpoint waits out iroh's 3 s QAD timeout before coming online; with it off, it does not. With `--n0`, the same on/off pair against n0's production relays as custom relays, which all serve QAD: on sees QAD answer, off does not; their online times are noted, not checked. Every scenario reaches the server. | `iroh-relay`, `ss`, UDP 7842 free; internet for `--n0` |
| `run_relay_failover.sh` | **Relay failover**, fully offline against two local `iroh-relay --dev` instances (relay-only until phase D). Phase A: relays down *before* startup (per-relay probe: startup fails only when none is reachable; a single custom relay runs in reduced-redundancy mode, and fails to start only when it is down). Phase B: a relay dies *after* startup (iroh re-homes on its own; both down fails new clients; both back recovers). Phase C: the home relay answers probes but refuses connections (the in-place failover removes it after 60 s, the server homes on the other relay without restarting, and the restore probe puts it back once it is connectable again). Phase D: the same wedge with direct paths allowed and a client holding a live connection whose paths are relay1 + direct; the failover still moves the server onto the other relay in the background, the held connection keeps echoing over its direct path (ending up direct-only: iroh drops the wedged relay path and does not add a peer's new home relay to an established connection), a new relay-only client's connection path shows the new home relay, and a client that restarts with the same two-relay configuration during the outage comes online, reaches the server through the new home relay, and goes direct again. | `iroh-relay` |

```sh
cargo install iroh-relay --features server      # one-time

./e2e/run_e2e.sh                                # default relays + n0 discovery (internet)
./e2e/run_e2e.sh --local-relays                 # two local relays, offline, direct paths allowed
./e2e/run_e2e.sh --local-relays --relay-only    # ... relay paths only
./e2e/run_e2e.sh --relay-url URL --relay-url URL [--relay-only]   # your own relays

./e2e/run_quic_addr_discovery.sh                # ~1 minute, offline
./e2e/run_quic_addr_discovery.sh --n0           # ... and n0's relays as custom relays (internet)
./e2e/run_relay_failover.sh                     # ~8 minutes: two 60 s failover windows + a 90 s restore probe
```

Each suite prints a `PASS`/`FAIL` line per scenario and exits non-zero on
any failure. The scenario list and contract are at the top of each script.

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `E2E_BIN` | `target/debug/examples/e2e` (rebuilt by cargo) | The harness binary |
| `IROH_RELAY_BIN` | `iroh-relay` on `PATH` | The relay binary |
| `READY_TIMEOUT` | `60` | Seconds to wait for a process to become ready |
| `KEEP_LOGS` | `0` | `1` keeps the working directory (per-process logs; it holds the generated test keys, nothing else) |
| `RELAY_URL` | unset | `run_e2e.sh` only: whitespace-separated fallback for `--relay-url` |

`RUST_LOG` is honored by the harness (default `info`; the crate's own log
lines are what the scripts assert on).

## CI

The `e2e` job in `.github/workflows/ci.yml` runs the offline suites,
`run_e2e.sh --local-relays`, `run_e2e.sh --local-relays --relay-only`,
`run_quic_addr_discovery.sh` and `run_relay_failover.sh`, then
`run_quic_addr_discovery.sh --n0` last, whatever came before: its `--n0`
section, the suite's only check that QAD answers, uses n0's public relays as
custom relays, so its failure never skips an offline suite. The default-relay run of `run_e2e.sh` needs
n0's DNS as well and is left to a developer machine.
