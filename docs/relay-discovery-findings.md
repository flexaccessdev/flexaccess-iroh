# Why internet discovery is disabled automatically with custom relays

Analysis behind making internet discovery non-configurable: iroh internet
discovery (n0 DNS lookup + pkarr publishing) is enabled with the default relay
infrastructure and always disabled when custom relay URLs are configured. A
former `--discovery` option (custom Pkarr URL / `"none"`) was removed. Verified
against iroh **1.0.2** source and [tunnel-rs]'s e2e suites in `test-scripts/`
(2026-07-20).

This finding is why all three programs ([tunnel-rs], [ezvpn], [flextunnel]) tie
discovery to the relay mode rather than exposing it as a knob — see
[relays-and-address-lookup.md](relays-and-address-lookup.md).

## Question

When both client and server are configured with the same custom relays, does the
iroh discovery server make any real difference — or can it be disabled
automatically?

## Conclusion

It can be disabled. With custom relays on both sides, discovery adds nothing to
connection establishment, and leaving the default (n0) discovery on was actively
undesirable: an endpoint with a **persistent identity** (the only case in which
`PkarrPublisher` is installed — see [Default relays][defaults]) published its
custom relay URL and addresses to iroh's public DNS. That is an internet
dependency for an otherwise self-contained deployment, and, for those persistent
endpoints, an information leak. Ephemeral endpoints publish no record either way,
so the leak never applied to them — but the internet dependency did, since they
still resolved through `dns.iroh.link`.

[defaults]: relays-and-address-lookup.md#default-relays

## Mechanism (iroh 1.0.2 internals)

Discovery exists to answer one question: "at which addresses / on which relay can
this EndpointId be reached?" With custom relays, the answer is already in the
config:

1. **The client passes every configured relay as a hint.** The connect path
   builds the server's `EndpointAddr` with all configured relay URLs, or (in
   relay-only mode) tries each relay in turn.

2. **iroh sends the QUIC handshake to all hinted paths at once.** Before a path
   is selected, QUIC Initial packets are broadcast to *every* known transport
   address, including every relay hint — see
   `iroh-1.0.2/src/socket/remote_map/remote_state.rs`,
   `RemoteStateMessage::SendDatagram`: "Sends a datagram to all known paths. Used
   to send QUIC Initial packets." The handshake therefore succeeds via whichever
   relay the server is currently homed on. This is why the old warning
   (`discovery = "none"` does not work reliably with more than one custom relay)
   no longer applies on iroh 1.0.

3. **Direct-path upgrade does not need discovery either.** Hole punching is
   negotiated over the established relay path (NAT traversal candidates are
   exchanged on the connection itself), so the relay hint is sufficient to
   bootstrap a direct P2P connection.

### Home-relay semantics (the one caveat)

- An iroh endpoint has **one home relay at a time**, chosen as the
  fastest-probing relay in its `RelayMap` by net_report, and keeps a persistent
  connection only to it (`socket/transports/relay/actor.rs`; non-home relay
  connections close after an inactivity timeout).
- Relay servers are stateless and independent: a relay only delivers packets to
  endpoints currently connected to it. Traffic sent via a relay the server is not
  connected to is dropped.
- net_report re-probes every **20–26 s** (`new_re_stun_timer` in `socket.rs`), so
  after its home relay dies the server re-homes onto another configured relay
  within roughly 30 s.

Consequence: a client configured with only a **subset** of the server's relays
can reach the server only while the server's current home relay is in that
subset. Public discovery was the mechanism that could rescue that case (the
client would learn the server's current home relay). Hence the guidance in
[self-hosting.md](self-hosting.md): configure clients with the full relay list.

## Empirical verification

[tunnel-rs]'s `test-scripts/run_relay_failover_e2e.sh` is fully offline: two
local `iroh-relay --dev` instances, relay-only mode, internet discovery
auto-disabled. It covers the startup probe, iroh's own re-homing, and the shared failover:

| Phase | Scenario |
|---|---|
| A | Every configured relay is probed at startup: a server configured with both relays fails to start only when both are down, starts with a warning when one is, and a client with both relays connects through the live one; a single custom relay is rejected as configuration |
| B | Runtime relay loss is survivable: killing the server's home relay leaves the server up, it re-homes onto the surviving relay on its own (observed ≈ the 20–26 s re-probe cycle) and a restarted client with both relays reconnects; with both relays down new clients fail; after both restart, clients connect again |
| C | The in-place home-relay failover for the case iroh does not recover on its own; see [relay-failover.md](relay-failover.md#verification) |

`test-scripts/run_e2e.sh --relay-url <r1> --relay-url <r2>` (TCP + UDP) also
passes against two local relays with no internet discovery, in both normal and
`--relay-only` mode — previously the multi-relay configuration required public
discovery.

Log line confirming the behavior on endpoint creation:

```
INFO tunnel_rs::iroh_mode::endpoint] Internet discovery disabled (custom relays configured)
```

mDNS local-network discovery remains enabled; relay-only mode skips all
discovery including mDNS.

[tunnel-rs]: https://github.com/flexaccessdev/tunnel-rs
[ezvpn]: https://github.com/flexaccessdev/ezvpn
[flextunnel]: https://github.com/flexaccessdev/flextunnel
