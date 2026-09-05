#!/usr/bin/env bash
#
# Relay failover end-to-end test for flexaccess-iroh (relay-only, no internet).
#
# Runs TWO local iroh-relay instances (`--dev` mode, plain HTTP) and exercises
# relay failures against the e2e harness (examples/e2e). Servers and clients
# are each given an explicit relay list per scenario. Custom relays disable
# internet discovery, so nothing here touches public iroh infrastructure.
#
# Contract under test: a custom relay set holds at least TWO distinct relays,
# because a server rides out a relay outage by moving onto another configured
# relay in place (no rebuild, no dropped identity or connections). Every
# configured relay is probed individually at startup; a relay that is down is
# a warning, and startup fails only when none is reachable. Clients dial with
# every configured relay as a hint, so a server homed on any of them is reachable.
#
# Phase A - relay offline BEFORE startup (the per-relay startup probe):
#   A0  both relays down; server configured with both ..... startup fails (negative)
#   A1  only relay2 up; server and client with both ....... both start (warning
#       for relay1); the client connects via relay2; echo passes
#   A2  a single custom relay is rejected as configuration: server and client
#       configured with ONLY relay2 ........................ startup fails (negative)
#
# Phase B - a relay dies AFTER startup (iroh's own re-homing):
#   B1  both relays up; server and client with both relays; connects; echo passes
#   B2  the server's home relay is killed; the server stays up and re-homes onto
#       the survivor on its own (net_report re-probes every ~20-26s); a new
#       client configured with both relays connects; echo passes
#   B3  the surviving relay is killed too (both down); a new client fails (negative)
#   B4  both relays are restarted; a new client with both relays connects again
#       (server relay reconnect + re-home); echo passes
#
# Phase C - the home relay stays "healthy" for net_report but cannot be connected
#           (the in-place home-relay failover, flexaccess_iroh::relay_failover):
#   C0  relay1 direct, relay2 behind a proxy that adds latency; the server homes
#       on relay1 deterministically; a client connects; echo passes
#   C1  relay1 is replaced, on the same port, by a fake that answers the net-report
#       probe (/ping) but refuses relay connections. iroh keeps preferring it, so
#       nothing re-homes on its own; after 60s the failover removes it from the
#       relay map, the forced net report homes the server on relay2, and a new
#       client connects through relay2; echo passes. The server process and its
#       endpoint never restart.
#   C2  the real relay1 comes back on its port; the failover's restore probe puts
#       it back in the relay map (checked every 90s), the server moves back onto
#       it, and a client connects via relay1; echo passes
#
# Requirements: cargo, iroh-relay (cargo install iroh-relay --features server).
#
# Usage:
#   ./e2e/run_relay_failover.sh
#
# Environment: E2E_BIN, IROH_RELAY_BIN, KEEP_LOGS, READY_TIMEOUT (see lib.sh).
#
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_iroh_relay

# ---------------------------------------------------------------------------
# Ports, identity, client authentication key
# ---------------------------------------------------------------------------
mapfile -t PORTS < <(pick_ports 4)
RELAY1_PORT="${PORTS[0]}"
RELAY2_PORT="${PORTS[1]}"
PROXY_PORT="${PORTS[2]}"
DEAD_PORT="${PORTS[3]}"
RELAY1_URL="http://127.0.0.1:$RELAY1_PORT"
RELAY2_URL="http://127.0.0.1:$RELAY2_PORT"
# relay2 as seen through the latency-adding proxy (phase C).
PROXY_URL="http://127.0.0.1:$PROXY_PORT"
# A relay URL nothing ever listens on: fills the second slot of a client that
# must only use one live relay, since a single custom relay is rejected.
DEAD_URL="http://127.0.0.1:$DEAD_PORT"
log "Relays: relay1=$RELAY1_URL relay2=$RELAY2_URL proxy->relay2=$PROXY_URL"

define_relay 1 "$RELAY1_PORT"
define_relay 2 "$RELAY2_PORT"

SECRET="$(new_server_secret)"
keygen "failover e2e client" "$WORK/client.key" "$WORK/authorized_keys"

# ---------------------------------------------------------------------------
# Fake relay and delay proxy (phase C)
# ---------------------------------------------------------------------------

# A relay that answers the net-report probe but refuses relay connections, on
# relay1's port.
FAKE_RELAY_PID=""
start_fake_relay() {
    local logfile="$WORK/fake_relay.$(date +%s%N).log"
    start_bg "$logfile" "$BIN" fake-relay --port "$RELAY1_PORT"
    FAKE_RELAY_PID="$BG_PID"
    wait_for_log "$logfile" "READY fake relay" 30 || {
        dump_log "$logfile"
        die "the fake relay did not start"
    }
    note "fake relay up on relay1's port $RELAY1_PORT (pid $FAKE_RELAY_PID)"
}

stop_fake_relay() {
    kill_pid "$FAKE_RELAY_PID"
    FAKE_RELAY_PID=""
    note "fake relay stopped"
}

# relay2 behind a proxy that delays each new connection, so net_report always
# measures it as the slower relay.
PROXY_PID=""
PROXY_DELAY_MS=40
start_delay_proxy() {
    local logfile="$WORK/delay_proxy.$(date +%s%N).log"
    start_bg "$logfile" "$BIN" delay-proxy --listen "$PROXY_PORT" \
        --upstream "$RELAY2_PORT" --delay-ms "$PROXY_DELAY_MS"
    PROXY_PID="$BG_PID"
    wait_for_log "$logfile" "READY delay proxy" 30 || {
        dump_log "$logfile"
        die "the delay proxy did not start"
    }
    note "delay proxy up: $PROXY_URL -> relay2 (+${PROXY_DELAY_MS}ms per connection)"
}

stop_delay_proxy() {
    kill_pid "$PROXY_PID"
    PROXY_PID=""
    note "delay proxy stopped"
}

# ---------------------------------------------------------------------------
# Server management
# ---------------------------------------------------------------------------
SERVER_PID=""
SERVER_LOG=""
SERVER_ID=""

# Turn relay URLs into harness arguments. Args: <relay_url>...
relay_args() {
    local url
    for url in "$@"; do
        printf -- '--relay-url\0%s\0' "$url"
    done
}

# Start the server in relay-only mode. Args: <relay_url>...
start_server() {
    SERVER_LOG="$WORK/server.$(date +%s%N).log"
    local -a args=()
    mapfile -d '' -t args < <(relay_args "$@")
    E2E_SERVER_SECRET="$SECRET" start_bg "$SERVER_LOG" \
        "$BIN" server --relay-only --authorized-keys "$WORK/authorized_keys" "${args[@]}"
    SERVER_PID="$BG_PID"
}

# Start a server that is EXPECTED to fail at startup for the reason matching
# regex $1. Passes when the process reports that failure and never becomes
# ready. Args: <failure_regex> <relay_url>...
expect_server_start_failure() {
    local pattern="$1"; shift
    local rc=0
    start_server "$@"
    # rc 0: the expected failure was logged (also when the process exited
    # right after logging it). rc 1: timed out. rc 2: the process died without
    # logging it, i.e. it failed for some other reason. Only rc 0 passes, and
    # only if the server never became ready.
    wait_for_log_or_death "$SERVER_PID" "$SERVER_LOG" "$pattern" "$READY_TIMEOUT" || rc=$?
    if grep -Eq "Waiting for clients to connect" "$SERVER_LOG"; then
        rc=1
    fi
    [[ "$rc" -eq 0 ]] || dump_log "$SERVER_LOG"
    stop_server
    return "$rc"
}

# Start a server that is EXPECTED to come up. Args: <relay_url>...
expect_server_ready() {
    local rc=0
    start_server "$@"
    wait_for_log_or_death "$SERVER_PID" "$SERVER_LOG" \
        "Waiting for clients to connect" "$READY_TIMEOUT" || rc=1
    if [[ "$rc" -eq 0 ]]; then
        SERVER_ID="$(server_endpoint_id "$SERVER_LOG")"
        [[ -n "$SERVER_ID" ]] || { note "server did not log its EndpointId"; rc=1; }
    fi
    [[ "$rc" -eq 0 ]] || dump_log "$SERVER_LOG"
    return "$rc"
}

stop_server() {
    kill_pid "$SERVER_PID"
    SERVER_PID=""
}

# The port of the relay the server last reported as its connected home relay.
# The failover logs "Home relay: <url> connected" on a change while healthy
# and "Home relay connection restored on <url> after Ns" when an outage ends;
# either names the current home relay.
server_home_relay_port() {
    grep -Eo "Home relay: http://127\.0\.0\.1:[0-9]+/ connected|Home relay connection restored on http://127\.0\.0\.1:[0-9]+/" "$SERVER_LOG" |
        tail -1 | sed -E 's|.*:([0-9]+)/.*|\1|'
}

# Wait until the server reports its home relay connected on port $1.
wait_for_home_relay() {
    local port="$1" timeout="$2"
    local max_attempts=$(( timeout * 2 )) attempt=0
    while (( attempt < max_attempts )); do
        [[ "$(server_home_relay_port)" == "$port" ]] && return 0
        sleep 0.5
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# ---------------------------------------------------------------------------
# Client runs
# ---------------------------------------------------------------------------
CLIENT_LOG=""

# Run one relay-only client to completion. Args: <logfile> <relay_url>...
# Returns the client's exit status.
run_client() {
    local logfile="$1"; shift
    local -a args=()
    mapfile -d '' -t args < <(relay_args "$@")
    local rc=0
    "$BIN" client --relay-only --server-id "$SERVER_ID" \
        --private-key-file "$WORK/client.key" \
        --message "failover-$(date +%s%N)" "${args[@]}" >"$logfile" 2>&1 || rc=$?
    return "$rc"
}

# Connect and push one echo through, retrying with a fresh client process:
# after a relay failure the server needs a re-probe cycle (~20-26s) to re-home.
# Args: <attempts> <relay_url>...
connect_and_echo() {
    local attempts="$1"; shift
    local attempt rc
    for (( attempt = 1; attempt <= attempts; attempt++ )); do
        CLIENT_LOG="$WORK/client.$(date +%s%N).log"
        rc=0
        run_client "$CLIENT_LOG" "$@" || rc=$?
        if [[ "$rc" -eq 0 ]] && grep -q "Echo OK" "$CLIENT_LOG"; then
            note "client connected $(grep -Eo 'via .*' "$CLIENT_LOG" | head -1)"
            return 0
        fi
        note "attempt $attempt/$attempts failed (rc=$rc), retrying..."
        sleep 3
    done
    dump_log "$CLIENT_LOG"
    return 1
}

# The message the startup relay probe emits when EVERY configured relay is
# down (one dead relay is only a warning). Negative scenarios must fail in
# the expected way; requiring the message keeps an unrelated startup failure
# (bad key, malformed config) from passing as the expected one.
RELAY_PROBE_FAILURE='all [0-9]+ custom relays failed to come online'
# The config error for fewer than two distinct custom relays.
SINGLE_RELAY_REJECTED='at least 2 distinct relay_urls'

# Run a client that is EXPECTED to fail for the reason matching regex $1.
# Passes when it exits non-zero without ever authenticating AND reports that
# failure. Args: <failure_regex> <relay_url>...
expect_connect_failure() {
    local pattern="$1"; shift
    local logfile="$WORK/client.$(date +%s%N).log"
    local rc=0
    run_client "$logfile" "$@" || rc=$?
    if [[ "$rc" -eq 0 ]] || grep -q "Authenticated as" "$logfile"; then
        note "client unexpectedly connected (rc=$rc)"
        dump_log "$logfile"
        return 1
    fi
    if ! grep -Eq "$pattern" "$logfile"; then
        note "client failed without the expected reason ($pattern)"
        dump_log "$logfile"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Scenario bookkeeping
# ---------------------------------------------------------------------------
RESULT=0
declare -a SUMMARY=()

scenario() {
    log "[$1] $2"
}

record() {
    local id="$1" ok="$2"
    if [[ "$ok" -eq 0 ]]; then
        SUMMARY+=("PASS  $id"); log "[$id] PASS"
    else
        SUMMARY+=("FAIL  $id"); log "[$id] FAIL"; RESULT=1
    fi
}

# ===========================================================================
# Phase A - relays offline BEFORE startup (the per-relay startup probe)
# ===========================================================================

scenario A0 "both relays down: server configured with both fails to start"
rc=0
expect_server_start_failure "$RELAY_PROBE_FAILURE" "$RELAY1_URL" "$RELAY2_URL" || rc=1
record A0 "$rc"

scenario A1 "relay1 down: server and client configured with both start on relay2 alone"
start_relay 2
rc=0
expect_server_ready "$RELAY1_URL" "$RELAY2_URL" || rc=1
if [[ "$rc" -eq 0 ]] && ! grep -Eq "1 of 2 custom relays failed to come online" "$SERVER_LOG"; then
    note "server did not warn about the dead relay"
    rc=1
fi
if [[ "$rc" -eq 0 ]]; then
    connect_and_echo 3 "$RELAY1_URL" "$RELAY2_URL" || rc=1
fi
if [[ "$rc" -eq 0 ]] && ! grep -Eq "1 of 2 custom relays failed to come online" "$CLIENT_LOG"; then
    note "client did not warn about the dead relay"
    rc=1
fi
if [[ "$rc" -eq 0 ]] && ! grep -Eq "Connected to [0-9a-f]+ via Relay $RELAY2_URL/" "$CLIENT_LOG"; then
    note "client did not connect through relay2"
    rc=1
fi
record A1 "$rc"
stop_server

scenario A2 "a single custom relay is rejected: server and client with only relay2 fail to start"
rc=0
expect_server_start_failure "$SINGLE_RELAY_REJECTED" "$RELAY2_URL" || rc=1
expect_connect_failure "$SINGLE_RELAY_REJECTED" "$RELAY2_URL" || rc=1
record A2 "$rc"

stop_relay 2

# ===========================================================================
# Phase B - a relay dies AFTER client/server are connected (iroh re-homes)
# ===========================================================================

scenario B1 "both relays up: client with both relays connects"
start_relay 1
start_relay 2
rc=0
expect_server_ready "$RELAY1_URL" "$RELAY2_URL" || rc=1
HOME_RELAY_NUM=""
if [[ "$rc" -eq 0 ]]; then
    connect_and_echo 3 "$RELAY1_URL" "$RELAY2_URL" || rc=1
fi
if [[ "$rc" -eq 0 ]]; then
    case "$(server_home_relay_port)" in
        "$RELAY1_PORT") HOME_RELAY_NUM=1 ;;
        "$RELAY2_PORT") HOME_RELAY_NUM=2 ;;
        *) note "server did not report a connected home relay"; rc=1 ;;
    esac
    note "server home relay is relay$HOME_RELAY_NUM"
fi
record B1 "$rc"

scenario B2 "kill the server's home relay: server re-homes on its own, a new client connects via the survivor"
rc=0
if [[ -n "$HOME_RELAY_NUM" ]]; then
    SURVIVOR_NUM=$(( 3 - HOME_RELAY_NUM ))
    SURVIVOR_PORT="${RELAY_PORT[$SURVIVOR_NUM]}"
    stop_relay "$HOME_RELAY_NUM"
    # Losing a relay at runtime must NOT take the already-started server down.
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        note "server exited when a relay died at runtime"
        rc=1
    fi
    # The dead relay stops answering net_report's probe, so iroh itself moves
    # the home relay within a re-probe cycle, no failover action needed.
    if [[ "$rc" -eq 0 ]]; then
        wait_for_home_relay "$SURVIVOR_PORT" 60 || { note "server did not re-home onto relay$SURVIVOR_NUM"; rc=1; }
    fi
    if [[ "$rc" -eq 0 ]] && grep -Eq "Removed .* from the relay map" "$SERVER_LOG"; then
        note "the failover acted although iroh re-homed on its own"
        rc=1
    fi
    # The new client lists both relays (one is dead: a warning at its probe).
    if [[ "$rc" -eq 0 ]]; then
        connect_and_echo 4 "$RELAY1_URL" "$RELAY2_URL" || rc=1
    fi
else
    rc=1
fi
record B2 "$rc"

scenario B3 "kill the surviving relay too (both down): new client fails"
rc=0
if [[ -n "${SURVIVOR_NUM:-}" ]]; then
    stop_relay "$SURVIVOR_NUM"
    expect_connect_failure "$RELAY_PROBE_FAILURE" "$RELAY1_URL" "$RELAY2_URL" || rc=1
else
    rc=1
fi
record B3 "$rc"

scenario B4 "restart both relays: server recovers and a new client connects"
rc=0
start_relay 1
start_relay 2
# The server's relay actors reconnect with backoff; allow several attempts.
connect_and_echo 8 "$RELAY1_URL" "$RELAY2_URL" || rc=1
record B4 "$rc"

stop_server
stop_relay 1
stop_relay 2

# ===========================================================================
# Phase C - the home relay answers probes but cannot be connected (in-place failover)
# ===========================================================================

scenario C0 "relay1 direct, relay2 behind a slow proxy: server homes on relay1"
rc=0
start_relay 1
start_relay 2
start_delay_proxy
expect_server_ready "$RELAY1_URL" "$PROXY_URL" || rc=1
if [[ "$rc" -eq 0 ]]; then
    wait_for_home_relay "$RELAY1_PORT" 30 || { note "server did not home on relay1"; rc=1; }
fi
if [[ "$rc" -eq 0 ]]; then
    connect_and_echo 3 "$RELAY1_URL" "$PROXY_URL" || rc=1
fi
record C0 "$rc"

scenario C1 "relay1 becomes a fake that answers probes but refuses connections: the failover moves the server onto relay2 in place"
rc=0
stop_relay 1
start_fake_relay
wait_for_log "$SERVER_LOG" "No connected home relay" 60 || { note "server never noticed the relay loss"; rc=1; }
if [[ "$rc" -eq 0 ]]; then
    # 60s outage window, then the wedged relay is taken out of the relay map.
    wait_for_log "$SERVER_LOG" "Removed $RELAY1_URL/ from the relay map" 90 || {
        note "the failover did not remove relay1 from the relay map"; rc=1; }
fi
if [[ "$rc" -eq 0 ]]; then
    wait_for_log "$SERVER_LOG" "Home relay connection restored on $PROXY_URL/" 60 || {
        note "server did not home on relay2 after the failover"; rc=1; }
fi
if [[ "$rc" -eq 0 ]]; then
    # iroh must not have re-homed on its own before the failover acted.
    removed_line="$(grep -En "Removed $RELAY1_URL/ from the relay map" "$SERVER_LOG" | head -1 | cut -d: -f1)"
    restored_line="$(grep -En "Home relay connection restored on $PROXY_URL/" "$SERVER_LOG" | head -1 | cut -d: -f1)"
    if (( restored_line < removed_line )); then
        note "server re-homed before the failover acted (lines $restored_line < $removed_line)"
        rc=1
    fi
fi
if [[ "$rc" -eq 0 ]] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
    note "server process died"
    rc=1
fi
# A new client reaches the server through relay2. Its second relay slot is a
# dead port rather than the fake: a client that homed on the fake could never
# come online, and the failover runs only on the server.
if [[ "$rc" -eq 0 ]]; then
    connect_and_echo 3 "$PROXY_URL" "$DEAD_URL" || rc=1
fi
[[ "$rc" -eq 0 ]] || dump_log "$SERVER_LOG"
record C1 "$rc"

scenario C2 "the real relay1 returns: the restore probe puts it back and the server moves back onto it"
rc=0
stop_fake_relay
start_relay 1
# The restore probe runs every 90s after the removal; allow for one full
# interval plus the 10s probe, then a net-report cycle for the move back.
wait_for_log "$SERVER_LOG" "$RELAY1_URL/ is connectable again and back in the relay map" 150 || {
    note "relay1 was not restored to the relay map"; rc=1; }
if [[ "$rc" -eq 0 ]]; then
    wait_for_home_relay "$RELAY1_PORT" 60 || { note "server did not move back onto relay1"; rc=1; }
fi
if [[ "$rc" -eq 0 ]]; then
    connect_and_echo 3 "$RELAY1_URL" "$PROXY_URL" || rc=1
fi
[[ "$rc" -eq 0 ]] || dump_log "$SERVER_LOG"
record C2 "$rc"

stop_server
stop_delay_proxy
stop_relay 1
stop_relay 2

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
log "Relay failover e2e summary:"
for line in "${SUMMARY[@]}"; do note "$line"; done
if [[ "$RESULT" -eq 0 ]]; then
    log "E2E RESULT: ALL PASS ✅"
else
    log "E2E RESULT: FAILURES ❌ (re-run with KEEP_LOGS=1 to inspect $WORK)"
fi
exit "$RESULT"
