#!/usr/bin/env bash
#
# QUIC address discovery (QAD) end-to-end test for flexaccess-iroh. The QAD
# setting is all or none (RelayConfig::with_quic_addr_discovery): on (the
# default), iroh probes every custom relay for it, as it does on its own; off
# (--no-quic-addr-discovery), it probes none. Each scenario runs a client that
# reaches the server, and checks whether its endpoint's net report saw QAD
# answer and how long the endpoint took to come online.
#
# Local section (always; offline), against two local `iroh-relay --dev`
# instances, plain HTTP with nothing on UDP: neither serves QAD, like relays
# behind a Cloudflare Tunnel or any other HTTP-only front.
#
#   on          QAD on: the endpoint waits out iroh's 3 s QAD probe timeout
#               before coming online, and QAD does not answer
#   off         QAD off: the endpoint does not wait
#
# n0 section (with --n0; needs the internet): n0's production relays
# (use1-1 and euc1-1.relay.n0.iroh.link) as the custom relays, which all serve
# QAD over the public internet:
#
#   n0-on       QAD on: the endpoint sees QAD answer, without the 3 s wait.
#               This is the suite's only check that QAD answers at all
#   n0-off      QAD off: the endpoint does not see it answer
#
# Usage: ./e2e/run_quic_addr_discovery.sh [--n0]
#
# Needs iroh-relay; the internet for --n0.
# Environment: E2E_BIN, IROH_RELAY_BIN, KEEP_LOGS, READY_TIMEOUT (see lib.sh).
#
set -euo pipefail

N0=0
case "${1:-}" in
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d'; exit 0 ;;
    --n0) N0=1 ;;
    "") ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
esac

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_iroh_relay

# How long each endpoint gets to see QAD answer. A relay that serves it
# answers in about one round trip; the wait only bounds the negative cases.
QAD_WAIT=10

# iroh's QAD probe timeout is 3 s (iroh 1.5): an endpoint start that waited
# it out takes at least this long, and one that did not stays under QUICK_MS.
WAITED_MS=2500
QUICK_MS=2000

# ---------------------------------------------------------------------------
# Relays
# ---------------------------------------------------------------------------
mapfile -t PORTS < <(pick_ports 2)
define_relay 1 "${PORTS[0]}"
define_relay 2 "${PORTS[1]}"
log "Starting the relays (neither serves QAD)..."
start_relay 1
start_relay 2
BOTH=(--relay-url "http://127.0.0.1:${PORTS[0]}" --relay-url "http://127.0.0.1:${PORTS[1]}")

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
keygen "e2e client" "$WORK/client.key" "$WORK/authorized_keys"

# start_server <name> <relay args...>: start a server (QAD on) and set
# SERVER_PID, SERVER_LOG and SERVER_ID.
start_server() {
    local name="$1"; shift
    SERVER_LOG="$WORK/server_$name.log"
    log "Starting the $name server..."
    start_bg "$SERVER_LOG" "$BIN" server --authorized-keys "$WORK/authorized_keys" "$@"
    SERVER_PID="$BG_PID"
    wait_for_log_or_death "$SERVER_PID" "$SERVER_LOG" "Waiting for clients to connect" "$READY_TIMEOUT" || {
        dump_log "$SERVER_LOG"
        die "the $name server did not come up"
    }
    SERVER_ID="$(server_endpoint_id "$SERVER_LOG")"
    [[ -n "$SERVER_ID" ]] || die "the $name server did not log its EndpointId"
    log "Server EndpointId: $SERVER_ID"
}

# check_server_alive <name>: fail unless the current server is still running.
check_server_alive() {
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log "[$1-server-alive] FAIL: the server exited"
        dump_log "$SERVER_LOG"
        RESULT=1
    fi
}

# Run a client that reports whether its endpoint saw QAD answer.
# Args: <logfile> <relay args...>. Returns the client's exit status.
run_client() {
    local logfile="$1" rc=0; shift
    "$BIN" client --server-id "$SERVER_ID" --private-key-file "$WORK/client.key" \
        --qad-wait-secs "$QAD_WAIT" "$@" >"$logfile" 2>&1 || rc=$?
    return "$rc"
}

RESULT=0
declare -a SUMMARY=()
record() {
    local id="$1" ok="$2"
    if [[ "$ok" -eq 0 ]]; then
        SUMMARY+=("PASS  $id"); log "[$id] PASS"
    else
        SUMMARY+=("FAIL  $id"); log "[$id] FAIL"; RESULT=1
    fi
}

# expect <logfile> <regex> <what>: note and fail unless the log matches.
expect() {
    grep -Eq "$2" "$1" || { note "$3"; return 1; }
}

# expect_online <logfile> <label> <waited|quick>: note and fail unless the
# endpoint logged as <label> came online after at least WAITED_MS (waited) or
# within QUICK_MS (quick). The time is noted for the summary either way.
expect_online() {
    local logfile="$1" label="$2" bound="$3" ms
    ms="$(sed -nE "s/.*\] $label online after ([0-9]+) ms.*/\1/p" "$logfile" | head -1)"
    [[ -n "$ms" ]] || { note "$label: no online time logged"; return 1; }
    TIMES+=("$label ${ms} ms")
    case "$bound" in
        waited) (( ms >= WAITED_MS )) ||
            { note "$label came online after $ms ms, before the 3 s QAD timeout"; return 1; } ;;
        quick) (( ms < QUICK_MS )) ||
            { note "$label came online after $ms ms, not within $QUICK_MS ms"; return 1; } ;;
    esac
}

# scenario <id> <answered|did not answer> <waited|quick> <what> <relay args...>:
# run a client, and check that its endpoint's net report saw QAD answer or
# not, how long the endpoint took to come online, and that it reached the
# server.
scenario() {
    local id="$1" expected="$2" online="$3" what="$4" rc=0 ok=0; shift 4
    log "[$id] $what"
    local logfile="$WORK/client_$id.log"
    run_client "$logfile" "$@" || rc=$?
    [[ "$rc" -eq 0 ]] || { note "client exited with $rc"; ok=1; }
    expect "$logfile" "\] Endpoint: QUIC address discovery $expected" \
        "the endpoint's QAD did not $expected" || ok=1
    TIMES=()
    expect_online "$logfile" "Endpoint" "$online" || ok=1
    note "online: ${TIMES[*]}"
    expect "$logfile" "Echo OK" "the client got no echo" || ok=1
    [[ "$ok" -eq 0 ]] || dump_log "$logfile"
    record "$id" "$ok"
    SUMMARY[-1]+="  (${TIMES[*]})"
    LAST_LOG="$logfile"
}

# ---------------------------------------------------------------------------
# Local relays
# ---------------------------------------------------------------------------
start_server local "${BOTH[@]}"

scenario on "did not answer" waited "QAD on" "${BOTH[@]}"

scenario off "did not answer" quick "QAD off on every relay" "${BOTH[@]}" --no-quic-addr-discovery
expect "$LAST_LOG" "QUIC address discovery is off for the custom relays" \
    "the client did not log that QAD is off" || record off-logged 1

check_server_alive local
kill_pid "$SERVER_PID"

# ---------------------------------------------------------------------------
# n0's relays as custom relays
# ---------------------------------------------------------------------------
if [[ "$N0" -eq 1 ]]; then
    N0_RELAYS=(--relay-url "https://use1-1.relay.n0.iroh.link./"
        --relay-url "https://euc1-1.relay.n0.iroh.link./")
    start_server n0 "${N0_RELAYS[@]}"

    scenario n0-on "answered" quick "n0's relays, QAD on" "${N0_RELAYS[@]}"

    scenario n0-off "did not answer" quick "n0's relays, QAD off" \
        "${N0_RELAYS[@]}" --no-quic-addr-discovery

    check_server_alive n0
fi

echo
log "QUIC address discovery e2e summary:"
for line in "${SUMMARY[@]}"; do note "$line"; done
if [[ "$RESULT" -eq 0 ]]; then
    log "E2E RESULT: ALL PASS ✅"
else
    log "E2E RESULT: FAILURES ❌ (re-run with KEEP_LOGS=1 to inspect $WORK)"
fi
exit "$RESULT"
