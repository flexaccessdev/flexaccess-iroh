#!/usr/bin/env bash
#
# QUIC address discovery (QAD) end-to-end test for flexaccess-iroh, fully
# offline against two local `iroh-relay --dev` instances:
#
#   relay1  serves QAD: a `tls` section with a certificate from a test CA and
#           `enable_quic_addr_discovery`, its QUIC server on 127.0.0.1:7842
#           (the port the crate assumes); the relay itself stays plain HTTP
#   relay2  does not serve QAD (no TLS, nothing on UDP). It is on 127.0.0.2:
#           the crate looks for a relay's QAD at its URL host on UDP 7842, so
#           on 127.0.0.1 it would find relay1's
#
# The server and clients use both relays, trust the test CA through
# --relay-ca (RelayConfig::with_extra_ca_roots) unless a scenario says
# otherwise, and run with direct paths allowed: QAD needs the endpoint's UDP
# sockets.
#
#   1. probe        the startup probe finds that relay1 serves QAD and relay2
#                   does not
#   2. endpoint     the created endpoint's net report then sees QAD answer
#   3. rebuilt      an endpoint replaced with rebuild_endpoint (no probe of its
#                   own) still has QAD on for relay1: its net report sees QAD
#                   answer, and it reaches the server
#   4. untrusted    control: without the test CA, the probe's QAD check fails
#                   its TLS handshake, so relay1 counts as not serving QAD and
#                   neither endpoint sees QAD answer. This shows the signal
#                   above is QAD, and that the CA reaches the probe endpoints
#                   and not just the main one
#
# Usage: ./e2e/run_quic_addr_discovery.sh
#
# Needs Linux (127.0.0.2 on loopback), iroh-relay and openssl, and UDP
# 127.0.0.1:7842 free.
# Environment: E2E_BIN, IROH_RELAY_BIN, KEEP_LOGS, READY_TIMEOUT (see lib.sh).
#
set -euo pipefail

case "${1:-}" in
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d'; exit 0 ;;
    "") ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
esac

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_iroh_relay
command -v openssl >/dev/null || die "openssl not found"

# How long each endpoint gets to see QAD answer. A relay that serves it
# answers in about one round trip; the wait only bounds the negative cases.
QAD_WAIT=10

# ---------------------------------------------------------------------------
# Relays
# ---------------------------------------------------------------------------
# A test CA and a server certificate it signs: webpki refuses a self-signed
# CA certificate presented as the server's own (CaUsedAsEndEntity).
log "Generating a test CA and relay1's certificate..."
{
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -subj "/CN=flexaccess-iroh e2e CA" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign" \
        -keyout "$WORK/ca.key" -out "$WORK/ca.crt" &&
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -subj /CN=localhost -keyout "$WORK/relay1.key" -out "$WORK/relay1.csr" &&
    printf '%s\n' "basicConstraints=critical,CA:FALSE" "extendedKeyUsage=serverAuth" \
        "subjectAltName=DNS:localhost,IP:127.0.0.1" > "$WORK/relay1.ext" &&
    openssl x509 -req -in "$WORK/relay1.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
        -CAcreateserial -days 1 -extfile "$WORK/relay1.ext" -out "$WORK/relay1.crt"
} >/dev/null 2>&1 || die "openssl could not create the certificates"

mapfile -t PORTS < <(pick_ports 2)
define_relay 1 "${PORTS[0]}"
define_relay 2 "${PORTS[1]}" 127.0.0.2
cat >> "$WORK/relay1.toml" <<EOF
enable_quic_addr_discovery = true

[tls]
cert_mode = "Manual"
manual_cert_path = "$WORK/relay1.crt"
manual_key_path = "$WORK/relay1.key"
quic_bind_addr = "127.0.0.1:7842"
EOF
log "Starting the relays (relay1 serves QAD on UDP 127.0.0.1:7842)..."
start_relay 1
start_relay 2
RELAY1="http://127.0.0.1:${PORTS[0]}"
RELAY2="http://127.0.0.2:${PORTS[1]}"
BOTH=(--relay-url "$RELAY1" --relay-url "$RELAY2")
CA=(--relay-ca "$WORK/ca.crt")

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
keygen "e2e client" "$WORK/client.key" "$WORK/authorized_keys"
SERVER_LOG="$WORK/server.log"
log "Starting the server..."
start_bg "$SERVER_LOG" "$BIN" server --authorized-keys "$WORK/authorized_keys" "${BOTH[@]}" "${CA[@]}"
SERVER_PID="$BG_PID"
wait_for_log_or_death "$SERVER_PID" "$SERVER_LOG" "Waiting for clients to connect" "$READY_TIMEOUT" || {
    dump_log "$SERVER_LOG"
    die "the server did not come up"
}
SERVER_ID="$(server_endpoint_id "$SERVER_LOG")"
[[ -n "$SERVER_ID" ]] || die "the server did not log its EndpointId"
log "Server EndpointId: $SERVER_ID"

# Run a client that rebuilds its endpoint once, reporting QAD for both.
# Args: <logfile> <relay args...>. Returns the client's exit status.
run_client() {
    local logfile="$1" rc=0; shift
    "$BIN" client --server-id "$SERVER_ID" --private-key-file "$WORK/client.key" \
        --rebuild --qad-wait-secs "$QAD_WAIT" "$@" >"$logfile" 2>&1 || rc=$?
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

# ---------------------------------------------------------------------------
# 1.-3. Both relays, relay1's CA trusted
# ---------------------------------------------------------------------------
log "[probe/endpoint/rebuilt] both relays, relay1's CA trusted"
CLIENT_LOG="$WORK/client_both.log"
rc=0
run_client "$CLIENT_LOG" "${BOTH[@]}" "${CA[@]}" || rc=$?
[[ "$rc" -eq 0 ]] || note "client exited with $rc"

ok=0
expect "$CLIENT_LOG" "1 of the 2 reachable custom relays serve QUIC address discovery: $RELAY1/?\$" \
    "the probe did not find relay1 alone serving QAD" || ok=1
expect "$SERVER_LOG" "1 of the 2 reachable custom relays serve QUIC address discovery: $RELAY1/?\$" \
    "the server's probe did not find relay1 alone serving QAD" || ok=1
record probe "$ok"

ok=0
expect "$CLIENT_LOG" "\] Endpoint: QUIC address discovery answered" \
    "the created endpoint never saw QAD answer" || ok=1
record endpoint "$ok"

ok=0
[[ "$rc" -eq 0 ]] || ok=1
expect "$CLIENT_LOG" "Rebuilt endpoint: QUIC address discovery answered" \
    "the rebuilt endpoint never saw QAD answer" || ok=1
[[ "$(grep -c "Echo OK" "$CLIENT_LOG")" -eq 2 ]] ||
    { note "expected an echo from each endpoint"; ok=1; }
record rebuilt "$ok"
[[ "$RESULT" -eq 0 ]] || dump_log "$CLIENT_LOG"

# ---------------------------------------------------------------------------
# 4. Control: the test CA not trusted
# ---------------------------------------------------------------------------
log "[untrusted] without the test CA, relay1 counts as not serving QAD"
CLIENT_LOG="$WORK/client_untrusted.log"
rc=0
run_client "$CLIENT_LOG" "${BOTH[@]}" || rc=$?
ok=0
[[ "$rc" -eq 0 ]] || { note "client exited with $rc"; ok=1; }
expect "$CLIENT_LOG" "None of the 2 reachable custom relays serves QUIC address discovery" \
    "relay1 counted as serving QAD without its CA" || ok=1
expect "$CLIENT_LOG" "\] Endpoint: QUIC address discovery did not answer" \
    "the created endpoint saw QAD answer without the test CA" || ok=1
expect "$CLIENT_LOG" "Rebuilt endpoint: QUIC address discovery did not answer" \
    "the rebuilt endpoint saw QAD answer without relay1's CA" || ok=1
[[ "$ok" -eq 0 ]] || dump_log "$CLIENT_LOG"
record untrusted "$ok"

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log "[server-alive] FAIL: the server exited"
    dump_log "$SERVER_LOG"
    RESULT=1
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
