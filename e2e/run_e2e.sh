#!/usr/bin/env bash
#
# Authentication and connectivity end-to-end test for flexaccess-iroh.
#
# Runs the e2e harness (examples/e2e) as a server and several clients through
# real relays and checks, in order:
#
#   1. a client whose key is not in the server's authorized keys is refused:
#      it exits with the auth status (3), sees the explicit rejection, never
#      authenticates, and the server logs why
#   2. an authorized client connects, proves its key (the endpoint-bound
#      transcript of flexaccess_iroh::auth), and gets its message echoed
#   3. a second client with the SAME key does the same from a DISTINCT
#      ephemeral iroh identity (the auth key is the credential, never the
#      endpoint id)
#   4. under --relay-only, every client connection ran through a relay
#
# With no options the default relays and n0 discovery are used (needs
# internet). Custom relays turn internet discovery off and need no public
# infrastructure; --local-relays starts two iroh-relay instances here so the
# whole run is offline.
#
# Usage:
#   ./e2e/run_e2e.sh                                   # default relays (internet)
#   ./e2e/run_e2e.sh --local-relays                    # two local relays, offline
#   ./e2e/run_e2e.sh --local-relays --relay-only       # ... relay paths only
#   ./e2e/run_e2e.sh --relay-url URL --relay-url URL   # your own relays
#
# Environment: E2E_BIN, IROH_RELAY_BIN, KEEP_LOGS, READY_TIMEOUT (see lib.sh);
# RELAY_URL is a whitespace-separated fallback for --relay-url.
#
set -euo pipefail

declare -a RELAY_URLS=()
RELAY_ONLY=0
LOCAL_RELAYS=0

usage() {
    cat <<'USAGE'
Usage: run_e2e.sh [OPTIONS]

Options:
  --relay-url URL   Custom relay URL for both sides (repeatable; at least two,
                    a single custom relay is rejected). May be --relay-url=URL.
  --local-relays    Start two local iroh-relay instances and use them.
  --relay-only      Reach the server only through the relays (no direct
                    paths). Requires custom relays.
  -h, --help        Show this help and exit.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --relay-url)
            shift
            [[ $# -gt 0 ]] || { echo "ERROR: --relay-url requires a value" >&2; exit 2; }
            RELAY_URLS+=("$1")
            ;;
        --relay-url=*) RELAY_URLS+=("${1#*=}") ;;
        --local-relays) LOCAL_RELAYS=1 ;;
        --relay-only) RELAY_ONLY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ ${#RELAY_URLS[@]} -eq 0 && -n "${RELAY_URL:-}" ]]; then
    read -r -a RELAY_URLS <<<"$RELAY_URL"
fi
if [[ "$LOCAL_RELAYS" == 1 && ${#RELAY_URLS[@]} -gt 0 ]]; then
    echo "ERROR: --local-relays and --relay-url are exclusive" >&2
    exit 2
fi
if [[ ${#RELAY_URLS[@]} -eq 1 ]]; then
    echo "ERROR: custom relays need at least two --relay-url values" >&2
    exit 2
fi
if [[ "$RELAY_ONLY" == 1 && "$LOCAL_RELAYS" == 0 && ${#RELAY_URLS[@]} -eq 0 ]]; then
    echo "ERROR: --relay-only requires custom relays (--relay-url or --local-relays)" >&2
    exit 2
fi

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---------------------------------------------------------------------------
# Relays
# ---------------------------------------------------------------------------
if [[ "$LOCAL_RELAYS" == 1 ]]; then
    require_iroh_relay
    mapfile -t PORTS < <(pick_ports 2)
    RELAY1_PORT="${PORTS[0]}"
    RELAY2_PORT="${PORTS[1]}"
    define_relay 1 "$RELAY1_PORT"
    define_relay 2 "$RELAY2_PORT"
    log "Starting two local relays..."
    start_relay 1
    start_relay 2
    RELAY_URLS=("http://127.0.0.1:$RELAY1_PORT" "http://127.0.0.1:$RELAY2_PORT")
fi

declare -a RELAY_ARGS=()
for url in "${RELAY_URLS[@]:-}"; do
    [[ -n "$url" ]] && RELAY_ARGS+=(--relay-url "$url")
done
if [[ "$RELAY_ONLY" == 1 ]]; then
    RELAY_ARGS+=(--relay-only)
fi
if [[ ${#RELAY_URLS[@]} -gt 0 ]]; then
    log "Using custom relays (internet discovery off): ${RELAY_URLS[*]}"
else
    log "Using the default relays and n0 discovery (needs internet)"
fi
[[ "$RELAY_ONLY" == 1 ]] && log "Relay-only: no direct paths"

# ---------------------------------------------------------------------------
# Keys and identity
# ---------------------------------------------------------------------------
keygen "e2e client" "$WORK/client.key" "$WORK/authorized_keys"
keygen "unlisted e2e client" "$WORK/unlisted.key"
SECRET="$(new_server_secret)"

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
SERVER_LOG="$WORK/server.log"
log "Starting the server..."
E2E_SERVER_SECRET="$SECRET" start_bg "$SERVER_LOG" \
    "$BIN" server --authorized-keys "$WORK/authorized_keys" ${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"}
SERVER_PID="$BG_PID"
unset SECRET
wait_for_log_or_death "$SERVER_PID" "$SERVER_LOG" "Waiting for clients to connect" "$READY_TIMEOUT" || {
    dump_log "$SERVER_LOG"
    die "the server did not come up"
}
SERVER_ID="$(server_endpoint_id "$SERVER_LOG")"
[[ -n "$SERVER_ID" ]] || die "the server did not log its EndpointId"
log "Server EndpointId: $SERVER_ID"

# Run one client to completion. Args: <logfile> <private_key_file> <message>.
# Returns the client's exit status.
run_client() {
    local logfile="$1" key="$2" message="$3" rc=0
    "$BIN" client --server-id "$SERVER_ID" --private-key-file "$key" \
        --message "$message" ${RELAY_ARGS[@]+"${RELAY_ARGS[@]}"} >"$logfile" 2>&1 || rc=$?
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

# ---------------------------------------------------------------------------
# 1. An unlisted key is rejected
# ---------------------------------------------------------------------------
log "[unlisted-key] a key missing from authorized_keys is rejected"
rc=0
run_client "$WORK/client_unlisted.log" "$WORK/unlisted.key" "should-not-echo" || rc=$?
ok=0
if [[ "$rc" -ne 3 ]]; then
    note "client exited with $rc instead of auth status 3"; ok=1
fi
if ! grep -q "Authentication rejected: Invalid authentication proof" "$WORK/client_unlisted.log"; then
    note "client did not receive the explicit rejection"; ok=1
fi
if grep -q "Authenticated as" "$WORK/client_unlisted.log"; then
    note "client with an unlisted key authenticated"; ok=1
fi
if ! grep -Eq "Rejected client [0-9a-f]+: key ed25519-pub:[A-Za-z0-9_-]+ is not authorized" "$SERVER_LOG"; then
    note "server did not log the unauthorized key"; ok=1
fi
[[ "$ok" -eq 0 ]] || dump_log "$WORK/client_unlisted.log"
record unlisted-key "$ok"

# ---------------------------------------------------------------------------
# 2./3. Two clients on the same key, distinct ephemeral identities
# ---------------------------------------------------------------------------
log "[echo] an authorized client authenticates and gets its message echoed"
ok=0
run_client "$WORK/client_1.log" "$WORK/client.key" "hello-1-$(date +%s%N)" || {
    note "first client failed (rc=$?)"; ok=1
}
grep -q "Echo OK" "$WORK/client_1.log" || { note "first client reported no echo"; ok=1; }
[[ "$ok" -eq 0 ]] || dump_log "$WORK/client_1.log"
record echo "$ok"

log "[shared-key] a second client with the same key uses a distinct ephemeral identity"
ok=0
run_client "$WORK/client_2.log" "$WORK/client.key" "hello-2-$(date +%s%N)" || {
    note "second client failed (rc=$?)"; ok=1
}
grep -q "Echo OK" "$WORK/client_2.log" || { note "second client reported no echo"; ok=1; }
mapfile -t AUTHENTICATED_IDS < <(
    sed -nE 's/.*Client ([0-9a-f]+) authenticated successfully as e2e client.*/\1/p' \
        "$SERVER_LOG" | sort -u
)
if (( ${#AUTHENTICATED_IDS[@]} < 2 )); then
    note "server saw ${#AUTHENTICATED_IDS[@]} distinct client identities, expected 2"; ok=1
fi
[[ "$ok" -eq 0 ]] || { dump_log "$WORK/client_2.log"; dump_log "$SERVER_LOG"; }
record shared-key "$ok"

# ---------------------------------------------------------------------------
# 4. Relay-only really went through a relay
# ---------------------------------------------------------------------------
if [[ "$RELAY_ONLY" == 1 ]]; then
    log "[relay-path] relay-only connections use a relay path"
    ok=0
    for logfile in "$WORK/client_1.log" "$WORK/client_2.log"; do
        if ! grep -Eq "Connected to [0-9a-f]+ via Relay " "$logfile"; then
            note "$(basename "$logfile") did not connect via a relay"; ok=1
        fi
        if grep -Eq "via .*Direct " "$logfile"; then
            note "$(basename "$logfile") used a direct path under --relay-only"; ok=1
        fi
    done
    record relay-path "$ok"
fi

# The server must still be up after all of that.
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log "[server-alive] FAIL: the server exited"
    dump_log "$SERVER_LOG"
    RESULT=1
fi

echo
log "Auth + connectivity e2e summary:"
for line in "${SUMMARY[@]}"; do note "$line"; done
if [[ "$RESULT" -eq 0 ]]; then
    log "E2E RESULT: ALL PASS ✅"
else
    log "E2E RESULT: FAILURES ❌ (re-run with KEEP_LOGS=1 to inspect $WORK)"
fi
exit "$RESULT"
