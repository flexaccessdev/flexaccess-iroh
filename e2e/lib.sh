# Sourced by the e2e scripts: the harness binary, process management, log
# waits, ports, keys, and local iroh-relay instances.
#
# Requirements: bash, cargo (to build the harness), and iroh-relay for the
# suites that run relays locally (`cargo install iroh-relay --features server`).
#
# Environment overrides honored by every suite:
#   E2E_BIN         path to a built harness (default: cargo builds examples/e2e)
#   IROH_RELAY_BIN  path to the iroh-relay binary (default: iroh-relay on PATH)
#   KEEP_LOGS       set to 1 to keep the working directory after the run
#   READY_TIMEOUT   seconds to wait for each process to become ready (default 60)

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$E2E_DIR/.." && pwd)"
READY_TIMEOUT="${READY_TIMEOUT:-60}"

log()  { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# The harness binary
# ---------------------------------------------------------------------------
if [[ -n "${E2E_BIN:-}" ]]; then
    BIN="$E2E_BIN"
else
    # Always rebuild: cargo is a no-op when the harness is current, and a stale
    # binary would test the wrong crate.
    log "Building the e2e harness (cargo build --example e2e)..."
    (cd "$REPO_DIR" && cargo build -q --example e2e) || die "building the e2e harness failed"
    BIN="$REPO_DIR/target/debug/examples/e2e"
fi
[[ -x "$BIN" ]] || die "e2e harness not found at $BIN"

require_iroh_relay() {
    RELAY_BIN="${IROH_RELAY_BIN:-$(command -v iroh-relay || true)}"
    [[ -n "$RELAY_BIN" && -x "$RELAY_BIN" ]] ||
        die "iroh-relay not found. Install with: cargo install iroh-relay --features server"
}

# ---------------------------------------------------------------------------
# Working directory + process management
# ---------------------------------------------------------------------------
WORK="$(mktemp -d)"
declare -a PIDS=()

cleanup() {
    local status=$?
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] || continue
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [[ "${KEEP_LOGS:-0}" == "1" ]]; then
        echo "==> Logs kept in $WORK"
    else
        rm -rf "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

# Start a background process, in its own session where setsid exists so the
# whole process group can be killed. Args: <logfile> <command...>. Records
# the PID in PIDS and BG_PID.
start_bg() {
    local logfile="$1"; shift
    if command -v setsid >/dev/null 2>&1; then
        setsid "$@" >"$logfile" 2>&1 &
    else
        "$@" >"$logfile" 2>&1 &
    fi
    BG_PID=$!
    PIDS+=("$BG_PID")
}

kill_pid() {
    local pid="$1"
    [[ -n "$pid" ]] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    # Reap so a port is really free before a restart.
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

# Wait until $1 (a log file) contains the regex $2, or time out after $3 secs.
wait_for_log() {
    local logfile="$1" pattern="$2" timeout="$3"
    local max_attempts=$(( timeout * 2 )) attempt=0
    while (( attempt < max_attempts )); do
        if [[ -f "$logfile" ]] && grep -Eq "$pattern" "$logfile"; then
            return 0
        fi
        sleep 0.5
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# Like wait_for_log, but gives up early (rc 2) if process $1 exits first.
wait_for_log_or_death() {
    local pid="$1" logfile="$2" pattern="$3" timeout="$4"
    local max_attempts=$(( timeout * 2 )) attempt=0
    while (( attempt < max_attempts )); do
        if [[ -f "$logfile" ]] && grep -Eq "$pattern" "$logfile"; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            # One last look: the pattern may have landed just before exit.
            grep -Eq "$pattern" "$logfile" 2>/dev/null && return 0
            return 2
        fi
        sleep 0.5
        attempt=$(( attempt + 1 ))
    done
    return 1
}

# Wait until something accepts TCP connections on 127.0.0.1:$1, or time out
# after $2 seconds.
wait_for_tcp_port() {
    local port="$1" timeout="$2"
    local deadline=$(( SECONDS + timeout ))
    while (( SECONDS < deadline )); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

dump_log() {
    echo "----- $1 -----" >&2
    cat "$1" >&2 || true
}

# ---------------------------------------------------------------------------
# Ports, keys, identities
# ---------------------------------------------------------------------------

# Print $1 distinct free localhost ports, one per line.
pick_ports() {
    "$BIN" pick-port --count "$1"
}

# A fresh server identity: any 32 bytes are an Ed25519 seed. The harness
# logs the matching EndpointId at startup (see server_endpoint_id).
new_server_secret() {
    head -c 32 /dev/urandom | base64 | tr -d '\n'
}

# The EndpointId a server logged at startup.
server_endpoint_id() {
    sed -nE 's/.*EndpointId: ([0-9a-f]+).*/\1/p' "$1" | head -1
}

# Write a client key named $1 to $2 and append its entry to $3 (optional).
keygen() {
    local comment="$1" private_key_file="$2" authorized_keys="${3:-}"
    if [[ -n "$authorized_keys" ]]; then
        "$BIN" keygen "$comment" --private-key-file "$private_key_file" \
            --authorized-keys "$authorized_keys" >/dev/null
    else
        "$BIN" keygen "$comment" --private-key-file "$private_key_file" >/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Local iroh-relay instances (dev mode, plain HTTP; configs hold no secrets)
# ---------------------------------------------------------------------------
declare -A RELAY_PORT=()
declare -A RELAY_PID=()

# Register relay $1 on port $2 and write its config.
define_relay() {
    local num="$1" port="$2"
    RELAY_PORT[$num]="$port"
    cat > "$WORK/relay$num.toml" <<EOF
enable_metrics = false
http_bind_addr = "127.0.0.1:$port"
EOF
}

start_relay() {
    local num="$1" port="${RELAY_PORT[$1]}"
    local logfile="$WORK/relay$num.$(date +%s%N).log"
    start_bg "$logfile" "$RELAY_BIN" --dev -c "$WORK/relay$num.toml"
    RELAY_PID[$num]="$BG_PID"
    wait_for_tcp_port "$port" 30 || {
        dump_log "$logfile"
        die "relay$num did not start"
    }
    note "relay$num up (pid ${RELAY_PID[$num]}, port $port)"
}

stop_relay() {
    local num="$1"
    kill_pid "${RELAY_PID[$num]:-}"
    RELAY_PID[$num]=""
    note "relay$num stopped"
}
