#!/usr/bin/env bash
# Prove the native Certainly client against controlled peers, before any
# external conformance suite is trusted to tell us anything.
#
# A rejection test only means something if the same fixture succeeds when
# it should, so each negative case sits next to a positive control, and
# every case checks the outcome the client logged, not just that it failed.
#
#   make -C tests/host conformance-check
#
# Needs: the built client (make -C tests/host conformance-client), OpenSSL
# with `s_server -ciphersuites` (not LibreSSL) and uv. Output goes to
# build/conformance/check-client/; override the root with CONFORMANCE_OUT.

set -o pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${CONFORMANCE_OUT:-$root/build/conformance}
client=$out/certainly_client
fix=$out/fixtures
logs=$out/check-client
openssl=${OPENSSL:-openssl}
name=conformance.test

# Slack beyond a client's own deadline for it to log and clean up.
cleanup_allowance_ms=3000

pass=0
fail=0
pids=()

die() { echo "check-client: $*" >&2; exit 2; }

# ── Prerequisites ──

[ -x "$client" ] || die "client not built: run 'make -C tests/host conformance-client'"
command -v "$openssl" >/dev/null || die "openssl not found (set OPENSSL=...)"
"$openssl" s_server -help 2>&1 | grep -q -- '-ciphersuites' ||
    die "$openssl lacks 's_server -ciphersuites' (LibreSSL?); install OpenSSL 1.1.1 or later and set OPENSSL=..."
command -v uv >/dev/null || die "uv not found (needed for fault_peer.py)"

mkdir -p "$logs"
rm -f "$logs"/*
# Fresh every run, so a stale fixture can never make a result look right.
rm -rf "$fix"
"$here/fixtures/gen.sh" "$fix" || die "fixture generation failed"
vtime=$(cat "$fix/validation_time")

peer() { uv run --no-project --quiet python "$here/fault_peer.py" "$@"; }

cleanup() {
    local p
    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ── Reporting ──

ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() {
    fail=$((fail + 1))
    printf '  FAIL  %s\n' "$1"
    [ -n "$RESULT" ] && printf '        %s\n' "$RESULT"
}

# ── Peers ──

wait_for() {   # wait_for <file> <text> <pid>
    local i
    for i in $(seq 1 100); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        kill -0 "$3" 2>/dev/null || return 1
        sleep 0.05
    done
    return 1
}

# start_tls <tag> <port> <s_server args...>; the server's pid is left in SRV
start_tls() {
    local tag=$1 port=$2
    shift 2
    ( cd "$fix" && exec "$openssl" s_server -accept "$port" "$@" ) \
        >"$logs/$tag.server.log" 2>&1 &
    SRV=$!
    pids+=("$SRV")
    wait_for "$logs/$tag.server.log" ACCEPT "$SRV" ||
        die "s_server for $tag did not start; see $logs/$tag.server.log"
}

# start_peer <tag> <fault_peer args...>
start_peer() {
    local tag=$1
    shift
    peer "$@" >"$logs/$tag.peer.log" 2>&1 &
    SRV=$!
    pids+=("$SRV")
    wait_for "$logs/$tag.peer.log" READY "$SRV" ||
        die "fault_peer for $tag did not start; see $logs/$tag.peer.log"
}

stop() {
    kill "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}

free_port() { peer port; }

# ── Running the client ──

# run <tag> <deadline-ms> <client args...>
# Sets RC, RESULT (the final JSON line) and HUNG. The client enforces its
# own deadline; the wall-clock watchdog here only catches one that does not.
run() {
    local tag=$1 deadline=$2 pid waited=0 limit
    shift 2
    limit=$((deadline + cleanup_allowance_ms))
    LOG=$logs/$tag.client.jsonl
    HUNG=0
    "$client" --attempt "$tag" --log "$LOG" --deadline-ms "$deadline" "$@" &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$limit" ]; then
            kill -9 "$pid" 2>/dev/null
            HUNG=1
            break
        fi
        sleep 0.05
        waited=$((waited + 50))
    done
    wait "$pid"
    RC=$?
    RESULT=$(grep '"event":"result"' "$LOG" 2>/dev/null | tail -1)
}

field() {
    printf '%s' "$RESULT" |
        sed -n "s/.*\"$1\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p"
}

expect_field() {   # expect_field <description> <field> <value>
    local got
    got=$(field "$2")
    if [ "$got" = "$3" ]; then ok "$1"; else bad "$1 ($2=$got, wanted $3)"; fi
}

expect_outcome() {   # expect_outcome <description> <outcome> <exit code>
    if [ "$HUNG" = 1 ]; then bad "$1: client did not terminate"; return; fi
    expect_field "$1 -> $2" outcome "$2"
    [ "$RC" = "$3" ] || bad "$1: exit status $RC, wanted $3"
}

expect_positive() {   # expect_positive <description> [extra field checks]
    expect_outcome "$1" success 0
}

base() {   # base <port> [client args]: trusted destination, fixed time
    local port=$1
    shift
    run_args=(--connect "127.0.0.1:$port" --server-name "$name"
              --ca "$fix/ca.pem" --validation-time "$vtime" "$@")
}

# ── Cases ──

suite_matrix="TLS_CHACHA20_POLY1305_SHA256:0x1303 TLS_AES_128_GCM_SHA256:0x1301"

for entry in $suite_matrix; do
    suite=${entry%%:*}
    code=${entry##*:}
    echo "== valid peer, $suite"
    port=$(free_port)
    start_tls "$suite" "$port" -cert server.pem -key server.key -tls1_3 \
        -ciphersuites "$suite" -rev
    srv=$SRV

    base "$port"
    run "$suite-handshake" 8000 "${run_args[@]}"
    expect_positive "handshake completes"
    expect_field "negotiates TLS 1.3" tls_version 1.3
    expect_field "uses $suite" cipher_suite "$code"
    expect_field "no TLS 1.2 fallback" tls12_fallback_attempted false

    base "$port" --mode data --send "$fix/line.txt" --expect "$fix/line.expected" \
        --out "$logs/$suite-line.out"
    run "$suite-data" 8000 "${run_args[@]}"
    expect_positive "exact payload exchanged"
    expect_field "all reply bytes received" bytes_received "$(wc -c <"$fix/line.expected" | tr -d ' ')"
    cmp -s "$logs/$suite-line.out" "$fix/line.expected" ||
        bad "stored reply differs from the known payload"

    base "$port" --mode data --send "$fix/line.txt" --expect "$fix/line.expected" \
        --read-chunk 1 --write-chunk 1 --wouldblock-every 3
    run "$suite-data-chunked" 15000 "${run_args[@]}"
    expect_positive "exact payload with 1-byte transfers and would-block"
    if [ "$(field wouldblocks_injected)" -gt 0 ] 2>/dev/null; then
        ok "would-block was injected"
    else
        bad "no would-block was injected"
    fi
    stop "$srv"

    echo "== multi-record download, $suite"
    port=$(free_port)
    start_tls "$suite-www" "$port" -cert server.pem -key server.key -tls1_3 \
        -ciphersuites "$suite" -WWW
    srv=$SRV
    printf 'GET /big.txt HTTP/1.0\r\n\r\n' >"$logs/get.txt"
    base "$port" --mode data --send "$logs/get.txt" --recv-until-close \
        --out "$logs/$suite-big.out" --read-chunk 997 --write-chunk 5 \
        --wouldblock-every 5
    run "$suite-download" 30000 "${run_args[@]}"
    expect_positive "download ends with a TLS close"
    size=$(wc -c <"$fix/big.txt" | tr -d ' ')
    if tail -c "$size" "$logs/$suite-big.out" | cmp -s - "$fix/big.txt"; then
        ok "all $size bytes arrive intact across records"
    else
        bad "downloaded bytes differ from big.txt"
    fi
    stop "$srv"
done

echo "== certificate rejection (each beside a control that succeeds)"
port=$(free_port)
start_tls cert "$port" -cert server.pem -key server.key -tls1_3 -rev
srv=$SRV
base "$port"
run cert-control 8000 "${run_args[@]}"
expect_positive "control: trusted chain, right name, valid time"

base "$port"
run_args=("${run_args[@]/$name/wrong.test}")
run cert-wrong-name 8000 "${run_args[@]}"
expect_outcome "wrong server name" certificate-error 11
expect_field "reported as a name mismatch" bearssl_error_name BR_ERR_X509_BAD_SERVER_NAME
expect_field "rejected at the Certificate message" tls13_state RecvCertificate

base "$port"
run_args=("${run_args[@]/$vtime/$((vtime + 11 * 365 * 86400))}")
run cert-expired 8000 "${run_args[@]}"
expect_outcome "validation time after expiry" certificate-error 11
expect_field "reported as expired" bearssl_error_name BR_ERR_X509_EXPIRED

base "$port"
run_args=("${run_args[@]/$vtime/$((vtime - 365 * 86400))}")
run cert-not-yet-valid 8000 "${run_args[@]}"
expect_outcome "validation time before issuance" certificate-error 11
expect_field "reported as outside validity" bearssl_error_name BR_ERR_X509_EXPIRED
stop "$srv"

port=$(free_port)
start_tls other "$port" -cert other-server.pem -key other-server.key -tls1_3 -rev
srv=$SRV
base "$port"
run cert-untrusted 8000 "${run_args[@]}"
expect_outcome "certificate from an untrusted issuer" certificate-error 11
expect_field "reported as not trusted" bearssl_error_name BR_ERR_X509_NOT_TRUSTED
expect_field "rejected at the Certificate message" tls13_state RecvCertificate
base "$port"
run_args=("${run_args[@]/$fix\/ca.pem/$fix/other-ca.pem}")
run cert-untrusted-control 8000 "${run_args[@]}"
expect_positive "control: same server once its issuer is trusted"
stop "$srv"

echo "== entropy is required before any connection"
port=$(free_port)   # nothing listens here
for mode in none fail; do
    base "$port" --entropy "$mode"
    run "entropy-$mode" 8000 "${run_args[@]}"
    expect_outcome "entropy provider '$mode'" entropy-error 21
    expect_field "no socket was opened" connections 0
    expect_field "failed in setup, before connecting" phase setup
done

echo "== transport failures are told apart"
port=$(free_port)   # nothing listens here
base "$port"
run refused 8000 "${run_args[@]}"
expect_outcome "connection refused" connect-error 17
expect_field "never reached the handshake" phase connect

for kind in stall close reset; do
    port=$(free_port)
    start_peer "peer-$kind" "$kind" --port "$port"
    srv=$SRV
    base "$port"
    case $kind in
        stall)
            run "peer-$kind" 1500 "${run_args[@]}"
            expect_outcome "peer accepts and goes silent" timeout 12
            elapsed=$(field t_ms)
            if [ "$elapsed" -ge 1500 ] && [ "$elapsed" -le $((1500 + cleanup_allowance_ms)) ] 2>/dev/null; then
                ok "ended at the deadline (${elapsed} ms)"
            else
                bad "ended after ${elapsed} ms, deadline 1500 ms"
            fi
            ;;
        close)
            run "peer-$kind" 8000 "${run_args[@]}"
            expect_outcome "peer closes before the ServerHello" peer-eof 13
            ;;
        reset)
            run "peer-$kind" 8000 "${run_args[@]}"
            expect_outcome "peer resets before the ServerHello" peer-reset 14
            ;;
    esac
    expect_field "stopped during the handshake" phase handshake
    stop "$srv"
done

for cut in eof reset stall; do
    tls=$(free_port)
    start_tls "cut-$cut" "$tls" -cert server.pem -key server.key -tls1_3 -rev
    tlssrv=$SRV
    port=$(free_port)
    start_peer "proxy-$cut" proxy --port "$port" --upstream "$tls" \
        --cut-after-ms 500 --cut "$cut"
    srv=$SRV
    # No request is sent, so the reply being waited for can never arrive.
    base "$port" --mode data --expect "$fix/line.expected"
    case $cut in
        eof)   run "cut-$cut" 8000 "${run_args[@]}"
               expect_outcome "orderly close after the handshake" peer-eof 13 ;;
        reset) run "cut-$cut" 8000 "${run_args[@]}"
               expect_outcome "reset after the handshake" peer-reset 14 ;;
        stall) run "cut-$cut" 2000 "${run_args[@]}"
               expect_outcome "peer goes silent after the handshake" timeout 12 ;;
    esac
    expect_field "ended in the data phase" phase data
    stop "$srv"
    stop "$tlssrv"
done

echo "== TLS version is checked, not assumed"
port=$(free_port)
start_tls tls12 "$port" -cert server.pem -key server.key -tls1_2 -rev
srv=$SRV
base "$port"
run tls12-strict 8000 "${run_args[@]}"
expect_outcome "TLS 1.2-only peer fails a TLS 1.3 test" tls12-fallback 15
expect_field "fallback reconnected" connections 2
base "$port" --allow-tls12
run tls12-allowed 8000 "${run_args[@]}"
expect_positive "TLS 1.2 accepted when asked for"
expect_field "reported as TLS 1.2" tls_version 1.2
stop "$srv"

echo "== setup problems are not protocol results"
port=$(free_port)
base "$port"
run_args=("${run_args[@]/$fix\/ca.pem/$logs/missing.pem}")
run missing-ca 8000 "${run_args[@]}"
expect_outcome "trust anchor file missing" setup-error 22
expect_field "no socket was opened" connections 0

for n in 0 1 2; do
    base "$port" --alloc-fail-after "$n"
    run "alloc-$n" 8000 "${run_args[@]}"
    expect_outcome "allocation $n fails" memory-error 23
    expect_field "no socket was opened" connections 0
done

"$client" >/dev/null 2>&1
[ $? -eq 20 ] && ok "usage error exits 20" || bad "usage error exit status"

echo
echo "check-client: $pass passed, $fail failed (logs in $logs)"
[ "$fail" -eq 0 ]
