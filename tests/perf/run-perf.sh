#!/usr/bin/env bash
# Run the performance workloads against one revision of the library and
# write one JSON line per trial to build/perf/<label>/results.jsonl.
#
#   tests/perf/run-perf.sh [--label NAME] [--tree DIR] [--trials N] [--quick]
#
# --tree names a checkout whose src/ and include/ are measured (default:
# this repository), so an older revision can be run through the same client,
# peer and workloads. Compare two result files with compare.py.
#
# Needs: OpenSSL (to mint throwaway certificates), uv, a C compiler, make.

set -o pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
label=current
tree=$root
trials=3
quick=0
openssl=${OPENSSL:-openssl}

while [ $# -gt 0 ]; do
    case $1 in
        --label)  label=$2; shift 2 ;;
        --tree)   tree=$(cd "$2" && pwd); shift 2 ;;
        --trials) trials=$2; shift 2 ;;
        --quick)  quick=1; trials=1; shift ;;
        *) echo "run-perf: unknown option $1" >&2; exit 2 ;;
    esac
done

die() { echo "run-perf: $*" >&2; exit 2; }

command -v "$openssl" >/dev/null || die "openssl not found (set OPENSSL=...)"
command -v uv >/dev/null || die "uv not found (needed for perf_peer.py)"

out=$root/build/perf/$label
fix=$root/build/perf/fixtures
client=$out/perf_client
results=$out/results.jsonl
mkdir -p "$out"

echo "== building $label from $tree"
make -s -C "$root/tests/host" perf-client PERF_TREE="$tree" PERF_LABEL="$label" \
    >"$out/build.log" 2>&1 || { cat "$out/build.log" >&2; die "build failed"; }

# ── Throwaway certificates ──
#
# The name is the IP literal the client connects to: the host transport
# resolves only literals, and BearSSL matches it against the subject CN
# when there is no subjectAltName.
if [ ! -f "$fix/server.pem" ]; then
    mkdir -p "$fix"
    (
        cd "$fix" || exit 1
        "$openssl" ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
        "$openssl" req -new -x509 -key ca.key -sha256 -days 3650 \
            -subj "/CN=Certainly Perf CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
        "$openssl" ecparam -name prime256v1 -genkey -noout -out server.key 2>/dev/null
        "$openssl" req -new -key server.key -subj "/CN=127.0.0.1" -out server.csr
        printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' >leaf.ext
        "$openssl" x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
            -CAcreateserial -days 3650 -sha256 -extfile leaf.ext \
            -out server.pem 2>/dev/null
        rm -f server.csr leaf.ext ./*.srl
    ) || die "fixture generation failed"
fi

# ── Peer ──
peer_log=$out/peer.log
uv run --no-project --quiet python "$here/perf_peer.py" \
    --cert "$fix/server.pem" --key "$fix/server.key" >"$peer_log" 2>&1 &
peer_pid=$!
trap 'kill $peer_pid 2>/dev/null; wait $peer_pid 2>/dev/null' EXIT

port=
for _ in $(seq 1 100); do
    port=$(sed -n 's/^READY //p' "$peer_log")
    [ -n "$port" ] && break
    kill -0 $peer_pid 2>/dev/null || die "peer exited; see $peer_log"
    sleep 0.05
done
[ -n "$port" ] || die "peer did not start; see $peer_log"

# ── Workloads ──
: >"$results"
failures=0

run() {   # run <scenario> <client args...>
    local name=$1 t line rc
    shift
    for t in $(seq 1 "$trials"); do
        line=$("$client" --port "$port" --ca "$fix/ca.pem" "$@")
        rc=$?
        if [ -z "$line" ]; then
            echo "  FAIL  $name (no result, exit $rc)"
            failures=$((failures + 1))
            continue
        fi
        printf '%s\n' "$line" |
            sed "s/^{/{\"scenario\":\"$name\",\"trial\":$t,/" >>"$results"
        if [ $rc -ne 0 ]; then
            echo "  FAIL  $name: $(printf '%s' "$line" | sed -n 's/.*"failure":"\([^"]*\)".*"library":"\([^"]*\)".*/\1 (\2)/p')"
            failures=$((failures + 1))
        fi
    done
    echo "  done  $name"
}

KB=1024
MB=$((1024 * 1024))
big=$((4 * MB))
mid=$((1 * MB))
if [ $quick = 1 ]; then big=$((512 * KB)); mid=$((256 * KB)); fi

echo "== workloads ($trials trial(s) each)"

# Correctness first: a fast run that corrupts data must not look like a win.
run verify-get --mode get --bytes $mid --chunk 16384 --verify
run verify-put --mode put --bytes $mid

run handshake --mode handshake --repeat 10

# Whole records, a typical application read size.
run get-full-records --mode get --bytes $big --chunk 16384 --read-buf 4096
run get-big-read-buf --mode get --bytes $big --chunk 16384 --read-buf 65536
run get-tiny-read-buf --mode get --bytes $mid --chunk 16384 --read-buf 256

# Many small records in flight: what streaming and chunked servers produce.
run get-records-4096 --mode get --bytes $mid --chunk 4096
run get-records-512  --mode get --bytes $mid --chunk 512
run get-records-64   --mode get --bytes $mid --chunk 64

# TCP segments smaller than records, and a transport that stalls.
run get-mtu-segments  --mode get --bytes $mid --chunk 16384 --read-chunk 1460
run get-wouldblock    --mode get --bytes $mid --chunk 16384 --read-chunk 1460 --wouldblock-every 3

# Does cost per byte stay flat as the transfer grows?
for kb in 64 256 1024 4096; do
    if [ $quick = 1 ] && [ $kb -gt 1024 ]; then continue; fi
    run "scale-get-${kb}k" --mode get --bytes $((kb * KB)) --chunk 16384
done

# Upload.
run put-full-records  --mode put --bytes $big --write-buf 16384
run put-app-writes    --mode put --bytes $mid --write-buf 4096
run put-small-writes  --mode put --bytes $((mid / 4)) --write-buf 64
run put-mtu-segments  --mode put --bytes $mid --write-buf 16384 --write-chunk 1460

echo "== results: $results ($failures failure(s))"
[ $failures -eq 0 ]
