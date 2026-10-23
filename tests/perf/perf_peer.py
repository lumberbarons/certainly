#!/usr/bin/env python3
"""TLS 1.3 peer for the Certainly performance harness.

Serves connections one at a time on 127.0.0.1 until killed. The client names
the workload on its first line, so one peer covers every scenario and the
record size is chosen per connection:

  GET <bytes> <chunk>   send <bytes> of a fixed pattern, one write of at most
                        <chunk> bytes at a time. Each write becomes one TLS
                        record, so <chunk> sets the record size.
  PUT <bytes>           read <bytes> from the client, then answer "OK\\n".
  NOP                   close at once (handshake-only runs).

The pattern is byte i == i % 251, which the client can check without
sharing a file. Prints "READY <port>" once listening, then one JSON line per
connection with the negotiated version and suite.
"""

import argparse
import json
import socket
import ssl
import sys

PATTERN_MOD = 251


def pattern(offset, n):
    base = bytes(range(PATTERN_MOD))
    start = offset % PATTERN_MOD
    reps = (start + n) // PATTERN_MOD + 2
    return (base * reps)[start:start + n]


def read_line(conn):
    line = bytearray()
    while not line.endswith(b"\n"):
        b = conn.recv(1)
        if not b:
            break
        line += b
        if len(line) > 256:
            break
    return line.decode("ascii", "replace").strip()


def serve_get(conn, total, chunk):
    sent = 0
    while sent < total:
        n = min(chunk, total - sent)
        conn.sendall(pattern(sent, n))
        sent += n


def serve_put(conn, total):
    got = 0
    while got < total:
        data = conn.recv(min(65536, total - got))
        if not data:
            return got
        got += len(data)
    conn.sendall(b"OK\n")
    return got


def handle(conn):
    info = {"event": "connection", "version": conn.version(),
            "cipher": conn.cipher()[0] if conn.cipher() else None}
    cmd = read_line(conn).split()
    info["command"] = cmd
    if cmd[:1] == ["GET"] and len(cmd) == 3:
        serve_get(conn, int(cmd[1]), max(1, int(cmd[2])))
    elif cmd[:1] == ["PUT"] and len(cmd) == 2:
        info["received"] = serve_put(conn, int(cmd[1]))
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # Take the client's first choice, so every revision of the library is
    # measured on the suite it prefers rather than on the server's favourite
    # (AES-256-GCM, which some revisions advertise but cannot complete).
    ctx.options &= ~ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.load_cert_chain(args.cert, args.key)

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(8)
    print("READY %d" % srv.getsockname()[1], flush=True)

    while True:
        raw, _ = srv.accept()
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            with ctx.wrap_socket(raw, server_side=True) as conn:
                info = handle(conn)
        except (OSError, ssl.SSLError) as e:
            info = {"event": "connection", "error": str(e)}
        finally:
            raw.close()
        print(json.dumps(info), flush=True)


if __name__ == "__main__":
    sys.exit(main())
