#!/usr/bin/env python3
"""Misbehaving TCP peers for the native client checks.

Each mode serves exactly one connection on 127.0.0.1 and exits, or gives up
after --lifetime-s so a failed run cannot leave it behind. It prints READY
once it is listening.

  stall    accept and say nothing, ever
  close    accept, then close at once (orderly FIN before any TLS)
  reset    accept, then abort with RST
  proxy    relay to a real TLS server, then after --cut-after-ms end the
           connection with an orderly close (eof), an abort (reset) or by
           going silent (stall)
  port     print a free port and exit
"""

import argparse
import select
import socket
import struct
import sys
import time


def listener(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s


def abort(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def accept(srv, deadline):
    print("READY", flush=True)
    srv.settimeout(max(0.1, deadline - time.monotonic()))
    conn, _ = srv.accept()
    return conn


def await_client_hello(conn):
    conn.settimeout(2)
    try:
        conn.recv(65536)
    except socket.timeout:
        pass


def relay(client, upstream, until, how, deadline):
    while time.monotonic() < until:
        ready, _, _ = select.select([client, upstream], [], [], 0.02)
        for src in ready:
            dst = upstream if src is client else client
            data = src.recv(65536)
            if not data:
                return
            dst.sendall(data)
    if how == "eof":
        client.shutdown(socket.SHUT_WR)
        client.close()
    elif how == "reset":
        abort(client)
    else:
        while time.monotonic() < deadline:
            time.sleep(0.05)
    upstream.close()


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("mode", choices=["stall", "close", "reset", "proxy", "port"])
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--upstream", type=int)
    p.add_argument("--cut-after-ms", type=int, default=300)
    p.add_argument("--cut", choices=["eof", "reset", "stall"], default="eof")
    p.add_argument("--lifetime-s", type=float, default=20)
    a = p.parse_args()

    if a.mode == "port":
        s = listener(0)
        print(s.getsockname()[1])
        return 0

    deadline = time.monotonic() + a.lifetime_s
    srv = listener(a.port)
    try:
        conn = accept(srv, deadline)
    except socket.timeout:
        return 1

    if a.mode == "stall":
        while time.monotonic() < deadline:
            time.sleep(0.05)
    elif a.mode == "close":
        # Read the ClientHello first: closing with unread data makes the OS
        # send RST instead of the orderly FIN this mode is for.
        await_client_hello(conn)
        conn.shutdown(socket.SHUT_WR)
        conn.close()
    elif a.mode == "reset":
        # Wait for the ClientHello so the reset lands in the handshake, not
        # in the middle of the client's TCP connect.
        await_client_hello(conn)
        abort(conn)
    else:
        up = socket.create_connection(("127.0.0.1", a.upstream))
        relay(conn, up, time.monotonic() + a.cut_after_ms / 1000.0, a.cut,
              deadline)
    return 0


if __name__ == "__main__":
    sys.exit(main())
