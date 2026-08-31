#!/usr/bin/env python3
"""Fail-fast availability check for the deterministic RSA-AES lab endpoints."""

import argparse
import json
import socket
import sys
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Endpoint:
    port: int
    name: str
    security_type: int
    session_encrypted: bool
    implementation: str


ENDPOINTS = (
    Endpoint(5911, "RA2", 5, True, "TigerVNC 1.16.2"),
    Endpoint(5912, "RA2ne", 6, False, "TigerVNC 1.16.2"),
    Endpoint(5913, "RA2_256", 129, True, "TigerVNC 1.16.2"),
    Endpoint(5914, "RA2ne_256", 130, False, "TigerVNC 1.16.2"),
    Endpoint(5915, "VNCAuth", 2, False, "TigerVNC 1.16.2"),
    Endpoint(5916, "RA2r", 13, True, "independent Python oracle"),
    Endpoint(5917, "RA2r_256", 133, True, "independent Python oracle"),
)


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError(f"short read: wanted {size}, got {len(result)}")
        result.extend(chunk)
    return bytes(result)


def probe(host, endpoint, timeout):
    with socket.create_connection((host, endpoint.port), timeout=timeout) as sock:
        banner = read_exact(sock, 12)
        if banner != b"RFB 003.008\n":
            raise RuntimeError(f"unexpected banner {banner!r}")
        sock.sendall(b"RFB 003.008\n")
        count = read_exact(sock, 1)[0]
        if count == 0:
            raise RuntimeError("server rejected protocol negotiation")
        offered = list(read_exact(sock, count))
        if offered != [endpoint.security_type]:
            raise RuntimeError(
                f"expected security [{endpoint.security_type}], received {offered}"
            )
        return {
            **asdict(endpoint),
            "host": host,
            "banner": banner.decode("ascii").strip(),
            "offered": offered,
            "status": "available",
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    results = []
    failed = False
    for endpoint in ENDPOINTS:
        try:
            results.append(probe(args.host, endpoint, args.timeout))
        except Exception as exc:  # availability diagnostics belong in the result
            failed = True
            results.append({
                **asdict(endpoint),
                "host": args.host,
                "status": "error",
                "error": str(exc),
            })

    print(json.dumps({"endpoints": results}, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
