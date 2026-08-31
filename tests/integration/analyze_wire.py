#!/usr/bin/env python3
"""Check post-authentication wire markers without decoding credentials or keys."""

import argparse
import json
import struct
import sys


ENDPOINTS = {
    5911: {"name": "RA2", "encrypted": True, "size": (1280, 720), "server_marker": b"OpsKat RA2 AES-128"},
    5912: {"name": "RA2ne", "encrypted": False, "size": (1280, 720), "server_marker": b"OpsKat RA2ne Auth-only AES-128"},
    5913: {"name": "RA2_256", "encrypted": True, "size": (1280, 720), "server_marker": b"OpsKat RA2 AES-256"},
    5914: {"name": "RA2ne_256", "encrypted": False, "size": (1280, 720), "server_marker": b"OpsKat RA2ne Auth-only AES-256"},
    5915: {"name": "VNCAuth", "encrypted": False, "size": (1280, 720), "server_marker": b"OpsKat legacy VNCAuth baseline"},
    5916: {"name": "RA2r", "encrypted": True, "size": (16, 2), "server_marker": b"OPSKAT_FRAME_RA2R"},
    5917: {"name": "RA2r_256", "encrypted": True, "size": (16, 2), "server_marker": b"OPSKAT_FRAME_RA2R_256"},
}
KEY_DOWN_MARKER = b"\x04\x01\x00\x00\x00\x00\x00\x78"
KEY_UP_MARKER = b"\x04\x00\x00\x00\x00\x00\x00\x78"


def iter_packets(path):
    with open(path, "rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("short pcap header")
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("pcap (not pcapng) input required")
        link_type = struct.unpack(endian + "I", header[20:24])[0]
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("short packet header")
            captured = struct.unpack(endian + "IIII", packet_header)[2]
            packet = stream.read(captured)
            if len(packet) != captured:
                raise ValueError("short packet data")
            yield link_type, packet


def tcp_payload(link_type, packet):
    if link_type == 1:  # Ethernet
        if len(packet) < 14:
            return None
        protocol = struct.unpack(">H", packet[12:14])[0]
        offset = 14
        while protocol in (0x8100, 0x88A8):
            if len(packet) < offset + 4:
                return None
            protocol = struct.unpack(">H", packet[offset + 2:offset + 4])[0]
            offset += 4
    elif link_type == 113:  # Linux cooked v1
        if len(packet) < 16:
            return None
        protocol = struct.unpack(">H", packet[14:16])[0]
        offset = 16
    elif link_type == 276:  # Linux cooked v2
        if len(packet) < 20:
            return None
        protocol = struct.unpack(">H", packet[0:2])[0]
        offset = 20
    else:
        raise ValueError(f"unsupported pcap link type {link_type}")

    if protocol != 0x0800 or len(packet) < offset + 20:  # IPv4 only
        return None
    ip_header = packet[offset:]
    ip_length = (ip_header[0] & 0x0F) * 4
    if ip_header[9] != 6 or len(ip_header) < ip_length + 20:
        return None
    tcp = ip_header[ip_length:]
    tcp_length = ((tcp[12] >> 4) & 0x0F) * 4
    if len(tcp) < tcp_length:
        return None
    source, destination = struct.unpack(">HH", tcp[:4])
    return source, destination, tcp[tcp_length:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--output")
    args = parser.parse_args()

    streams = {port: {"client": bytearray(), "server": bytearray()} for port in ENDPOINTS}
    for link_type, packet in iter_packets(args.pcap):
        parsed = tcp_payload(link_type, packet)
        if parsed is None:
            continue
        source, destination, payload = parsed
        if source in streams:
            streams[source]["server"].extend(payload)
        if destination in streams:
            streams[destination]["client"].extend(payload)

    results = []
    failed = False
    for port, endpoint in ENDPOINTS.items():
        client = bytes(streams[port]["client"])
        server = bytes(streams[port]["server"])
        clipboard_prefix = f"OPSKAT_CLIENT_CLIPBOARD_{port}_".encode("ascii")
        width, height = endpoint["size"]
        framebuffer_request = bytes((3, 0)) + struct.pack(">HHHH", 0, 0, width, height)
        observations = {
            "port": port,
            "name": endpoint["name"],
            "sessionEncrypted": endpoint["encrypted"],
            "serverPostAuthMarkerVisible": endpoint["server_marker"] in server,
            "clientFramebufferRequestVisible": framebuffer_request in client,
            "clientClipboardMarkerVisible": clipboard_prefix in client,
            "clientKeyboardMarkerVisible": KEY_DOWN_MARKER in client and KEY_UP_MARKER in client,
            "capturedClientBytes": len(client),
            "capturedServerBytes": len(server),
        }
        expected_visible = not endpoint["encrypted"]
        observations["verdict"] = "pass" if all(
            observations[key] == expected_visible
            for key in (
                "serverPostAuthMarkerVisible",
                "clientFramebufferRequestVisible",
                "clientClipboardMarkerVisible",
                "clientKeyboardMarkerVisible",
            )
        ) else "fail"
        failed |= observations["verdict"] != "pass"
        results.append(observations)

    report = {"capture": args.pcap, "endpoints": results, "credentialsInspected": False}
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    print(encoded, end="")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
