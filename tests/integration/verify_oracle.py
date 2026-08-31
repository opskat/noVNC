#!/usr/bin/env python3
"""Verify sanitized RA2r oracle events from the live interoperability lab."""

import argparse
import json
import sys


VARIANTS = {
    "RA2r": {"security_type": 13, "random_bytes": 16},
    "RA2r_256": {"security_type": 133, "random_bytes": 32},
}


def read_sessions(path, variant):
    sessions = {}
    order = []
    legacy = []
    with open(path, encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if event.get("variant") != variant:
                continue
            connection_id = event.get("connection_id")
            if connection_id is not None:
                if connection_id not in sessions:
                    sessions[connection_id] = []
                    order.append(connection_id)
                sessions[connection_id].append(event)
            elif event.get("event") == "connection":
                legacy.append([event])
            elif legacy:
                legacy[-1].append(event)
    return legacy + [sessions[connection_id] for connection_id in order]


def event_named(session, name):
    return [event for event in session if event.get("event") == name]


def verify_session(session, variant):
    expected = VARIANTS[variant]
    replacements = event_named(session, "replacement_ciphers")
    security_results = event_named(session, "security_result_and_client_init")
    server_inits = event_named(session, "server_init_sent")
    framebuffers = event_named(session, "framebuffer_sent")
    keyboards = event_named(session, "keyboard")
    pointers = event_named(session, "pointer")
    clipboards = event_named(session, "clipboard")
    flows = event_named(session, "flow_complete")

    replacement = replacements[-1] if replacements else {}
    security_result = security_results[-1] if security_results else {}
    flow = flows[-1] if flows else {}
    checks = {
        "credentialsAccepted": bool(event_named(session, "credentials_accepted")),
        "secondRandomExchange": replacement.get("random_bytes") == expected["random_bytes"],
        "replacementCounterReset": (
            replacement.get("client_counter") == 0
            and replacement.get("server_counter") == 0
        ),
        "encryptedSecurityResult": (
            security_result.get("client_counter") == 1
            and security_result.get("server_counter") == 1
        ),
        "serverInit": bool(server_inits) and server_inits[-1].get("server_counter") == 2,
        "framebuffer": bool(framebuffers),
        "keyboard": {event.get("down") for event in keyboards} == {False, True},
        "pointer": bool(pointers),
        "clipboard": any(
            event.get("marker", "").startswith("OPSKAT_CLIENT_CLIPBOARD_")
            for event in clipboards
        ),
        "flowComplete": set(flow.get("observed", ())) == {
            "clipboard", "framebuffer", "keyboard", "pointer"
        },
    }
    return checks, flow


def verify(path, variant):
    sessions = read_sessions(path, variant)
    for session in reversed(sessions):
        checks, flow = verify_session(session, variant)
        if all(checks.values()):
            return {
                "allPassed": True,
                "checks": checks,
                "flowCounters": {
                    "client": flow.get("client_counter"),
                    "server": flow.get("server_counter"),
                },
            }
    return {
        "allPassed": False,
        "checks": verify_session(sessions[-1], variant)[0] if sessions else {},
        "flowCounters": None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ra2r", required=True)
    parser.add_argument("--ra2r-256", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()

    try:
        implementations = {
            "RA2r": verify(args.ra2r, "RA2r"),
            "RA2r_256": verify(args.ra2r_256, "RA2r_256"),
        }
    except (OSError, ValueError) as exc:
        print(f"oracle verification failed: {exc}", file=sys.stderr)
        return 1

    report = {
        "implementations": implementations,
        "credentialValueIncluded": False,
        "privateKeyIncluded": False,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    print(encoded, end="")
    return 0 if all(result["allPassed"] for result in implementations.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
