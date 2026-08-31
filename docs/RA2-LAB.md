# RSA-AES interoperability lab

This lab is the release gate for the OpsKat noVNC fork's RSA-AES support. It combines five single-security-type TigerVNC 1.16.2 servers with two protocol-independent Python RA2r oracles. The browser harness connects through loopback-only WebSocket proxies, so the remote host exposes only the seven raw VNC ports using the lab's existing LAN binding model.

## Deterministic endpoints

| Port | Implementation | Security type | Wire value | Post-authentication transport |
| ---: | --- | --- | ---: | --- |
| 5911 | TigerVNC 1.16.2 | RA2 | 5 | AES-EAX-128 |
| 5912 | TigerVNC 1.16.2 | RA2ne | 6 | Plaintext after encrypted authentication |
| 5913 | TigerVNC 1.16.2 | RA2_256 | 129 | AES-EAX-256 |
| 5914 | TigerVNC 1.16.2 | RA2ne_256 | 130 | Plaintext after encrypted authentication |
| 5915 | TigerVNC 1.16.2 | VNCAuth | 2 | Plaintext baseline |
| 5916 | Python/PyCryptodome oracle | RA2r | 13 | Replacement AES-EAX-128 ciphers |
| 5917 | Python/PyCryptodome oracle | RA2r_256 | 133 | Replacement AES-EAX-256 ciphers |

The lab credential has an empty username. Supply its password through `RA2_LAB_PASSWORD`; do not put it in commands saved as evidence or committed files.

## Independent RA2r oracle

[`tests/integration/ra2r_oracle.py`](../tests/integration/ra2r_oracle.py) is a verification-only RFB server. It uses Python socket/struct/hashlib code and Debian's independently maintained PyCryptodome RSA PKCS#1 v1.5 and AES-EAX implementations. It does not import noVNC code or reproduce noVNC's JavaScript cipher implementation.

For both RA2r variants it verifies and records, without recording credentials or key material:

- RSA random exchange and authenticated transcript hashes;
- encrypted credential validation;
- authenticated second client/server random exchange;
- replacement directional key derivation and record-counter reset to zero;
- encrypted `SecurityResult`, `ClientInit`, `ServerInit`, raw framebuffer update and server clipboard data;
- representative client framebuffer request, keyboard, pointer and clipboard messages.

The image recipe and Compose overlay are in [`tests/integration/lab/`](../tests/integration/lab/). To refresh the authorized lab, copy them into `/opt/opskat-vnc-ra2-lab` as `oracle.py`, `oracle.Dockerfile` and `compose.oracle.yaml`, create `state/ra2r` and `state/ra2r-256` as UID/GID 1000 with mode `0700`, then run:

```bash
cd /opt/opskat-vnc-ra2-lab
export RA2_LAB_PASSWORD='<supply out of band>'
export RA2_LAB_BIND_HOST='<LAN address>'
docker compose -f compose.yaml -f compose.oracle.yaml up -d --build
docker compose -f compose.yaml -f compose.oracle.yaml ps
./probe.py
```

Bind all seven raw VNC ports to the host's LAN address, not `0.0.0.0`; the oracle overlay defaults to the authorized lab address and accepts `RA2_LAB_BIND_HOST` for an explicit replacement. Do not publish WebSocket proxy ports on the lab host.

## Live noVNC gate

The gate launches ChromeHeadless through the existing Karma browser infrastructure. `tests/integration/run_live.mjs` creates one loopback-only WebSocket-to-TCP proxy for each endpoint; the browser then instantiates the real `core/rfb.js` client.

The client exercises the public `securityPolicy`, `negotiatedsecurity`, `approveServer()`, `sendKey()` and `clipboardPasteFrom()` API. It reaches a non-empty framebuffer through `getImageData()` and dispatches mouse events through noVNC's canvas input path. The test disables negotiated QEMU-key and extended-clipboard capabilities after connection only to make the post-authentication keyboard and clipboard bytes deterministic for packet-capture assertions.

```bash
export RA2_LAB_HOST=192.168.8.141
export RA2_LAB_PASSWORD='<supply out of band>'
npm run test:integration:ra2
```

Expected policy matrix (`S` = `ServerInit`, framebuffer and client flow succeed; `R` = rejected before authentication):

| Policy | RA2 | RA2ne | RA2_256 | RA2ne_256 | VNCAuth | RA2r | RA2r_256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| server | S | S | S | S | S | S | S |
| always_maximum | R | R | S | R | R | R | S |
| always_on | S | R | S | R | R | S | S |
| prefer_on | S | S | S | S | S | S | S |
| prefer_off | S | S | S | S | S | S | S |

A passing run reports 35 completed cases. Each successful case asserts that `negotiatedsecurity` precedes `connect` and exactly matches the endpoint's type, stable name, authentication protection, session protection and AES size.

## Wire observation

Capture only the lab ports. Store packet captures under the ignored task evidence directory; packet data must never be committed.

```bash
# On the authorized lab host, from /opt/opskat-vnc-ra2-lab:
setsid tcpdump -i any -U -w task4-wire.pcap \
  '(tcp port 5911 or tcp port 5912 or tcp port 5913 or tcp port 5914 or tcp port 5915 or tcp port 5916 or tcp port 5917)' \
  >task4-tcpdump.log 2>&1 < /dev/null &
echo $! >task4-tcpdump.pid

# Run npm run test:integration:ra2, then stop capture:
kill -INT "$(cat task4-tcpdump.pid)"
```

After copying the pcap and the two oracle `events.jsonl` files locally, run:

```bash
python3 tests/integration/analyze_wire.py /path/to/task4-wire.pcap \
  --output /path/to/wire-verdict.json
python3 tests/integration/verify_oracle.py \
  --ra2r /path/to/ra2r-events.jsonl \
  --ra2r-256 /path/to/ra2r-256-events.jsonl \
  --output /path/to/oracle-verdict.json
```

The wire analyzer does not decrypt or inspect credentials. It checks deterministic post-authentication `ServerInit` names, framebuffer-request bytes, legacy keyboard events and clipboard marker prefixes. Those markers must be absent on RA2, RA2_256, RA2r and RA2r_256, and visible on RA2ne, RA2ne_256 and VNCAuth. Captured byte counts must remain non-zero for every direction, preventing an empty capture from passing as ciphertext. The oracle verifier independently requires accepted credentials, the second random exchange, replacement counters at zero, encrypted `SecurityResult`, `ServerInit`, framebuffer and keyboard/pointer/clipboard flow; its event input contains no credential values or private keys.

## Release and immutable pin

Run the full fork gates after the live and wire checks:

```bash
npm run lint
TEST_BROWSER_NAME=ChromeHeadless npm test
```

Inspect the staged paths and evidence for scope, oracle independence, deterministic matrix results, capture claims, secret/private-key exposure and reproducibility. Commit only explicit tracked paths. Push the exact verified `HEAD` before OpsKat pins it:

```bash
git push origin HEAD:develop/vnc-ra2-encryption
git rev-parse HEAD
git ls-remote origin refs/heads/develop/vnc-ra2-encryption
```

The two SHAs must match. OpsKat must pin that immutable commit, never an unverified local revision or a moving branch name.
