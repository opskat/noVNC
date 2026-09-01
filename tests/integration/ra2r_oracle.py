#!/usr/bin/env python3
"""Independent RA2r/RA2r_256 interoperability oracle for the noVNC lab."""

import hashlib
import json
import os
import socket
import struct
import threading
import time
import uuid
from pathlib import Path

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes


LISTEN_HOST = os.environ.get("ORACLE_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("ORACLE_LISTEN_PORT", "5900"))
SECURITY_TYPE = int(os.environ["ORACLE_SECURITY_TYPE"])
PASSWORD = os.environ["ORACLE_PASSWORD"].encode("utf-8")
STATE_DIR = Path(os.environ.get("ORACLE_STATE_DIR", "/state"))
MAX_RECORD = 8192
TAG_BYTES = 16

VARIANTS = {
    13: {"name": "RA2r", "random_bytes": 16, "hash": hashlib.sha1, "aes_bits": 128},
    133: {"name": "RA2r_256", "random_bytes": 32, "hash": hashlib.sha256, "aes_bits": 256},
}
VARIANT = VARIANTS[SECURITY_TYPE]
EVENT_CONTEXT = threading.local()


class ProtocolError(Exception):
    pass


class RecordCipher:
    """AES-EAX records implemented independently with PyCryptodome."""

    def __init__(self, key):
        self.key = bytes(key)
        self.counter = 0

    def _nonce(self):
        return self.counter.to_bytes(16, "little")

    def seal(self, plaintext):
        plaintext = bytes(plaintext)
        if len(plaintext) > MAX_RECORD:
            raise ProtocolError("record plaintext too long")
        header = struct.pack(">H", len(plaintext))
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self._nonce(), mac_len=TAG_BYTES)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self.counter += 1
        return header + ciphertext + tag

    def open_from(self, connection):
        header = read_exact(connection, 2)
        length = struct.unpack(">H", header)[0]
        if length > MAX_RECORD:
            raise ProtocolError("record plaintext too long")
        ciphertext = read_exact(connection, length)
        tag = read_exact(connection, TAG_BYTES)
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self._nonce(), mac_len=TAG_BYTES)
        cipher.update(header)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ProtocolError("record authentication failed") from exc
        self.counter += 1
        return plaintext


def read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EOFError(f"short read: wanted {size}, got {len(result)}")
        result.extend(chunk)
    return bytes(result)


def public_key_wire(key):
    key_bytes = key.size_in_bytes()
    return (
        struct.pack(">I", key.size_in_bits())
        + int(key.n).to_bytes(key_bytes, "big")
        + int(key.e).to_bytes(key_bytes, "big")
    )


def read_public_key(connection):
    bits_raw = read_exact(connection, 4)
    bits = struct.unpack(">I", bits_raw)[0]
    if bits < 1024 or bits > 8192:
        raise ProtocolError(f"invalid RSA key size {bits}")
    key_bytes = (bits + 7) // 8
    modulus = read_exact(connection, key_bytes)
    exponent = read_exact(connection, key_bytes)
    key = RSA.construct((int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")))
    return bits_raw + modulus + exponent, key


def derive_ciphers(client_random, server_random):
    digest = VARIANT["hash"]
    key_bytes = VARIANT["random_bytes"]
    client_key = digest(server_random + client_random).digest()[:key_bytes]
    server_key = digest(client_random + server_random).digest()[:key_bytes]
    return RecordCipher(client_key), RecordCipher(server_key)


def load_server_key():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    key_path = STATE_DIR / "rsa.pem"
    if key_path.exists():
        return RSA.import_key(key_path.read_bytes())
    key = RSA.generate(2048)
    temporary = key_path.with_suffix(".tmp")
    temporary.write_bytes(key.export_key(format="PEM", passphrase=None, pkcs=8))
    temporary.chmod(0o600)
    temporary.replace(key_path)
    return key


def emit(event, **fields):
    record = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "variant": VARIANT["name"],
        "security_type": SECURITY_TYPE,
        "event": event,
        **fields,
    }
    connection_id = getattr(EVENT_CONTEXT, "connection_id", None)
    if connection_id is not None:
        record["connection_id"] = connection_id
    line = json.dumps(record, sort_keys=True)
    print(line, flush=True)
    with (STATE_DIR / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")


def send_record(connection, cipher, plaintext):
    connection.sendall(cipher.seal(plaintext))


def parse_credentials(payload):
    if len(payload) < 2:
        raise ProtocolError("short credential record")
    username_length = payload[0]
    password_offset = 1 + username_length
    if password_offset >= len(payload):
        raise ProtocolError("short credential record")
    password_length = payload[password_offset]
    end = password_offset + 1 + password_length
    if end != len(payload):
        raise ProtocolError("malformed credential record")
    username = payload[1:password_offset]
    password = payload[password_offset + 1:end]
    if username or password != PASSWORD:
        raise ProtocolError("invalid credentials")


def server_init():
    width, height = 16, 2
    pixel_format = bytes((32, 24, 0, 1)) + struct.pack(">HHH", 255, 255, 255) + bytes((16, 8, 0, 0, 0, 0))
    name = f"OPSKAT_FRAME_{VARIANT['name'].upper()}".encode("ascii")
    return struct.pack(">HH", width, height) + pixel_format + struct.pack(">I", len(name)) + name


def framebuffer_update():
    marker = (f"OPSKAT_FRAMEBUFFER_{VARIANT['name'].upper()}|".encode("ascii") * 8)[:128]
    marker = marker.ljust(128, b"!")
    rectangle = struct.pack(">HHHHi", 0, 0, 16, 2, 0) + marker
    return bytes((0, 0)) + struct.pack(">H", 1) + rectangle


def server_clipboard():
    marker = f"OPSKAT_SERVER_CLIPBOARD_{VARIANT['name'].upper()}".encode("ascii")
    return bytes((3, 0, 0, 0)) + struct.pack(">I", len(marker)) + marker


def consume_client_messages(connection, client_cipher, server_cipher):
    pending = bytearray()
    observed = set()
    flow_reported = False
    framebuffer_sent = False
    while True:
        pending.extend(client_cipher.open_from(connection))
        while pending:
            message_type = pending[0]
            if message_type == 0:
                length = 20
            elif message_type == 2:
                if len(pending) < 4:
                    break
                length = 4 + 4 * struct.unpack(">H", pending[2:4])[0]
            elif message_type == 3:
                length = 10
            elif message_type == 4:
                length = 8
            elif message_type == 5:
                length = 6
            elif message_type == 6:
                if len(pending) < 8:
                    break
                text_length = struct.unpack(">I", pending[4:8])[0]
                if text_length & 0x80000000:
                    raise ProtocolError("unexpected extended clipboard message")
                length = 8 + text_length
            elif message_type == 150:
                length = 10
            elif message_type == 248:
                if len(pending) < 9:
                    break
                length = 9 + pending[8]
            else:
                raise ProtocolError(f"unsupported client message type {message_type}")
            if len(pending) < length:
                break
            message = bytes(pending[:length])
            del pending[:length]

            if message_type == 3 and not framebuffer_sent:
                send_record(connection, server_cipher, framebuffer_update())
                send_record(connection, server_cipher, server_clipboard())
                framebuffer_sent = True
                observed.add("framebuffer")
                emit("framebuffer_sent", marker="OPSKAT_FRAMEBUFFER", server_counter=server_cipher.counter)
            elif message_type == 4:
                observed.add("keyboard")
                emit("keyboard", down=bool(message[1]), keysym=struct.unpack(">I", message[4:8])[0])
            elif message_type == 5:
                observed.add("pointer")
                emit("pointer", button_mask=message[1], x=struct.unpack(">H", message[2:4])[0], y=struct.unpack(">H", message[4:6])[0])
            elif message_type == 6:
                observed.add("clipboard")
                marker = message[8:].decode("latin-1", "replace")
                emit("clipboard", marker=marker)

            if not flow_reported and {"framebuffer", "keyboard", "pointer", "clipboard"} <= observed:
                emit("flow_complete", observed=sorted(observed), client_counter=client_cipher.counter, server_counter=server_cipher.counter)
                flow_reported = True


def handle_client(connection, address, server_key):
    connection.settimeout(15)
    emit("connection", peer=address[0])
    connection.sendall(b"RFB 003.008\n")
    if read_exact(connection, 12) != b"RFB 003.008\n":
        raise ProtocolError("client did not negotiate RFB 3.8")
    connection.sendall(bytes((1, SECURITY_TYPE)))
    if read_exact(connection, 1) != bytes((SECURITY_TYPE,)):
        emit("policy_rejected")
        return

    server_wire = public_key_wire(server_key.public_key())
    connection.sendall(server_wire)
    client_wire, client_key = read_public_key(connection)

    encrypted_length = struct.unpack(">H", read_exact(connection, 2))[0]
    encrypted_client_random = read_exact(connection, encrypted_length)
    client_random = PKCS1_v1_5.new(server_key).decrypt(encrypted_client_random, None)
    if client_random is None or len(client_random) != VARIANT["random_bytes"]:
        raise ProtocolError("invalid client random")
    server_random = get_random_bytes(VARIANT["random_bytes"])
    encrypted_server_random = PKCS1_v1_5.new(client_key).encrypt(server_random)
    connection.sendall(struct.pack(">H", len(encrypted_server_random)) + encrypted_server_random)

    client_cipher, server_cipher = derive_ciphers(client_random, server_random)
    expected_client_hash = VARIANT["hash"](client_wire + server_wire).digest()
    if client_cipher.open_from(connection) != expected_client_hash:
        raise ProtocolError("client transcript hash mismatch")
    send_record(connection, server_cipher, VARIANT["hash"](server_wire + client_wire).digest())
    send_record(connection, server_cipher, bytes((2,)))
    parse_credentials(client_cipher.open_from(connection))
    emit("credentials_accepted", username_empty=True)

    replacement_client_random = client_cipher.open_from(connection)
    if len(replacement_client_random) != VARIANT["random_bytes"]:
        raise ProtocolError("invalid replacement client random")
    replacement_server_random = get_random_bytes(VARIANT["random_bytes"])
    send_record(connection, server_cipher, replacement_server_random)
    client_cipher, server_cipher = derive_ciphers(replacement_client_random, replacement_server_random)
    emit("replacement_ciphers", random_bytes=VARIANT["random_bytes"], client_counter=client_cipher.counter, server_counter=server_cipher.counter)

    send_record(connection, server_cipher, struct.pack(">I", 0))
    if client_cipher.open_from(connection) not in (b"\x00", b"\x01"):
        raise ProtocolError("invalid ClientInit")
    emit("security_result_and_client_init", client_counter=client_cipher.counter, server_counter=server_cipher.counter)
    send_record(connection, server_cipher, server_init())
    emit("server_init_sent", server_counter=server_cipher.counter)
    consume_client_messages(connection, client_cipher, server_cipher)


def main():
    server_key = load_server_key()
    emit("oracle_started", listen_port=LISTEN_PORT, rsa_bits=server_key.size_in_bits(), aes_bits=VARIANT["aes_bits"])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(16)
        while True:
            connection, address = listener.accept()
            def run(conn=connection, peer=address):
                EVENT_CONTEXT.connection_id = uuid.uuid4().hex
                try:
                    with conn:
                        handle_client(conn, peer, server_key)
                except EOFError:
                    emit("connection_closed")
                except Exception as exc:
                    emit("connection_error", error=str(exc))
                finally:
                    del EVENT_CONTEXT.connection_id
            threading.Thread(target=run, daemon=True).start()


if __name__ == "__main__":
    main()
