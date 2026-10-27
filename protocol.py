from __future__ import annotations

import getpass
import json
import socket
import socketserver
import threading
from typing import Any

from aes import decrypt_ascii, encrypt_ascii, validate_key

MAX_LINE = 1_000_000


def _json_ascii(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _read_message(stream) -> dict[str, Any]:
    line = stream.readline(MAX_LINE + 1)
    if not line:
        raise ConnectionError("Koneksi ditutup sebelum pesan diterima.")
    if len(line) > MAX_LINE or not line.endswith(b"\n"):
        raise ValueError("Pesan terlalu besar atau tidak diakhiri newline.")
    result = json.loads(line.decode("ascii"))
    if not isinstance(result, dict):
        raise ValueError("Pesan protokol harus berupa objek JSON.")
    return result


def _send_message(stream, message: dict[str, Any]) -> None:
    data = (_json_ascii(message) + "\n").encode("ascii")
    if len(data) > MAX_LINE:
        raise ValueError("Pesan terlalu besar.")
    stream.write(data)
    stream.flush()


def _payload(obj: Any) -> str:
    return _json_ascii(obj)


def _parse_payload(text: str) -> dict[str, Any]:
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("Isi terenkripsi harus berupa objek JSON.")
    return obj


def _f_nonce(nonce_hex: str) -> str:
    return f"{(int(nonce_hex, 16) + 1) % (1 << 128):032x}"


def _print_cipher(label: str, envelope: dict[str, str]) -> None:
    print(f"{label} IV (Hex): {envelope['iv']}")
    print(f"{label} ciphertext (Hex): {envelope['ciphertext']}")
    print(f"{label} tag (Hex): {envelope['tag']}")


class PeerState:
    def __init__(self, role: str, long_term_key: str, peer_host: str) -> None:
        self.role = role
        self.long_term_key = long_term_key
        self.peer_host = peer_host
        self.session_key: str | None = None
        self.pending_session_key: str | None = None
        self.lock = threading.Lock()

    def get_session_key(self) -> str | None:
        with self.lock:
            return self.session_key

    def set_pending(self, key: str | None) -> None:
        with self.lock:
            self.pending_session_key = key

    def get_pending(self) -> str | None:
        with self.lock:
            return self.pending_session_key

    def set_session_key(self, key: str) -> None:
        validate_key(key)
        with self.lock:
            self.session_key = key
            self.pending_session_key = None


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


def _start_server(bind_ip: str, port: int, handler, state: Any) -> ThreadedServer:
    server = ThreadedServer((bind_ip, port), handler)
    server.state = state
    thread = threading.Thread(
        target=server.serve_forever,
        name=f"server-{bind_ip}:{port}",
        daemon=True,
    )
    thread.start()
    return server


def _exchange(
    host: str,
    port: int,
    outgoing: dict[str, Any],
    expect_reply: bool = True,
) -> dict[str, Any] | None:
    with socket.create_connection((host, port), timeout=8) as connection:
        connection.settimeout(30)
        with connection.makefile("rwb") as stream:
            _send_message(stream, outgoing)
            if not expect_reply:
                return None
            return _read_message(stream)


def _check_response(response: dict[str, Any]) -> dict[str, Any]:
    if response.get("type") == "ERROR":
        raise RuntimeError(response.get("message", "Pesan error dari peer."))
    return response


def _read_key(prompt: str) -> str:
    while True:
        value = getpass.getpass(prompt)
        try:
            validate_key(value)
            return value
        except ValueError as exc:
            print(exc)


def send_chat(state: PeerState, port: int, plaintext: str) -> None:
    key = state.get_session_key()
    if key is None:
        raise RuntimeError("Belum ada kunci sesi, Alice harus menjalankan handshake dahulu.")
    envelope = encrypt_ascii(key, plaintext, "CHAT")
    print(f"[{state.role}] Mengirim plaintext ASCII: {plaintext}")
    _print_cipher(f"[{state.role}] Ciphertext", envelope)
    response = _check_response(_exchange(state.peer_host, port, {
        "type": "CHAT", "sender": state.role, "envelope": envelope,
    }))
    if response.get("type") != "ACK":
        raise RuntimeError("Penerima tidak mengonfirmasi pesan.")
    print(f"[{state.role}] ACK diterima.")
