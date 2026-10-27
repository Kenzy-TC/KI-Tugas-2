from __future__ import annotations

import socketserver
from collections.abc import Callable

from aes import decrypt_ascii
from protocol import (
    PeerState,
    _parse_payload,
    _print_cipher,
    _read_key,
    _read_message,
    _send_message,
    _start_server,
    send_chat,
)


class PeerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(30)
        try:
            message = _read_message(self.rfile)
            if message.get("type") == "CHAT":
                self._receive_chat(message)
            else:
                self.handle_role_message(message)
        except Exception as exc:
            try:
                _send_message(self.wfile, {"type": "ERROR", "message": str(exc)})
            except Exception:
                pass
            print(f"[{self.server.state.role}] Pesan ditolak: {exc}")

    def handle_role_message(self, message: dict) -> None:
        raise ValueError("Jenis pesan tidak didukung oleh endpoint ini.")

    def _receive_chat(self, message: dict) -> None:
        state: PeerState = self.server.state
        key = state.get_session_key()
        if key is None:
            raise ValueError("Belum ada kunci sesi aktif, lakukan handshake dahulu.")
        plaintext = decrypt_ascii(key, message.get("envelope", {}), "CHAT")
        print(f"\n[{state.role}] Pesan dari {message.get('sender', 'peer')}: {plaintext}")
        _print_cipher(f"[{state.role}] Data diterima", message["envelope"])
        _send_message(self.wfile, {"type": "ACK"})


def _print_peer_help(role: str) -> None:
    print("Perintah: send <pesan ASCII>, status, help, quit")
    if role == "Alice":
        print("Khusus Alice: handshake (minta kunci sesi baru dari KDC dan mulai ulang)")


def run_peer(
    role: str,
    bind_ip: str,
    peer_host: str,
    port: int,
    handler_class: type[PeerHandler],
    handshake: Callable[[PeerState], None] | None = None,
) -> None:
    long_term_key = _read_key(f"Masukkan kunci jangka panjang {role} (16 ASCII): ")
    state = PeerState(role, long_term_key, peer_host)
    server = _start_server(bind_ip, port, handler_class, state)
    print(f"[{role}] Mendengar di {bind_ip}:{port}, peer={peer_host}:{port}.")
    _print_peer_help(role)
    try:
        while True:
            try:
                line = input(f"{role}> ")
            except EOFError:
                break
            command = line.strip()
            if command.lower() in ("quit", "exit"):
                break
            elif command.lower() == "help":
                _print_peer_help(role)
            elif command.lower() == "status":
                print("Kunci sesi " + ("aktif." if state.get_session_key() else "belum aktif."))
            elif command.lower() == "handshake" and handshake is not None:
                try:
                    handshake(state)
                except Exception as exc:
                    state.set_pending(None)
                    print(f"[{role}] Handshake gagal: {exc}")
            elif line.startswith("send "):
                plaintext = line[5:]
                try:
                    send_chat(state, port, plaintext)
                except Exception as exc:
                    print(f"[{role}] Gagal mengirim pesan: {exc}")
            elif not command:
                continue
            else:
                print("Perintah tidak dikenal. Ketik help.")
    finally:
        server.shutdown()
        server.server_close()
        print(f"[{role}] Server berhenti.")
