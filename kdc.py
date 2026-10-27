from __future__ import annotations

import argparse
import socketserver
import threading

from aes import encrypt_ascii, validate_key
from protocol import (
    _payload,
    _print_cipher,
    _read_key,
    _read_message,
    _send_message,
    _start_server,
)


class KDCState:
    def __init__(self, alice_key: str, bob_key: str) -> None:
        self.alice_key = alice_key
        self.bob_key = bob_key
        self.session_key: str | None = None
        self.lock = threading.Lock()

    def get_session_key(self) -> str | None:
        with self.lock:
            return self.session_key

    def set_session_key(self, key: str) -> None:
        validate_key(key)
        with self.lock:
            self.session_key = key


class KDCHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(20)
        try:
            request = _read_message(self.rfile)
            if request.get("type") != "AS_REQ":
                raise ValueError("KDC hanya menerima pesan AS_REQ.")
            if request.get("ID_A") != "Alice" or request.get("ID_B") != "Bob":
                raise ValueError("Identitas Alice/Bob tidak valid.")
            n1 = request.get("N1")
            if not isinstance(n1, str) or len(n1) != 32 or len(bytes.fromhex(n1)) != 16:
                raise ValueError("N1 dari Alice tidak valid.")
            session_key = self.server.state.get_session_key()
            if session_key is None:
                raise ValueError("Kunci sesi belum diatur. Jalankan perintah setkey di KDC.")

            ticket = encrypt_ascii(
                self.server.state.bob_key,
                _payload({"K_S": session_key, "ID_A": "Alice"}),
                "BOB_TICKET",
            )
            alice_part = encrypt_ascii(
                self.server.state.alice_key,
                _payload({"K_S": session_key, "ID_A": "Alice", "ID_B": "Bob", "N1": n1}),
                "ALICE_PART",
            )
            print(f"[KDC]: permintaan Alice diterima (N1={n1}).")
            _print_cipher("[KDC] Ticket untuk Bob", ticket)
            _print_cipher("[KDC] E_KA balasan Alice", alice_part)
            _send_message(self.wfile, {
                "type": "AS_REP", "alice_part": alice_part, "ticket": ticket,
            })
        except Exception as exc:
            try:
                _send_message(self.wfile, {"type": "ERROR", "message": str(exc)})
            except Exception:
                pass
            print(f"[KDC] Permintaan ditolak: {exc}")


def run_kdc(bind_ip: str, port: int) -> None:
    alice_key = _read_key("Masukkan kunci jangka panjang Alice (16 ASCII): ")
    bob_key = _read_key("Masukkan kunci jangka panjang Bob (16 ASCII): ")
    state = KDCState(alice_key, bob_key)
    server = _start_server(bind_ip, port, KDCHandler, state)
    print(f"[KDC] Mendengar di {bind_ip}:{port}, belum ada kunci sesi.")
    print("Perintah KDC: setkey (atur/ganti key sesi), status, help, quit")
    try:
        while True:
            try:
                command = input("KDC> ").strip().lower()
            except EOFError:
                break
            if command in ("quit", "exit"):
                break
            if command == "help":
                print("setkey = masukkan kunci sesi AES-128 baru.")
            elif command == "status":
                print("Kunci jangka panjang Alice/Bob siap" +
                      ("sudah diatur." if state.get_session_key() else "belum diatur."))
            elif command == "setkey":
                state.set_session_key(_read_key("Kunci sesi baru (16 ASCII): "))
                print("Kunci sesi disimpan, jalankan handshake Alice untuk mendistribusikannya.")
            elif command:
                print("Perintah tidak dikenal. Ketik help.")
    finally:
        server.shutdown()
        server.server_close()
        print("[KDC] Server berhenti.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Jalankan server KDC.")
    parser.add_argument("--bind", required=True, help="IP interface mesin KDC")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port harus berada dalam rentang 1 sampai 65535.")

    run_kdc(args.bind, args.port)


if __name__ == "__main__":
    main()
