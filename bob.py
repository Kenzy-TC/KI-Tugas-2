from __future__ import annotations

import argparse
import secrets

from aes import decrypt_ascii, encrypt_ascii, validate_key
from peer import PeerHandler, run_peer
from protocol import (
    PeerState,
    _f_nonce,
    _parse_payload,
    _payload,
    _print_cipher,
    _read_message,
    _send_message,
)


class BobHandler(PeerHandler):
    def handle_role_message(self, message: dict) -> None:
        if message.get("type") != "TICKET":
            raise ValueError("Bob hanya menerima ticket Alice atau pesan chat.")
        state: PeerState = self.server.state
        ticket = message.get("ticket")
        if not isinstance(ticket, dict):
            raise ValueError("Ticket tidak ditemukan.")
        ticket_data = _parse_payload(decrypt_ascii(state.long_term_key, ticket, "BOB_TICKET"))
        if ticket_data.get("ID_A") != "Alice":
            raise ValueError("ID_A pada ticket tidak valid.")
        session_key = ticket_data.get("K_S")
        validate_key(session_key)

        n2 = secrets.token_hex(16)
        challenge = encrypt_ascii(session_key, _payload({"N2": n2}), "BOB_CHALLENGE")
        print("[Bob]: ticket diterima dan dibuka dengan kunci jangka panjang Bob.")
        _print_cipher("[Bob]", challenge)
        _send_message(self.wfile, {"type": "CHALLENGE", "envelope": challenge})

        proof_message = _read_message(self.rfile)
        if proof_message.get("type") != "CHALLENGE_REPLY":
            raise ValueError("Jawaban challenge dari Alice tidak diterima.")
        proof = _parse_payload(decrypt_ascii(
            session_key, proof_message.get("envelope", {}), "ALICE_PROOF"))
        if proof.get("f(N2)") != _f_nonce(n2):
            raise ValueError("Bukti f(N2) dari Alice salah.")
        state.set_session_key(session_key)
        print("[Bob] : kunci sesi aktif.")
        _send_message(self.wfile, {"type": "HANDSHAKE_OK"})


def run_bob(bind_ip: str, alice_host: str, port: int) -> None:
    run_peer("Bob", bind_ip, alice_host, port, BobHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Jalankan proses Bob.")
    parser.add_argument("--bind", required=True, help="IP interface mesin Bob")
    parser.add_argument("--alice-host", required=True, help="IP mesin Alice")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port harus berada dalam rentang 1 sampai 65535.")

    run_bob(args.bind, args.alice_host, args.port)


if __name__ == "__main__":
    main()
