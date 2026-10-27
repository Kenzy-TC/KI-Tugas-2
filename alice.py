from __future__ import annotations

import argparse
import secrets
import socket

from aes import decrypt_ascii, encrypt_ascii, validate_key
from peer import PeerHandler, run_peer
from protocol import (
    PeerState,
    _check_response,
    _exchange,
    _f_nonce,
    _parse_payload,
    _payload,
    _print_cipher,
    _read_message,
    _send_message,
)


class AliceHandler(PeerHandler):
    def handle_role_message(self, message: dict) -> None:
        if message.get("type") != "CHALLENGE":
            raise ValueError("Alice hanya menerima challenge Bob atau pesan chat.")
        state: PeerState = self.server.state
        key = state.get_pending()
        if key is None:
            raise ValueError("Tidak ada handshake, Alice menunggu challenge.")
        challenge = _parse_payload(decrypt_ascii(
            key, message.get("envelope", {}), "BOB_CHALLENGE"))
        n2 = challenge.get("N2")
        if not isinstance(n2, str) or len(n2) != 32:
            raise ValueError("Nonce challenge tidak valid.")
        if len(bytes.fromhex(n2)) != 16:
            raise ValueError("N2 harus berukuran 128 bit.")
        response = encrypt_ascii(key, _payload({"f(N2)": _f_nonce(n2)}), "ALICE_PROOF")
        print("[Alice] : challenge Bob berhasil dibuka.")
        _print_cipher("[Alice]", response)
        _send_message(self.wfile, {"type": "CHALLENGE_REPLY", "envelope": response})


def alice_handshake(state: PeerState, kdc_host: str, bob_host: str, port: int) -> None:
    if state.get_pending() is not None:
        raise RuntimeError("Handshake sedang berjalan.")
    n1 = secrets.token_hex(16)
    print(f"[Alice] ke KDC: ID_A=Alice, ID_B=Bob, N1={n1}")
    response = _check_response(_exchange(kdc_host, port, {
        "type": "AS_REQ", "ID_A": "Alice", "ID_B": "Bob", "N1": n1,
    }))
    alice_part = response.get("alice_part")
    ticket = response.get("ticket")
    if (response.get("type") != "AS_REP" or not isinstance(alice_part, dict)
            or not isinstance(ticket, dict)):
        raise ValueError("Jawaban KDC tidak sesuai protokol.")
    reply = _parse_payload(decrypt_ascii(state.long_term_key, alice_part, "ALICE_PART"))
    if (reply.get("ID_A") != "Alice" or reply.get("ID_B") != "Bob"
            or reply.get("N1") != n1):
        raise ValueError("Identitas atau N1 pada balasan KDC tidak cocok.")
    session_key = reply.get("K_S")
    validate_key(session_key)
    print("[Alice]: jawaban KDC terverifikasi dengan kunci jangka panjang Alice.")
    _print_cipher("[Alice] E_KA balasan KDC", alice_part)
    _print_cipher("[Alice] Ticket E_KB", ticket)

    state.set_pending(session_key)
    try:
        with socket.create_connection((bob_host, port), timeout=8) as connection:
            connection.settimeout(30)
            with connection.makefile("rwb") as stream:
                _print_cipher("[Alice]", ticket)
                _send_message(stream, {"type": "TICKET", "ticket": ticket})
                challenge_message = _check_response(_read_message(stream))
                if challenge_message.get("type") != "CHALLENGE":
                    raise ValueError("Bob tidak mengirim challenge.")
                challenge = _parse_payload(decrypt_ascii(
                    session_key, challenge_message.get("envelope", {}), "BOB_CHALLENGE"))
                n2 = challenge.get("N2")
                if not isinstance(n2, str) or len(n2) != 32 or len(bytes.fromhex(n2)) != 16:
                    raise ValueError("N2 challenge Bob tidak valid.")
                proof = encrypt_ascii(session_key, _payload({
                    "f(N2)": _f_nonce(n2),
                }), "ALICE_PROOF")
                print("[Alice]: challenge Bob terverifikasi.")
                _print_cipher("[Alice]", proof)
                _send_message(stream, {"type": "CHALLENGE_REPLY", "envelope": proof})
                final = _check_response(_read_message(stream))
                if final.get("type") != "HANDSHAKE_OK":
                    raise ValueError("Bob belum mengonfirmasi.")
        state.set_session_key(session_key)
    finally:
        state.set_pending(None)
    print("kunci sesi aktif. Alice dan Bob siap bertukar pesan.")


def run_alice(bind_ip: str, kdc_host: str, bob_host: str, port: int) -> None:
    run_peer(
        "Alice", bind_ip, bob_host, port, AliceHandler,
        handshake=lambda state: alice_handshake(state, kdc_host, bob_host, port),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Jalankan proses Alice.")
    parser.add_argument("--bind", required=True, help="IP interface mesin Alice")
    parser.add_argument("--kdc-host", required=True, help="IP mesin KDC")
    parser.add_argument("--bob-host", required=True, help="IP mesin Bob")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port harus berada dalam rentang 1 sampai 65535.")

    run_alice(args.bind, args.kdc_host, args.bob_host, args.port)


if __name__ == "__main__":
    main()
