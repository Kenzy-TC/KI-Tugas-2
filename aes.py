from __future__ import annotations
import hashlib
import hmac
import secrets

S_BOX = (
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
)

INV_S_BOX = tuple(S_BOX.index(value) for value in range(256))
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

def validate_key(key: str) -> bytes:
    if not isinstance(key, str):
        raise ValueError("Key harus berupa ASCII.")
    try:
        raw = key.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Key harus berisi karakter ASCII.") from exc
    if len(raw) != 16 or any(byte < 0x20 or byte > 0x7E for byte in raw):
        raise ValueError("Key AES harus 16 karakter ASCII.")
    return raw

def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF

def _mul(value: int, factor: int) -> int:
    result = 0
    while factor:
        if factor & 1:
            result ^= value
        value = _xtime(value)
        factor >>= 1
    return result

def _expand_key(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("AES membutuhkan key 16 byte.")
    words = [list(key[index:index + 4]) for index in range(0, 16, 4)]
    for index in range(4, 44):
        temp = words[index - 1][:]
        if index % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[byte] for byte in temp]
            temp[0] ^= RCON[index // 4]
        words.append([words[index - 4][offset] ^ temp[offset] for offset in range(4)])
    return [bytes(sum(words[4 * round_no:4 * round_no + 4], [])) for round_no in range(11)]

def _add_round_key(state: list[list[int]], round_key: bytes) -> None:
    for column in range(4):
        for row in range(4):
            state[row][column] ^= round_key[4 * column + row]

def _sub_bytes(state: list[list[int]], box: tuple[int, ...]) -> None:
    for row in range(4):
        for column in range(4):
            state[row][column] = box[state[row][column]]

def _shift_rows(state: list[list[int]]) -> None:
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]

def _inv_shift_rows(state: list[list[int]]) -> None:
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]

def _mix_columns(state: list[list[int]]) -> None:
    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        state[0][column] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        state[1][column] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        state[2][column] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        state[3][column] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)

def _inv_mix_columns(state: list[list[int]]) -> None:
    for column in range(4):
        a0, a1, a2, a3 = (state[row][column] for row in range(4))
        state[0][column] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        state[1][column] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        state[2][column] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        state[3][column] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)

def encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("Blok AES harus tepat 16 byte.")
    round_keys = _expand_key(key)
    state = [[block[4 * column + row] for column in range(4)] for row in range(4)]
    _add_round_key(state, round_keys[0])
    for round_no in range(1, 10):
        _sub_bytes(state, S_BOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_no])
    _sub_bytes(state, S_BOX)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return bytes(state[row][column] for column in range(4) for row in range(4))


def decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("Blok AES harus tepat 16 byte.")
    round_keys = _expand_key(key)
    state = [[block[4 * column + row] for column in range(4)] for row in range(4)]
    _add_round_key(state, round_keys[10])
    for round_no in range(9, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, INV_S_BOX)
        _add_round_key(state, round_keys[round_no])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, INV_S_BOX)
    _add_round_key(state, round_keys[0])
    return bytes(state[row][column] for column in range(4) for row in range(4))

def _mac_key(key: bytes) -> bytes:
    return hashlib.sha256(b"KI-ETS AES-CBC MAC key\x00" + key).digest()

def encrypt_ascii(key: str, plaintext: str, purpose: str) -> dict[str, str]:
    raw_key = validate_key(key)
    try:
        data = plaintext.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Plaintext harus berisi karakter ASCII.") from exc
    if not purpose or not purpose.isascii():
        raise ValueError("Label purpose harus berupa ASCII dan tidak kosong.")
    padding = 16 - (len(data) % 16)
    data += bytes([padding]) * padding
    iv = secrets.token_bytes(16)
    previous = iv
    encrypted = bytearray()
    for offset in range(0, len(data), 16):
        block = bytes(left ^ right for left, right in zip(data[offset:offset + 16], previous))
        previous = encrypt_block(raw_key, block)
        encrypted.extend(previous)
    body = purpose.encode("ascii") + b"\x00" + iv + bytes(encrypted)
    tag = hmac.new(_mac_key(raw_key), body, hashlib.sha256).digest()
    return {"purpose": purpose, "iv": iv.hex(), "ciphertext": bytes(encrypted).hex(), "tag": tag.hex()}

def decrypt_ascii(key: str, envelope: dict[str, str], expected_purpose: str) -> str:
    raw_key = validate_key(key)
    try:
        purpose = envelope["purpose"]
        iv = bytes.fromhex(envelope["iv"])
        ciphertext = bytes.fromhex(envelope["ciphertext"])
        received_tag = bytes.fromhex(envelope["tag"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Envelope AES tidak lengkap atau format hex tidak valid.") from exc
    if purpose != expected_purpose:
        raise ValueError("Label purpose envelope tidak sesuai.")
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise ValueError("Panjang IV atau ciphertext tidak valid.")
    body = purpose.encode("ascii") + b"\x00" + iv + ciphertext
    expected_tag = hmac.new(_mac_key(raw_key), body, hashlib.sha256).digest()
    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("Tag autentikasi salah: key tidak cocok atau data telah berubah.")
    previous = iv
    plaintext = bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        decrypted = decrypt_block(raw_key, block)
        plaintext.extend(left ^ right for left, right in zip(decrypted, previous))
        previous = block
    padding = plaintext[-1]
    if padding < 1 or padding > 16 or plaintext[-padding:] != bytes([padding]) * padding:
        raise ValueError("Padding plaintext tidak valid.")
    try:
        return bytes(plaintext[:-padding]).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Hasil dekripsi bukan plaintext ASCII.") from exc
