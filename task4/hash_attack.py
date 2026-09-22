"""Task 4 - Hash attacks  (25 points: 3 + 2 + 3 + 7 + 10)

  md5_padding(msg_len)                                       3 points
  md5_compress(state, block)                                 2 points
  md5_hash(data)                                             3 points
  length_extension_forgery(key_len, msg, mac, extra)         7 points
  find_collision(salt, bits)                                 10 points

GOAL:
  4.1 implement MD5 from scratch;
  4.2 forge a valid MAC without knowing the secret key: given
      MAC = MD5(key || msg), the length of the key and a suffix `extra`,
      produce (msg || padding || extra, MD5(key || that));
  4.3 find two different messages with the same 40-bit truncated digest
       MD5(salt || message)[:5] (a birthday attack; hashlib is allowed here);
  4.4 unlock your flag: `mac.flag_ct` is `CRYPTO{h4sh_<your student number>}`
      XORed with the keystream

          SHA-256(b"hash|" + forged_mac)   (repeated),

      so the flag appears exactly when your forged MAC is the right one.

Conventions
  * `md5_padding(msg_len)` returns the whole Merkle-Damgard padding for a
    message of `msg_len` bytes: 0x80, then zero bytes so that the total length
    is 56 modulo 64, then the message length in bits as a 64-bit
    little-endian integer.  The message itself is not part of the result.
  * `md5_compress(state, block)` compresses one 64-byte block into the
    chaining state: `state` is the tuple (a, b, c, d) of four 32-bit
    integers, and the return value is the new tuple.  The initial state is
        (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476).
  * `md5_hash(data)` returns the 16-byte digest as `bytes` (identical to
    `hashlib.md5(data).digest()`).
  * `length_extension_forgery(key_len, msg, mac, extra)` gets the *length* of
    the secret key and the MAC `mac = MD5(key || msg)`; it must return
    `(forged_msg, forged_mac)` with
        forged_msg = msg || padding(key_len + len(msg)) || extra
        forged_mac = MD5(key || forged_msg),
    without ever knowing the key.
  * `find_collision(salt, bits)` must return two *different* byte strings m1
    and m2 with MD5(salt || m1) and MD5(salt || m2) agreeing on their first
    `bits` bits (here `bits` is 40, so `bits // 8` bytes of the digest).

Data in `inputs_task4.json`:

    {"mac": {"key_len": .., "msg": "hex", "tag": "hex", "extra": "hex",
             "flag_ct": "hex"},
     "collision": {"salt": "hex", "bits": 40}}

Run `python3 test.py` to check yourself.  Only the standard library may be
    used (`hashlib` is allowed for the collision search in 4.3, but 4.1 and 4.2
    must be your own MD5).
"""

import struct

IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

K = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A,
    0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340,
    0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
    0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
    0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92,
    0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]

SHIFT = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4
         + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)

MASK = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def _not32(x):
    return x ^ MASK


def md5_padding(msg_len):
    """Return the Merkle-Damgard padding bytes for a message of msg_len bytes."""
    pad_len = (56 - (msg_len + 1)) % 64
    return b"\x80" + b"\x00" * pad_len + struct.pack("<Q", (msg_len * 8) % (1 << 64))


def md5_compress(state, block):
    """Compress one 64-byte `block` into the 4-word chaining `state`."""
    a0, b0, c0, d0 = state
    words = struct.unpack("<16I", block)
    a, b, c, d = a0, b0, c0, d0
    for i in range(64):
        if i < 16:
            f = (b & c) | (_not32(b) & d)
            g = i
        elif i < 32:
            f = (d & b) | (_not32(d) & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | _not32(d))
            g = (7 * i) % 16
        f = (f + a + K[i] + words[g]) & MASK
        a, d, c = d, c, b
        b = (b + _rotl(f, SHIFT[i])) & MASK
    return ((a0 + a) & MASK, (b0 + b) & MASK, (c0 + c) & MASK, (d0 + d) & MASK)


def md5_hash(data):
    """Return the 16-byte MD5 digest of `data`."""
    padded = bytes(data) + md5_padding(len(data))
    state = IV
    for i in range(0, len(padded), 64):
        state = md5_compress(state, padded[i:i + 64])
    return struct.pack("<4I", *state)


def length_extension_forgery(key_len, msg, mac, extra):
    """Forge MD5(key || msg || padding || extra) from the MAC of msg.

    Returns the tuple (forged_msg, forged_mac).
    """
    msg = bytes(msg)
    mac = bytes(mac)
    extra = bytes(extra)

    padding = md5_padding(key_len + len(msg))
    forged_msg = msg + padding + extra

    state = struct.unpack("<4I", mac)
    processed_len = key_len + len(msg) + len(padding)
    tail = extra + md5_padding(processed_len + len(extra))
    for i in range(0, len(tail), 64):
        state = md5_compress(state, tail[i:i + 64])
    forged_mac = struct.pack("<4I", *state)

    return forged_msg, forged_mac


def find_collision(salt, bits):
    """Return two different messages with the same truncated MD5(salt || m)."""
    import hashlib

    width = bits // 8
    seen = {}
    counter = 0
    while True:
        candidate = counter.to_bytes(8, "big")
        digest = hashlib.md5(bytes(salt) + candidate).digest()[:width]
        if digest in seen:
            return seen[digest], candidate
        seen[digest] = candidate
        counter += 1


def get_student_number():
    return "3035987788"
