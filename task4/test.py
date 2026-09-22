#!/usr/bin/env python3
"""Self-test for Task 4.

  * your MD5 is compared with hashlib (many message lengths, padding included)
  * your forged message must have the right structure *and* the forged MAC
    must unlock your flag - only MD5(key || forged_msg) does, so this is a
    definite answer even though the key itself is secret
  * your collision is checked directly against MD5

Run:  python3 test.py
"""

import hashlib
import json
import os
import sys
import time

import hash_attack

GREEN, RED, YELLOW, BLUE, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[34m", "\033[0m"


def ok(msg):
    print("{}{}{}".format(GREEN, msg, RESET))


def fail(msg):
    print("{}[-] {}{}".format(RED, msg, RESET))


def warn(msg):
    print("{}{}{}".format(YELLOW, msg, RESET))


def check_md5():
    data = b"the quick brown fox jumps over the lazy dog"
    lengths = [0, 1, 2, 3, 55, 56, 57, 63, 64, 65, 100, 119, 120, 128, 300]
    for n in lengths:
        message = (data * 20)[:n]
        got = hash_attack.md5_hash(message)
        if got != hashlib.md5(message).digest():
            fail("md5_hash() is wrong for a {}-byte message: got {}, expected {}"
                 .format(n, got.hex()[:16], hashlib.md5(message).hexdigest()[:16]))
            return False
    for n in [0, 1, 55, 56, 64, 1000]:
        pad = hash_attack.md5_padding(n)
        if (n + len(pad)) % 64 != 0 or len(pad) < 9:
            fail("md5_padding({}) returned {} bytes - a padded message must be "
                 "a multiple of 64 bytes and end with the 8-byte length"
                 .format(n, len(pad)))
            return False
        if hash_attack.md5_hash(b"A" * n) != hashlib.md5(b"A" * n).digest():
            fail("md5_padding({}) combined with md5_hash() does not match hashlib"
                 .format(n))
            return False
    # md5_compress() is exercised by every md5_hash() call above; here we only
    # check that it has the documented shape
    state = hash_attack.md5_compress(hash_attack.IV, b"\x00" * 64)
    if len(state) != 4 or any(not isinstance(x, int) or not 0 <= x <= 0xFFFFFFFF
                              for x in state):
        fail("md5_compress() must return four 32-bit integers (a, b, c, d)")
        return False
    ok("[+] MD5 implementation matches hashlib on {} message lengths".format(len(lengths)))
    return True


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "inputs_task4.json"), "r", encoding="utf-8") as fh:
        inputs = json.load(fh)

    student_id = hash_attack.get_student_number()
    print("{}student number: {!r}{}".format(BLUE, student_id, RESET))
    if student_id not in inputs:
        fail("your student number is not in the roster, please check it")
        return
    data = inputs[student_id]
    checks = 0

    # ---- 4.1 -------------------------------------------------------------
    if check_md5():
        checks += 1

    # ---- 4.2 -------------------------------------------------------------
    mac = data["mac"]
    msg = bytes.fromhex(mac["msg"])
    tag = bytes.fromhex(mac["tag"])
    extra = bytes.fromhex(mac["extra"])
    forged_msg, forged_mac = hash_attack.length_extension_forgery(
        mac["key_len"], msg, tag, extra)
    expected = msg + hash_attack.md5_padding(mac["key_len"] + len(msg)) + extra
    if bytes(forged_msg) != expected:
        fail("the forged message has the wrong structure:\n    got      {}\n    expected {}"
             .format(bytes(forged_msg).hex(), expected.hex()))
    elif len(bytes(forged_mac)) != 16:
        fail("the forged MAC must be a 16-byte digest")
    else:
        # The flag is XORed with the keystream SHA-256(b"hash|" + forged_mac)
        # repeated, so it only becomes readable when your MAC is exactly the
        # one the server computes, i.e. MD5(key || forged_msg).
        seed = hashlib.sha256(b"hash|" + bytes(forged_mac)).digest()
        flag_ct = bytes.fromhex(mac["flag_ct"])
        stream = (seed * (len(flag_ct) // len(seed) + 1))[:len(flag_ct)]
        raw = bytes(a ^ b for a, b in zip(flag_ct, stream))
        if student_id.encode() not in raw:
            fail("the flag did not decrypt; the forgery is not a MAC the "
                 "server would accept (check the padding and the key length)")
        else:
            ok("[+] 4.2: forgery built ({} bytes, MAC {}...)"
               .format(len(bytes(forged_msg)), bytes(forged_mac).hex()[:16]))
            ok("[+] your flag is {}".format(raw.decode(errors="replace")))
            checks += 1

    # ---- 4.3 -------------------------------------------------------------
    collision = data["collision"]
    salt = bytes.fromhex(collision["salt"])
    bits = collision["bits"]
    start = time.time()
    m1, m2 = hash_attack.find_collision(salt, bits)
    elapsed = time.time() - start
    width = bits // 8
    if bytes(m1) == bytes(m2):
        fail("find_collision() returned two identical messages")
    elif hashlib.md5(salt + bytes(m1)).digest()[:width] != \
            hashlib.md5(salt + bytes(m2)).digest()[:width]:
        fail("the two messages do not collide on the first {} bits".format(bits))
    else:
        ok("[+] 4.3: collision {} / {} found in {:.1f}s"
           .format(bytes(m1).hex(), bytes(m2).hex(), elapsed))
        checks += 1

    if checks == 3:
        print("{}+------------------------------+{}".format(GREEN, RESET))
        print("{}|  Task 4 passed, 25/25 points |{}".format(GREEN, RESET))
        print("{}+------------------------------+{}".format(GREEN, RESET))
    else:
        warn("Task 4 is not finished yet ({}/3 checks passed).".format(checks))


if __name__ == "__main__":
    sys.exit(main())
