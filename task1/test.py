#!/usr/bin/env python3
"""Self-test for Task 1.

Everything is checked mathematically, so any correct implementation passes:

  * your is_waldo() answers must agree with gcd(n1, n2) != 1
  * the classmate you pick must share a prime with you
  * the recovered d must decrypt your own ciphertext into your flag

Run:  python3 test.py
"""

import json
import math
import os

import get_private_key

GREEN, RED, YELLOW, BLUE, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[34m", "\033[0m"


def ok(msg):
    print("{}{}{}".format(GREEN, msg, RESET))


def fail(msg):
    print("{}[-] {}{}".format(RED, msg, RESET))


def warn(msg):
    print("{}{}{}".format(YELLOW, msg, RESET))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "inputs_task1.json"), "r", encoding="utf-8") as fh:
        data = json.load(fh)
    public_keys = data["public_keys"]

    student_id = get_private_key.get_student_number()
    print("{}student number: {!r}{}".format(BLUE, student_id, RESET))
    if student_id not in data["students"]:
        fail("your student number is not in the roster, please check it")
        return
    mine = data["students"][student_id]
    n, e, c = mine["N"], mine["e"], mine["c"]
    checks = 0

    # ---- is_waldo --------------------------------------------------------
    wrong = []
    for other_id, other_n in public_keys.items():
        if other_id == student_id:
            continue
        expected = math.gcd(n, other_n) != 1
        try:
            answer = bool(get_private_key.is_waldo(n, other_n))
        except Exception as exc:
            fail("is_waldo() raised {}".format(exc))
            return
        if answer != expected:
            wrong.append(other_id)
    if wrong:
        fail("is_waldo() gave the wrong answer for {} of {} classmates, "
             "e.g. {}".format(len(wrong), len(public_keys) - 1, wrong[:3]))
    else:
        ok("[+] is_waldo() is correct for all {} classmates".format(
            len(public_keys) - 1))
        checks += 1

    # ---- find Waldo, then the private key --------------------------------
    waldo = None
    for other_id, other_n in public_keys.items():
        if other_id != student_id and get_private_key.is_waldo(n, other_n):
            waldo = (other_id, other_n)
            break
    if waldo is None:
        fail("nobody shares a prime with you, go back to the previous step")
        return
    ok("[+] Waldo is {} (gcd = {}...)".format(waldo[0], str(math.gcd(n, waldo[1]))[:16]))

    d = get_private_key.get_private_key_from_n1_n2_e(n, waldo[1], e)
    p = math.gcd(n, waldo[1])
    q = n // p
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    if not isinstance(d, int) or d <= 0 or (e * d) % lam != 1:
        fail("the recovered d is not the inverse of e modulo lcm(p-1, q-1)")
    else:
        ok("[+] e * d == 1 (mod lcm(p-1, q-1))")
        checks += 1
        m = pow(c, d, n)
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if student_id.encode() in raw:
            ok("[+] your flag is {}".format(raw.decode(errors="replace")))
        else:
            warn("[?] the decrypted value {!r} does not look like your flag"
                 .format(raw[:40]))

    if checks == 2:
        print("{}+------------------------------+{}".format(GREEN, RESET))
        print("{}|  Task 1 passed, 15/15 points |{}".format(GREEN, RESET))
        print("{}+------------------------------+{}".format(GREEN, RESET))
    else:
        warn("Task 1 is not finished yet ({}/2 checks passed).".format(checks))


if __name__ == "__main__":
    main()
