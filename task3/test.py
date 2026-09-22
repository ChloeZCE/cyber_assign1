#!/usr/bin/env python3
"""Self-test for Task 3.

The checks are mathematical, so any correct implementation passes:

  * your CRT solution must satisfy every congruence and lie in [0, prod)
  * your cube root r must satisfy r**3 <= x < (r+1)**3
  * the recovered message must satisfy m**3 = C_i (mod N_i) for all three
    receivers and decode to a flag containing your student number

Run:  python3 test.py
"""

import json
import math
import os
import random

import broadcast_attack

GREEN, RED, YELLOW, BLUE, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[34m", "\033[0m"


def ok(msg):
    print("{}{}{}".format(GREEN, msg, RESET))


def fail(msg):
    print("{}[-] {}{}".format(RED, msg, RESET))


def warn(msg):
    print("{}{}{}".format(YELLOW, msg, RESET))


def check_crt():
    rng = random.Random(2026)
    primes = [1000003, 1000033, 1000037, 1000039, 1000081]
    for count in (2, 3, 4, 5):
        moduli = primes[:count]
        remainders = [rng.randrange(m) for m in moduli]
        try:
            x = broadcast_attack.crt(remainders, moduli)
        except Exception as exc:
            fail("crt() raised {}".format(exc))
            return False
        total = math.prod(moduli)
        if not isinstance(x, int) or not 0 <= x < total or \
                any(x % m != r for r, m in zip(remainders, moduli)):
            fail("crt({}, {}) = {} does not solve the congruences"
                 .format(remainders, moduli, x))
            return False
    ok("[+] crt() solves the congruences for 2, 3, 4 and 5 moduli")
    return True


def check_cube_root():
    values = [0, 1, 7, 8, 26, 27, 28, 10 ** 30, 10 ** 30 + 1,
              (12 ** 40) - 1, 12 ** 120]
    for x in values:
        try:
            r = broadcast_attack.integer_cube_root(x)
        except Exception as exc:
            fail("integer_cube_root() raised {}".format(exc))
            return False
        if not isinstance(r, int) or not (r ** 3 <= x < (r + 1) ** 3):
            fail("integer_cube_root({}) = {} is not the integer cube root"
                 .format(str(x)[:24], r))
            return False
    ok("[+] integer_cube_root() is exact on {} values".format(len(values)))
    return True


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "inputs_task3.json"), "r", encoding="utf-8") as fh:
        inputs = json.load(fh)

    student_id = broadcast_attack.get_student_number()
    print("{}student number: {!r}{}".format(BLUE, student_id, RESET))
    if student_id not in inputs:
        fail("your student number is not in the roster, please check it")
        return
    data = inputs[student_id]
    checks = 0

    if check_crt():
        checks += 1
    if check_cube_root():
        checks += 1

    m = broadcast_attack.recover_msg(data["N0"], data["N1"], data["N2"],
                                     data["C0"], data["C1"], data["C2"])
    if not isinstance(m, int) or any(pow(m, 3, data["N{}".format(i)]) != data["C{}".format(i)]
                                     for i in range(3)):
        fail("recover_msg() did not return an m with m**3 = C_i (mod N_i)"
             " for all three receivers")
    else:
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if student_id.encode() in raw:
            ok("[+] your flag is {}".format(raw.decode(errors="replace")))
            checks += 1
        else:
            fail("recover_msg() returned {!r}, which is not your flag"
                 .format(raw[:40]))

    if checks == 3:
        print("{}+------------------------------+{}".format(GREEN, RESET))
        print("{}|  Task 3 passed, 20/20 points |{}".format(GREEN, RESET))
        print("{}+------------------------------+{}".format(GREEN, RESET))
    else:
        warn("Task 3 is not finished yet ({}/3 checks passed).".format(checks))


if __name__ == "__main__":
    main()
