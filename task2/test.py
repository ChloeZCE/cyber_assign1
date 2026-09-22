#!/usr/bin/env python3
"""Self-test for Task 2.

The checks are mathematical, so any correct implementation passes:

  * the continued fraction you return must evaluate back to p/q
  * your convergents must match the recurrence built from your own c.f.
  * decrypting your flag with the recovered d must give back a readable flag
    that contains your student number.

Run:  python3 test.py
"""

import json
import os
import sys

import wiener_attack

GREEN, RED, YELLOW, BLUE, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[34m", "\033[0m"


def ok(msg):
    print("{}{}{}".format(GREEN, msg, RESET))


def fail(msg):
    print("{}[-] {}{}".format(RED, msg, RESET))


def warn(msg):
    print("{}{}{}".format(YELLOW, msg, RESET))


def evaluate(cf):
    """Evaluate a finite continued fraction [a0, a1, ...] as a Fraction."""
    from fractions import Fraction
    value = Fraction(cf[-1])
    for a in reversed(cf[:-1]):
        value = a + 1 / value
    return value


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "inputs_task2.json"), "r", encoding="utf-8") as fh:
        inputs = json.load(fh)

    student_id = wiener_attack.get_student_number()
    print("{}student number: {!r}{}".format(BLUE, student_id, RESET))
    if student_id not in inputs:
        fail("your student number is not in the roster, please check it")
        return

    data = inputs[student_id]
    n, e, c = data["N"], data["e"], data["c"]
    score = 0

    # ---- part 1: continued fraction -------------------------------------
    from fractions import Fraction
    p_test, q_test = 355, 113
    cf = list(wiener_attack.continued_fraction(p_test, q_test))
    if not cf or not all(isinstance(a, int) for a in cf):
        fail("continued_fraction() must return a list of integers")
    elif evaluate(cf) != Fraction(p_test, q_test):
        fail("continued_fraction({}, {}) = {} does not evaluate back to {}".format(
            p_test, q_test, cf, Fraction(p_test, q_test)))
    else:
        ok("[+] continued_fraction(355, 113) = {}".format(cf))
        score += 1

    # ---- part 2: convergents --------------------------------------------
    cf_check = [3, 7, 16]      # fixed input, independent of part 1
    conv = [tuple(x) for x in wiener_attack.convergents(cf_check)]
    expected = []
    h1, h2 = 1, 0
    k1, k2 = 0, 1
    for a in cf_check:
        h = a * h1 + h2
        k = a * k1 + k2
        expected.append((h, k))
        h2, h1 = h1, h
        k2, k1 = k1, k
    if conv != expected:
        fail("convergents({}) = {}\n    expected {}".format(cf_check, conv, expected))
    else:
        ok("[+] convergents are correct: {}".format(conv[:4] + ["..."]))
        score += 1

    # ---- part 3: the attack ---------------------------------------------
    d = wiener_attack.wiener_attack(e, n)
    if not d:
        fail("wiener_attack() returned no private exponent")
    else:
        m = pow(c, d, n)
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if d ** 4 * 9 < n and student_id.encode() in raw:
            ok("[+] wiener_attack() recovered d = {}... ({} bits)".format(
                str(d)[:18], d.bit_length()))
            ok("[+] your flag is {}".format(raw.decode(errors="replace")))
            score += 1
        else:
            fail("the recovered d does not decrypt your flag correctly "
                 "(got {!r})".format(raw[:40]))

    if score == 3:
        print("{}+------------------------------+{}".format(GREEN, RESET))
        print("{}|  Task 2 passed, 20/20 points |{}".format(GREEN, RESET))
        print("{}+------------------------------+{}".format(GREEN, RESET))
    else:
        warn("Task 2 is not finished yet ({}/3 checks passed).".format(score))


if __name__ == "__main__":
    sys.exit(main())
