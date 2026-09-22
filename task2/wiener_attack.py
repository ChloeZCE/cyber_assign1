"""Task 2 - Wiener's Attack  (20 points: 4 + 4 + 12)

GOAL: your RSA key has a 1024-bit modulus N but a deliberately small private
exponent d (d < N^(1/4)/3).  Recover d from the public key (e, N) with a
continued-fraction attack and decrypt your flag
(it looks like CRYPTO{w1ener_<your student number>}).

Your RSA key has a 1024-bit modulus N = p*q but the private exponent d is
small (d < N^(1/4)/3), so (N, e) leaks d through the continued fraction
expansion of e/N.

  continued_fraction(p, q) -> [a0, a1, a2, ...]   4 points
  convergents(cf)          -> [(h0, k0), ...]     4 points
  wiener_attack(e, N)      -> d                   12 points

`convergents` returns *all* convergents of the expansion, in order, as
(numerator, denominator) tuples, using
    h_{-1} = 1, h_{-2} = 0,   k_{-1} = 0, k_{-2} = 1,
    h_i = a_i * h_{i-1} + h_{i-2},   k_i = a_i * k_{i-1} + k_{i-2}.

Read `inputs_task2.json` for your data:
    {"N": <int>, "e": <int>, "c": <int>}   # c is your encrypted flag

Do not use any third-party module.  Run `python3 test.py` to check yourself.
"""


import math


def continued_fraction(p, q):
    """Return the continued fraction expansion of p/q as a list of integers."""
    cf = []
    while q:
        a = p // q
        cf.append(a)
        p, q = q, p - a * q
    return cf


def convergents(cf):
    """Return the list of convergents (numerator, denominator) of cf."""
    conv = []
    h_prev1, h_prev2 = 1, 0
    k_prev1, k_prev2 = 0, 1
    for a in cf:
        h = a * h_prev1 + h_prev2
        k = a * k_prev1 + k_prev2
        conv.append((h, k))
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k
    return conv


def wiener_attack(e, N):
    """Return the small private exponent d of the RSA key (e, N)."""
    cf = continued_fraction(e, N)
    for num, den in convergents(cf):
        # candidate k/d = num/den from the key equation e*d = 1 + k*phi(N)
        if num == 0 or den == 0:
            continue
        if (e * den - 1) % num != 0:
            continue
        phi = (e * den - 1) // num
        # p + q = N - phi + 1, p*q = N  =>  solve the quadratic for p, q
        s = N - phi + 1
        disc = s * s - 4 * N
        if disc < 0:
            continue
        root = math.isqrt(disc)
        if root * root != disc:
            continue
        if (s - root) % 2 != 0:
            continue
        p = (s - root) // 2
        q = (s + root) // 2
        if p > 1 and q > 1 and p * q == N:
            return den
    return 0


def get_student_number():
    return "3035987788"
