"""Task 3 - Broadcast attack  (20 points: 5 + 5 + 10)

  crt(remainders, moduli)                     -> x      5 points
  integer_cube_root(x)                        -> root   5 points
  recover_msg(N0, N1, N2, C0, C1, C2)         -> m      10 points

GOAL: the same short flag was sent to three receivers with the small exponent
e = 3, without padding.  Recover the plaintext from the three ciphertexts
alone - no private key, no factoring.  The plaintext looks like
CRYPTO{br0adcast_<your student number>}.

The same short flag was encrypted with the small exponent e = 3 under three
different RSA moduli, i.e.

    C_i = m^3 mod N_i     for i = 0, 1, 2.

The Chinese Remainder Theorem gives m^3 modulo N0*N1*N2, and because the flag
is much shorter than those 1536 bits the result is exactly m^3 - so an integer
cube root of that value is the plaintext.  (This is Hasted's broadcast attack;
in general one needs e ciphertexts for the e-th root to be exact.)

`inputs_task3.json` gives you, per student:

    {"e": 3, "N0": .., "N1": .., "N2": .., "C0": .., "C1": .., "C2": ..}

Implement

  * `crt(remainders, moduli)`: solve x = remainders[i] (mod moduli[i]) for
    pairwise coprime moduli, and return the solution with 0 <= x < prod(moduli).
  * `integer_cube_root(x)`: the integer floor of the real cube root of x.
  * `recover_msg(N0, N1, N2, C0, C1, C2)`: the flag as an integer.  Your flag
    is `CRYPTO{br0adcast_<your student number>}`.

Run `python3 test.py` to check yourself.  Only the Python standard library may
be used.
"""


def _egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_r, old_s  # gcd, x  such that a*x + b*y = gcd


def crt(remainders, moduli):
    """Solve the simultaneous congruences, return 0 <= x < prod(moduli)."""
    total = 1
    for m in moduli:
        total *= m

    x = 0
    for r, m in zip(remainders, moduli):
        M = total // m
        _, inv = _egcd(M, m)
        x += r * M * (inv % m)
    return x % total


def integer_cube_root(x):
    """Return the largest integer r with r**3 <= x."""
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0
    r = max(1 << ((x.bit_length() + 2) // 3), 1)
    while True:
        new_r = (2 * r + x // (r * r)) // 3
        if new_r >= r:
            break
        r = new_r
    while r ** 3 > x:
        r -= 1
    while (r + 1) ** 3 <= x:
        r += 1
    return r


def recover_msg(N0, N1, N2, C0, C1, C2):
    """Recover the broadcast message as an integer."""
    m_cubed = crt([C0, C1, C2], [N0, N1, N2])
    return integer_cube_root(m_cubed)


def get_student_number():
    return "3035987788"
