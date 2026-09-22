# Cryptography Lab 2026

## 1. Overview

In this lab you play the role of an **attacker**.  For every task you are given
the artifacts of a *deliberately broken* deployment (public keys, ciphertexts,
a captured MAC, a truncated digest ...) and your job is to **break it and
recover a flag**.  You never have the private key, the password or the random
number generator: everything you are given is public information, and the
attack itself is the point of the exercise.

Every student gets a **different instance** (it is generated from your student
number), so your numbers, ciphertexts and flags differ from everybody else's.

### 1.1 The four attacks

| Task | The attack | Your target (what you must recover) | File to submit | Code points | Report marks |
| --- | --- | --- | --- | --- | --- |
| 1 | **Ps and Qs** - two RSA moduli that share a prime factor | your own private key `d`, then your flag | `get_private_key.py` | 15 | 2 |
| 2 | **Wiener's attack** - an RSA key with a small private exponent | the private exponent `d`, then your flag | `wiener_attack.py` | 20 | 5 |
| 3 | **Håstad's broadcast attack** - one message sent to three receivers with `e = 3` | the plaintext, i.e. your flag | `broadcast_attack.py` | 20 | 3 |
| 4 | **Hash attacks** - MD5 as a MAC, and a truncated digest | a forged MAC, a collision, and your flag | `hash_attack.py` | 25 | 5 |

Tasks 1-3 are the RSA classics; task 4 is a more modern attack.  The code is
marked automatically, the report by your tutor (see 1.3).

**Every task ends with the same deliverable: a flag that contains your student
number.**  A flag is a short string, here `CRYPTO{...}`, that proves you
completed the task.  The flag is protected by the very thing you are asked to
break:

| Task | Which "key" unlocks the flag |
| --- | --- |
| 1 | your recovered RSA private exponent `d` |
| 2 | the small private exponent `d` you recover |
| 3 | the plaintext `m` you recover (the flag *is* the plaintext) |
| 4 | the forged MAC you compute |

The self-tests print the flag (`[+] your flag is CRYPTO{...}`), so "did I
finish this task?" always has a precise answer:

* Task 1 - `CRYPTO{psqs_<your student number>}`
* Task 2 - `CRYPTO{w1ener_<your student number>}`
* Task 3 - `CRYPTO{br0adcast_<your student number>}`
* Task 4 - `CRYPTO{h4sh_<your student number>}`

### 1.2 Provide your RSA public key

**[IMPORTANT]** You are also expected to get hands-on experience with
cryptographic applications.  The last part of the assignment asks you to
generate an RSA key pair for yourself and send us **only the public key**;
it will later be used to encrypt your password for the follow-up labs.  So,
take care of your own private key and never share it.

Requirements for the key you submit (5 marks, see 1.3):

* it is an **RSA** key of at least **2048 bits**;
* the file is called `public_key` and contains either a PEM public key
  (`-----BEGIN PUBLIC KEY-----` / `-----BEGIN RSA PUBLIC KEY-----`) or a single
  OpenSSH line (`ssh-rsa AAAA... comment`);
* **never submit a private key** - the grader rejects it.

With OpenSSL:

```bash
openssl genrsa -out private.pem 2048          # keep this file safe and secret
openssl rsa -in private.pem -pubout -out public_key
```

### 1.3 How the lab is marked

The lab mark is out of **100**:

| Component | Marks | Marked by |
| --- | --- | --- |
| Code, four tasks | 80 | the automatic grader |
| Report (2 + 5 + 3 + 5) | 15 | your tutor |
| RSA public key | 5 | the automatic grader |

The four tasks are worth 15 + 20 + 20 + 25 = 80 code points; **your code mark
is exactly the points you collect, with no scaling**.  The grader calls the
functions you were asked to implement and checks the *mathematical*
correctness of what you return, so any correct method is accepted.  Partial
credit is given for every sub-task that is correct, and a broken function never
costs marks in another sub-task.  Your tutor marks the report on the same
marking sheet that already contains the code and public-key marks.

### 1.4 What you submit

Put the four Python files, your public key and your report into a folder named
with your student number, compress it as `<student number>.zip` and submit:

```
<student number>/
    get_private_key.py     # Task 1
    wiener_attack.py       # Task 2
    broadcast_attack.py    # Task 3
    hash_attack.py         # Task 4
    public_key             # your RSA public key (see 1.2)
    report.pdf             # your report (see the report questions)
```

**Do not change the names of these six files** - the automatic grader looks for
exactly these names - and do not change the names of the functions or their
arguments.  The grader searches the whole submission, so you may keep the
`task1/` ... `task4/` folders you were given; what must not change are the six
file names above.

### 1.5 Rules

* Python 3.8 or newer and **only the Python standard library**.
* Fill in `get_student_number()` at the end of every file.  A submission whose
  student number is not on the class list cannot be marked.
* You may discuss the tasks, but the code and the report you hand in must be
  your own.  Submissions are compared with each other.
* Never hard-code an answer: your data is different from everybody else's and
  is regenerated every year.  Answers that are copied from a classmate will not
  even be correct.

At the end of each template:

```python
def get_student_number():
    # TODO: Fill your student number here
    return ""
```

Change the return value to your own student number, for example
`return "3030202610"`.  The grader uses it to look up *your* data.

### 1.6 How to work on a task

Every task folder contains

* `inputs_taskN.json` - your data (Task 1 also contains the public moduli of
  the whole class).  Look up your own student number in it;
* the Python file you have to complete (the "template") - its docstring states
  the goal, the required functions and their point values;
* `test.py` - a self-test: `cd` into the folder and run `python3 test.py`.

The self-test needs your student number to be filled in, and it never compares
your answer with a stored answer: it checks **mathematical properties** (that
`p*q == N`, that your key really decrypts the ciphertext, that your forgery
really unlocks the flag, that your collision really collides, ...).  When a
task is finished you will see, for example:

```
$ cd task1 && python3 test.py
student number: '3030202610'
[+] is_waldo() is correct for all 119 classmates
[+] Waldo is 3035921899 (gcd = 1234...)
[+] e * d == 1 (mod lcm(p-1, q-1))
[+] your flag is CRYPTO{psqs_3030202610}
+------------------------------+
|  Task 1 passed, 15/15 points |
+------------------------------+
```

(the number of classmates and the partner's student number are, of course,
different for you).  The points a self-test prints are the code points of that
task; the grader uses the same sub-scores, so if all four self-tests pass you
have the full 80/80 code points.

---

## 2. Task 1 - Ps and Qs Attack (15 points)

### 2.1 The scenario

A campus network issued an RSA key pair to every student using a home-made key
generator.  The generator is broken: when the machine rebooted, its random
number generator restarted from the same state, so several students were handed
**the same prime number**.  Nobody noticed, because each modulus `N` still looks
perfectly random.

You are given the public moduli of the whole class and one encrypted flag -
yours.  There is no private key anywhere in the data.

### 2.2 Your goal

**Recover your own RSA private exponent `d` using only public information and
decrypt your flag.**  The flag is `CRYPTO{psqs_<your student number>}`.

The attack in one sentence: if two moduli share a prime factor `p`, then
`p = gcd(N1, N2)` - one gcd factors *both* keys - and with the factorisation the
private key follows.

### 2.3 The cryptography you need

RSA in three lines: pick two large primes `p` and `q`, let `N = p*q` and
`phi(N) = (p-1)*(q-1)`; choose a public exponent `e` (usually 65537) coprime to
`phi(N)` and compute `d = e^(-1) mod phi(N)`.  Then

* encryption: `c = m^e mod N`;
* decryption: `m = c^d mod N`.

Decryption works because of **Euler's theorem**: for `m` coprime to `N`,
`m^phi(N) = 1 mod N`, so `m^(e*d) = m^(1 + k*phi(N)) = m`.  The same holds for
`lambda(N) = lcm(p-1, q-1)`, a smaller exponent with the same property - either
one gives a valid `d`.  Security rests on the belief that factoring `N` is hard;
the whole point of this task is that the factorisation is *not* hard when two
moduli share a prime.

### 2.4 What you are given

`inputs_task1.json`:

```json
{"public_keys": {"<student number>": <N>, ...},
 "students":    {"<student number>": {"N": ..., "e": ..., "c": ...}}}
```

| Field | Meaning |
| --- | --- |
| `public_keys` | the RSA modulus of **every** student in the class (including yours) |
| `students[<you>]["N"]`, `["e"]` | your own public key |
| `students[<you>]["c"]` | your flag, encrypted with your public key |

### 2.5 What you must implement

```python
def is_waldo(n1, n2)                        # 6 points
def get_private_key_from_n1_n2_e(n1, n2, e) # 9 points
```

* `is_waldo(n1, n2)` - "is this classmate Waldo?": return `True` if the two
  moduli share a non-trivial factor, otherwise `False`.  This is how you find
  the classmate whose key shares your prime.
* `get_private_key_from_n1_n2_e(n1, n2, e)` - given **your** modulus `n1`, the
  modulus `n2` of that classmate and your public exponent, return **your**
  private exponent `d`.

### 2.6 How your answer is checked

| Check | Points | How |
| --- | --- | --- |
| `is_waldo` | 6 | called with your modulus against the classmates who share your prime (up to two of them) and four who do not - between five and six answers, all of which must be right |
| `get_private_key_from_n1_n2_e` | 9 | called with your modulus and a real partner's; your `d` must satisfy `e*d = 1 mod lambda(N)` **and** decrypt your ciphertext into `CRYPTO{psqs_<you>}` |

### 2.7 Report (2 marks)

1. Explain the workflow of the attack: how a shared prime is detected, how the
   two moduli are factored, how the private key is derived. (1 mark)
2. How can this attack be prevented in practice? (1 mark)

---

## 3. Task 2 - Wiener's Attack (20 points)

### 3.1 The scenario

A legacy server wanted "fast" RSA, so its key generator used a **deliberately
short private exponent** `d` while keeping the 1024-bit modulus.  Its public key
`(N, e)` was published as usual.  The administrator believes that as long as `N`
is long enough the key is safe; it is not, because a small `d` is visible in the
continued fraction expansion of the *public* number `e/N`.

### 3.2 Your goal

**Recover the private exponent `d` from `(N, e)` alone and decrypt your flag**:
`CRYPTO{w1ener_<your student number>}`.

### 3.3 The cryptography you need

RSA's key equation is `e*d = 1 + k*phi(N)` for some integer `k`.  Dividing by
`d*phi(N)` gives `e/phi(N) - k/d = 1/(d*phi(N))`, and since
`phi(N) = N - (p+q) + 1` with `p+q` about `2*sqrt(N)`, the *public* ratio `e/N`
is an extremely good approximation of the *secret* fraction `k/d`.

A **continued fraction** is another way of writing a number,

$$x = a_0 + \frac{1}{a_1 + \frac{1}{a_2 + \dots}} = [a_0, a_1, a_2, \dots],$$

computed greedily with the Euclidean algorithm (the quotients of Euclid's
algorithm *are* the coefficients).  Its **convergents** are the rationals
obtained by truncating it: `[3, 7, 16]` gives `3/1`, `22/7`, `355/113`.  These
are the best rational approximations of the number, and **Legendre's theorem**
says that any rational closer than `1/(2*k^2)` *must* be one of them.  Since the
error above is below `1/(2*d^2)` whenever `d < N^(1/4)/3`, the secret fraction
`k/d` is guaranteed to be among the convergents of the public `e/N` - so the
private key can be read off public data.

### 3.4 What you are given

`inputs_task2.json`: `{"N": <1024-bit integer>, "e": <integer>, "c": <integer>}`
- your public key and your encrypted flag.

### 3.5 What you must implement

```python
def continued_fraction(p, q)   # 4 points: [a0, a1, a2, ...] of p/q
def convergents(cf)            # 4 points: [(h0,k0), (h1,k1), ...] in order
def wiener_attack(e, N)        # 12 points: the small private exponent d
```

`convergents` must return *all* convergents in order, using
`h(-1)=1, h(-2)=0, k(-1)=0, k(-2)=1` and
`h_i = a_i*h_(i-1) + h_(i-2)`, `k_i = a_i*k_(i-1) + k_(i-2)`.

### 3.6 How your answer is checked

| Check | Points | How |
| --- | --- | --- |
| `continued_fraction` | 4 | five rationals compared with the reference expansion |
| `convergents` | 4 | five expansions compared element by element |
| `wiener_attack` | 12 | your `d` must be a private exponent of `(e, N)`, satisfy `9*d^4 < N`, and decrypt your ciphertext into `CRYPTO{w1ener_<you>}` |

### 3.7 Report (5 marks)

1. Compute the continued fraction and the convergents of `355/113` by hand,
   showing the steps. (2 marks)
2. Show that `e/N` is approximately `k/d`. (1 mark)
3. Prove that `d < N^(1/4)/3` satisfies Legendre's condition
   `|e/N - k/d| < 1/(2d^2)`. (2 marks)

---

## 4. Task 3 - Håstad's Broadcast Attack (20 points)

### 4.1 The scenario

A server has to deliver the same short secret - a session key, stored here as a
flag - to three different receivers.  Instead of using a proper hybrid scheme it
does the "obvious" thing: it RSA-encrypts the secret separately for each
receiver with the small public exponent `e = 3`, **without random padding**.
You captured the three public moduli and the three ciphertexts.

Each ciphertext alone is safe (nobody can decrypt it without a private key).
Together they are not.

### 4.2 Your goal

**Recover the message `m` from the three ciphertexts alone - no private key, no
factoring.**  The plaintext is your flag:
`CRYPTO{br0adcast_<your student number>}`.

### 4.3 The cryptography you need

We have `Ci = m^3 mod Ni` for three pairwise coprime moduli, i.e. **three
congruences for the single unknown `m^3`**.  The **Chinese Remainder Theorem
(CRT)** says that a system `x = r_i mod m_i` with pairwise coprime `m_i` has
exactly one solution modulo `M = m_0*m_1*m_2`, namely

$$x = \sum_i r_i\,M_i\,(M_i^{-1} \bmod m_i) \bmod M,\qquad M_i = M/m_i .$$

Because our flag is short, `m^3 < M`, so this solution *is* `m^3` with no
wraparound, and a single integer cube root returns `m`.  (In general, with
exponent `e` you need `e` ciphertexts - hence "broadcast attack".)  Without
padding, three receivers are enough; with randomised padding (OAEP or PKCS#1
v1.5) each receiver would encrypt a *different* value and the attack would
fail - that is why real RSA always pads.

### 4.4 What you are given

`inputs_task3.json`:

```json
{"e": 3, "N0": .., "N1": .., "N2": .., "C0": .., "C1": .., "C2": ..}
```

Three 1024-bit moduli and `Ci = m^3 mod Ni` for the same `m`.

### 4.5 What you must implement

```python
def crt(remainders, moduli)                  # 5 points
def integer_cube_root(x)                     # 5 points
def recover_msg(N0, N1, N2, C0, C1, C2)      # 10 points
```

* `crt(remainders, moduli)` - solve `x = r_i mod m_i` for **any** number of
  pairwise coprime moduli, returning the solution with `0 <= x < prod(m_i)`.
  (You will be tested with 2, 3, 4 and 5 moduli.)
* `integer_cube_root(x)` - the largest integer `r` with `r^3 <= x`.
* `recover_msg(...)` - the flag as an integer.

### 4.6 How your answer is checked

| Check | Points | How |
| --- | --- | --- |
| `crt` | 5 | five cases (2, 3, 4, 5 small prime moduli, and your three 1024-bit ones); all must be correct |
| `integer_cube_root` | 5 | 13 values including perfect cubes and 361-bit numbers; must be exact |
| `recover_msg` | 10 | the returned `m` must satisfy `m^3 = Ci mod Ni` for all three receivers and decode to `CRYPTO{br0adcast_<you>}` |

### 4.7 Report (3 marks)

1. Explain how the CRT combines the three ciphertexts, and why three are enough
   for `e = 3` while two are not. (2 marks)
2. Why does the attack fail if the message is padded with fresh random bytes
   before every encryption? (1 mark)

---

## 5. Task 4 - Hash Attacks (25 points)

### 5.1 The scenario

* **An API gateway** authenticates every request with
  `MAC = MD5(secret_key || request)`: it concatenates a secret key with the
  request and hashes the result, sending the digest along as the "signature".
  This is a classic anti-pattern.  You sniffed one valid request with its MAC,
  and the API documentation tells you the **length** of the secret key (its
  value stays secret).  Your goal is to produce a valid MAC for a request of
  your choosing - without knowing the key.
* **A file integrity check.**  The same server stores `MD5(salt || file)[:5]`,
  only the first 40 bits of the digest, next to each upload.  Your goal is to
  produce two different files that pass the same check.
* The gateway also keeps your **flag**, encrypted with a keystream derived from
  the *correct* forged MAC: a wrong forgery cannot unlock it.

### 5.2 Your goal

1. Implement MD5 from scratch.
2. Extend the captured MAC into a valid MAC for `msg || padding || extra`
   (length extension attack).
3. Find a collision for the 40-bit truncated hash of your own salt.
4. Unlock your flag: `CRYPTO{h4sh_<your student number>}`.

Conditions: the forgery needs the *length* of the key and a message you can
append to; the collision exists because a 40-bit digest is much too short
(birthday bound `2^20`, a few seconds).

### 5.3 The cryptography you need

**Hash functions.**  A cryptographic hash maps an arbitrary-length input to a
fixed-length **digest** (16 bytes for MD5) and should satisfy three properties:
preimage resistance (given a digest you cannot find a preimage),
second-preimage resistance (given a message you cannot find another with the
same digest) and collision resistance (nobody can find *any* two messages with
the same digest).  By the **birthday bound**, collisions in an `n`-bit digest
can be found with about `2^(n/2)` random messages - which is why a digest's
collision security is only half its length.

**MD5 and the Merkle–Damgård construction.**  MD5 processes the message in
64-byte blocks: the four-word state `(a, b, c, d)` starts from a fixed initial
value (IV), each block is mixed into the state by 64 rounds of additions,
rotations and four non-linear functions, and the final state, written
little-endian, is the digest.  The message is first **padded**: a `0x80` byte,
zeros until the length is 56 modulo 64, and finally the message length **in
bits** as a little-endian 64-bit integer.  This structure - state chained block
by block - is the **Merkle–Damgård** construction (also used by SHA-1/SHA-2).

**Length extension.**  Because the digest *is* the chaining state after the last
block, anybody can restart the computation from it, without knowing the key.
Given `MAC = MD5(key || msg)` and knowing `key_len`, an attacker can therefore
compute the padding that was implicitly hashed after `msg`, treat the captured
MAC as the state, and continue hashing an appended suffix `extra`:

```
forged_msg = msg || padding(key_len + len(msg)) || extra
forged_mac = MD5(key || forged_msg)
```

This works *only* for "hash the key with the message" constructions.  The
standard fix is **HMAC**: `H((K xor opad) || H((K xor ipad) || m))`, two nested
hashes, which cannot be extended this way.

**MAC versus plain hash.**  A **MAC** (message authentication code) is the tag
that proves a message came from someone who knows the key.  A plain hash cannot
do that: as this task shows, a hash of `key || message` can be extended by
anyone.  (`flag_ct` is XORed with `SHA-256(b"hash|" + forged_mac)` so that only
the correct forged MAC yields a readable flag.)

**Truncated digests and birthdays.**  The integrity check keeps only the first
40 bits of the digest.  With `N = 2^40` possible values, about
`1.18 * 2^20 ≈ 1.2 million` random files already give a 50% chance of a
collision.  That is a few seconds on a laptop - so truncating a digest is a
serious weakening, and 40 bits is nowhere near enough for integrity.

### 5.4 What you are given

`inputs_task4.json`:

```json
{"mac": {"key_len": .., "msg": "hex", "tag": "hex", "extra": "hex",
         "flag_ct": "hex"},
 "collision": {"salt": "hex", "bits": 40}}
```

| Field | Meaning |
| --- | --- |
| `key_len` | the **length** of the secret key (its value is not given) |
| `msg`, `tag` | a captured request and its MAC `MD5(key \|\| msg)`, hex-encoded |
| `extra` | the suffix you should append to the request, e.g. `&action=admin` |
| `flag_ct` | your flag XORed with `SHA-256(b"hash\|" + forged_mac)` |
| `salt`, `bits` | the per-student salt of the integrity check and the number of digest bits kept (40) |

### 5.5 What you must implement

```python
def md5_padding(msg_len)                # 3 points: the padding bytes only
def md5_compress(state, block)          # 2 points: compress one 64-byte block
def md5_hash(data)                      # 3 points: the 16-byte digest
def length_extension_forgery(key_len, msg, mac, extra)  # 5 + 2 points
def find_collision(salt, bits)          # 10 points
```

* `md5_padding(msg_len)` returns the Merkle–Damgård padding for a message of
  that length (the message itself is not included).
* `md5_compress(state, block)` compresses one 64-byte block into the chaining
  state; `state` is the tuple `(a, b, c, d)` of four 32-bit integers and the
  initial state is `(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)`.
* `md5_hash(data)` returns the 16-byte digest, identical to
  `hashlib.md5(data).digest()`.
* `length_extension_forgery(key_len, msg, mac, extra)` returns
  `(forged_msg, forged_mac)` with
  `forged_msg = msg || padding(key_len + len(msg)) || extra` and
  `forged_mac = MD5(key || forged_msg)`, without ever knowing the key.
* `find_collision(salt, bits)` returns two **different** byte strings whose
  `MD5(salt || message)` agree on the first `bits` bits.

### 5.6 How your answer is checked

| Check | Points | How |
| --- | --- | --- |
| `md5_padding` | 3 | ten lengths must match the reference padding byte for byte |
| `md5_compress` | 2 | four random `(state, block)` pairs must match the reference |
| `md5_hash` | 3 | ten message lengths must match `hashlib` |
| `length_extension_forgery` | 5 | the forged MAC is verified against `MD5(key \|\| forged_msg)` (the grader recomputes the extension of the captured tag and decrypts `flag_ct`, so a wrong MAC scores nothing) |
| `length_extension_forgery` | 2 | the forged message must be exactly `msg \|\| padding \|\| extra` |
| `find_collision` | 10 | two distinct messages with equal first 40 bits of `MD5(salt \|\| message)` |

The grader also writes your flag into its log.

### 5.7 Report (5 marks)

1. Explain why the length extension attack works and what the attacker must
   know beforehand. (2 marks)
2. Why should one use HMAC instead of `MD5(key || message)`? (1 mark)
3. Using the birthday bound, estimate how many messages are needed for a
   collision in a 40-bit and in a 128-bit digest. (2 marks)

---

## 6. Academic integrity

You may use the lecture notes, the references below and public documentation,
but the code and the report must be your own work.  Submissions are compared
with each other and with previous cohorts; copying (or sharing data with a
classmate) is reported.  Remember that every student's data set is different,
so a copied answer will not even be correct.

## 7. References

* Ps and Qs (shared primes in the wild): <https://factorable.net/weakkeys12.extended.pdf>
* RSA and Wiener's attack: <https://en.wikipedia.org/wiki/Wiener%27s_attack>
* Continued fractions: <https://en.wikipedia.org/wiki/Continued_fraction>
* Chinese Remainder Theorem: <https://en.wikipedia.org/wiki/Chinese_remainder_theorem>
* Håstad's broadcast attack: <https://en.wikipedia.org/wiki/Coppersmith%27s_attack>
* MD5 (RFC 1321): <https://www.rfc-editor.org/rfc/rfc1321>
* HMAC (RFC 2104): <https://www.rfc-editor.org/rfc/rfc2104>
* Length extension attack: <https://en.wikipedia.org/wiki/Length_extension_attack>
* Birthday problem: <https://en.wikipedia.org/wiki/Birthday_problem>
