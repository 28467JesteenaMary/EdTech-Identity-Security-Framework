import secrets
import random

# Prime number for GF(256) or larger. Using a large prime for safety.
_PRIME = 2**521 - 1 # Mersenne Prime

def _eval_at(poly, x, prime):
    """Evaluate a polynomial at x."""
    accum = 0
    for coeff in reversed(poly):
        accum = (accum * x + coeff) % prime
    return accum

def make_shards(secret_int, min_shares, total_shares, prime=_PRIME):
    """Splits a secret into shares."""
    if min_shares > total_shares:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [secret_int] + [secrets.randbelow(prime) for _ in range(min_shares - 1)]
    points = [(i, _eval_at(poly, i, prime)) for i in range(1, total_shares + 1)]
    return points

def _extended_gcd(a, b):
    x, last_x = 0, 1
    y, last_y = 1, 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _div_mod(num, den, p):
    """Division in GF(p)."""
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    """Calculates f(x) given points (x_s, y_s)."""
    k = len(x_s)
    assert k == len(set(x_s)), "Points must be distinct."
    nums = []
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        num = 1
        den = 1
        for o in others:
            num = (num * (x - o)) % p
            den = (den * (cur - o)) % p
        nums.append(num)
        dens.append(den)
    den = 1
    for d in dens:
        den = (den * d) % p
    num = 0
    for i in range(k):
        num = (num + (y_s[i] * nums[i] * _div_mod(den, dens[i], p))) % p
    return (_div_mod(num, den, p) + p) % p

def recover_secret(shares, prime=_PRIME):
    """Recover the secret from shards."""
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares.")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)

def secret_to_shards(secret_str, min_shares=2, total_shares=3):
    """Converts a string secret to integer shards."""
    secret_int = int.from_bytes(secret_str.encode('utf-8'), 'big')
    shards = make_shards(secret_int, min_shares, total_shares)
    return shards 

def shards_to_secret(shards):
    """Reconstructs string from integer shards."""
    secret_int = recover_secret(shards)
    return secret_int.to_bytes((secret_int.bit_length() + 7) // 8, 'big').decode('utf-8')
