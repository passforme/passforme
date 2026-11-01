# Independent reference for the test vectors in crates/core/src/kdf.rs.
#
# Argon2id comes from argon2-cffi (the Argon2 authors' reference C code),
# NFKC from Python's unicodedata, and HKDF is written here from RFC 5869 on
# top of the standard library's hmac. Nothing is shared with the Rust code.
#
#   uv venv /tmp/sbx-ref && VIRTUAL_ENV=/tmp/sbx-ref uv pip install argon2-cffi
#   /tmp/sbx-ref/bin/python tools/kdf_reference.py
import hashlib, hmac, unicodedata
from argon2.low_level import hash_secret_raw, Type

def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]

def derive(password, m, t, p):
    sk = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    salt = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    acct = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    pw = unicodedata.normalize("NFKC", password).encode()
    pw_key = hash_secret_raw(pw, salt, time_cost=t, memory_cost=m, parallelism=p,
                             hash_len=32, type=Type.ID, version=19)
    prk = hkdf_extract(acct, pw_key + sk)
    return hkdf_expand(prk, b"strongbox v1 wrap", 32).hex(), hkdf_expand(prk, b"strongbox v1 auth", 32).hex()

# sanity: RFC 5869 A.1 through this HKDF
prk = hkdf_extract(bytes(range(13)), b"\x0b"*22)
assert hkdf_expand(prk, bytes(range(0xf0, 0xfa)), 42).hex().startswith("3cb25f25faacd57a")
w, a = derive("correct horse battery staple", 1024, 2, 1)
print(f'WRAP_FAST = "{w}"\nAUTH_FAST = "{a}"')
w, a = derive("correct horse battery staple", 256*1024, 3, 1)
print(f'WRAP_DEFAULT = "{w}"\nAUTH_DEFAULT = "{a}"')
w, _ = derive("café ﬁsh", 1024, 2, 1)
w2, _ = derive("café fish", 1024, 2, 1)
assert w == w2
print(f'WRAP_UNICODE = "{w}"')
