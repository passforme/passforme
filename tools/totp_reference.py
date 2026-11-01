# Independent reference for the TOTP vectors in crates/core/src/totp.rs:
# RFC 6238 (appendix B) computed with Python's standard hmac/hashlib only.
#
#   python3 tools/totp_reference.py
import hashlib, hmac, struct

SEEDS = {
    "sha1": b"12345678901234567890",
    "sha256": b"12345678901234567890123456789012",
    "sha512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

def totp(seed, t, algo, digits=8, period=30):
    mac = hmac.new(seed, struct.pack(">Q", t // period), getattr(hashlib, algo)).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10**digits
    return str(code).zfill(digits)

for t in [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]:
    print(t, *(totp(SEEDS[a], t, a) for a in SEEDS))
