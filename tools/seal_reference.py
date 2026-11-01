# Independent reference for the vectors in crates/core/src/seal.rs, built from
# the wire format in that module's documentation with libsodium's
# XChaCha20-Poly1305 (PyNaCl). Nothing is shared with the Rust code.
#
#   uv venv /tmp/sbx-ref && VIRTUAL_ENV=/tmp/sbx-ref uv pip install pynacl
#   /tmp/sbx-ref/bin/python tools/seal_reference.py
import struct
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as xchacha

ACCOUNT = bytes([0xA1]) * 16
ITEM = bytes([0x17]) * 16

def pad(plain):
    size = max(256, 1 << len(plain).bit_length())  # smallest power of two > len
    return plain + b"\x80" + b"\x00" * (size - len(plain) - 1)

def seal(key, nonce, aad, body):
    return bytes([1]) + nonce + xchacha(body, aad, nonce, key)

item_aad = b"strongbox v1 item" + ACCOUNT + ITEM + struct.pack(">Q", 7)
item = seal(bytes([0x42]) * 32, bytes([0x24]) * 24, item_aad, pad(b"hunter2"))
assert len(item) == 1 + 24 + 256 + 16
print(f'ITEM_REFERENCE = "{item.hex()}"')

vk_aad = b"strongbox v1 vault-key" + ACCOUNT
vk = seal(bytes([0x57]) * 32, bytes([0x31]) * 24, vk_aad, bytes([0x42]) * 32)
print(f'VAULT_KEY_REFERENCE = "{vk.hex()}"')
