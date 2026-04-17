"""Cryptographic operations: AES-256-CBC encryption and HMAC-SHA256 integrity.

Two separate security properties are provided:

  * **Confidentiality** — AES-256-CBC encryption ensures that unauthenticated
    callers receive ciphertext that is computationally uninterpretable without
    the 32-byte key.

  * **Integrity** — HMAC-SHA256 signatures ensure that any tampering with file
    content (in transit or at rest) can be detected by authenticated callers.
"""
import hashlib
import hmac
import os
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Separate key material for HMAC — never reuse an encryption key for signing.
_HMAC_KEY: bytes = b"mcp-v2-integrity-hmac-key-do-not-use-in-production"


class CryptoManager:
    """AES-256-CBC encryption and HMAC-SHA256 signing.

    The AES key is derived from the provided key string via SHA-256, giving a
    stable 32-byte key regardless of the input length.
    """

    def __init__(self, key: str) -> None:
        # Derive a fixed-length AES-256 key from the config string
        self._aes_key: bytes = hashlib.sha256(key.encode()).digest()

    # ------------------------------------------------------------------
    # AES-256-CBC  (confidentiality)
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* and return a base64-encoded ``IV || ciphertext`` blob."""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self._aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        enc = cipher.encryptor()
        data = plaintext.encode("utf-8")
        # PKCS#7 padding to next 16-byte boundary
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)
        ct = enc.update(data) + enc.finalize()
        return base64.b64encode(iv + ct).decode("ascii")

    def decrypt(self, blob_b64: str) -> str:
        """Decrypt a base64-encoded ``IV || ciphertext`` blob and return plaintext."""
        raw = base64.b64decode(blob_b64)
        iv, ct = raw[:16], raw[16:]
        cipher = Cipher(
            algorithms.AES(self._aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        pad_len = padded[-1]
        return padded[:-pad_len].decode("utf-8")

    # ------------------------------------------------------------------
    # HMAC-SHA256  (integrity)
    # ------------------------------------------------------------------

    def sign(self, content: str) -> str:
        """Return the HMAC-SHA256 hex digest of *content*."""
        return hmac.new(_HMAC_KEY, content.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, content: str, signature: str) -> bool:
        """Return True if *signature* matches the HMAC of *content*.

        Uses ``hmac.compare_digest`` to prevent timing-oracle attacks.
        """
        expected = self.sign(content)
        return hmac.compare_digest(expected, signature)
