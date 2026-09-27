"""
JOCKY Evidence Cryptographic Module
AES-256-GCM Encryption with PBKDF2 Key Derivation
"""
import os
import json
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoError(Exception):
    pass


class EvidenceCrypto:
    """Provides AES-256-GCM encryption/decryption for forensic evidence artifacts."""

    ITERATIONS = 100_000
    KEY_SIZE = 32  # 256 bits
    SALT_SIZE = 16 # 128 bits
    NONCE_SIZE = 12 # 96 bits

    @classmethod
    def derive_key(cls, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_SIZE,
            salt=salt,
            iterations=cls.ITERATIONS,
        )
        return kdf.derive(passphrase.encode('utf-8'))

    @classmethod
    def encrypt_data(cls, raw_data: bytes, passphrase: str, associated_data: bytes = None) -> Dict[str, str]:
        """Encrypts data using AES-256-GCM."""
        if not passphrase:
            raise CryptoError("Passphrase cannot be empty")

        salt = os.urandom(cls.SALT_SIZE)
        nonce = os.urandom(cls.NONCE_SIZE)
        key = cls.derive_key(passphrase, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, raw_data, associated_data)

        return {
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": cls.ITERATIONS,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "associated_data": base64.b64encode(associated_data).decode('utf-8') if associated_data else ""
        }

    @classmethod
    def decrypt_data(cls, encrypted_payload: Dict[str, str], passphrase: str) -> bytes:
        """Decrypts payload package produced by encrypt_data."""
        if not passphrase:
            raise CryptoError("Passphrase cannot be empty")

        try:
            salt = base64.b64decode(encrypted_payload["salt"])
            nonce = base64.b64decode(encrypted_payload["nonce"])
            ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
            associated_data_str = encrypted_payload.get("associated_data", "")
            associated_data = base64.b64decode(associated_data_str) if associated_data_str else None

            key = cls.derive_key(passphrase, salt)
            aesgcm = AESGCM(key)

            decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return decrypted
        except Exception as e:
            raise CryptoError(f"Decryption failed: Integrity check mismatch or invalid key ({str(e)})")


def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()
    
    filename_ad = os.path.basename(input_path).encode('utf-8')
    payload = EvidenceCrypto.encrypt_data(data, passphrase, associated_data=filename_ad)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    decrypted_bytes = EvidenceCrypto.decrypt_data(payload, passphrase)
    with open(output_path, "wb") as f:
        f.write(decrypted_bytes)
