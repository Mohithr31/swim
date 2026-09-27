import pytest
import os
import tempfile
from security.evidence_crypto import EvidenceCrypto, encrypt_file, decrypt_file, CryptoError


def test_encrypt_decrypt_roundtrip():
    passphrase = "secret_investigation_passphrase_2026"
    data = b"CONFIDENTIAL FORENSIC EVIDENCE: SYSTEM LOGS AND MEMORY DUMP SNAPSHOT"
    
    payload = EvidenceCrypto.encrypt_data(data, passphrase)
    assert payload["algorithm"] == "AES-256-GCM"
    assert payload["kdf"] == "PBKDF2-HMAC-SHA256"
    assert "salt" in payload
    assert "nonce" in payload
    assert "ciphertext" in payload

    decrypted = EvidenceCrypto.decrypt_data(payload, passphrase)
    assert decrypted == data


def test_decrypt_wrong_passphrase():
    passphrase = "correct_passphrase"
    wrong_passphrase = "wrong_passphrase"
    data = b"TOP SECRET EVIDENCE"

    payload = EvidenceCrypto.encrypt_data(data, passphrase)
    with pytest.raises(CryptoError):
        EvidenceCrypto.decrypt_data(payload, wrong_passphrase)


def test_file_encrypt_decrypt():
    passphrase = "file_crypto_passphrase"
    data = b"Sample raw evidence archive content..."

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, "archive.tar.gz")
        enc_path = os.path.join(tmpdir, "archive.tar.gz.enc")
        dec_path = os.path.join(tmpdir, "restored.tar.gz")

        with open(input_path, "wb") as f:
            f.write(data)

        encrypt_file(input_path, enc_path, passphrase)
        assert os.path.exists(enc_path)

        decrypt_file(enc_path, dec_path, passphrase)
        assert os.path.exists(dec_path)

        with open(dec_path, "rb") as f:
            restored = f.read()

        assert restored == data
