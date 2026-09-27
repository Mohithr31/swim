"""
JOCKY Crypt CLI Utility
Usage: python -m security.jocky_crypt encrypt/decrypt input_file output_file passphrase
"""
import sys
import argparse
from security.evidence_crypto import encrypt_file, decrypt_file, CryptoError


def main():
    parser = argparse.ArgumentParser(description="JOCKY AES-256-GCM Evidence Encryption Tool")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Encryption action")
    parser.add_argument("input_file", help="Input file path")
    parser.add_argument("output_file", help="Output file path")
    parser.add_argument("passphrase", help="Key derivation passphrase")

    args = parser.parse_args()

    try:
        if args.action == "encrypt":
            encrypt_file(args.input_file, args.output_file, args.passphrase)
            print(f"[jocky_crypt] Successfully encrypted '{args.input_file}' -> '{args.output_file}'")
        elif args.action == "decrypt":
            decrypt_file(args.input_file, args.output_file, args.passphrase)
            print(f"[jocky_crypt] Successfully decrypted '{args.input_file}' -> '{args.output_file}'")
    except CryptoError as ce:
        print(f"[jocky_crypt-error] {ce}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[jocky_crypt-error] Unexpected failure: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
