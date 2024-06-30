import argparse
from encryption import generate_key, encrypt_text, decrypt_text


def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt text using AES.")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode: encrypt or decrypt")
    parser.add_argument('text', help="Text to encrypt or decrypt")
    parser.add_argument('--key', help="Encryption key (hex format)", default=None)

    args = parser.parse_args()

    if args.key:
        key = bytes.fromhex(args.key)
    else:
        key = generate_key()
        print(f"Generated Key: {key.hex()}")

    if args.mode == 'encrypt':
        ciphertext = encrypt_text(args.text, key)
        print(f"Ciphertext: {ciphertext.hex()}")
    elif args.mode == 'decrypt':
        plaintext = decrypt_text(bytes.fromhex(args.text), key)
        print(f"Plaintext: {plaintext}")


if __name__ == '__main__':
    main()
