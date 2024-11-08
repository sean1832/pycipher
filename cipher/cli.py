import argparse
import base64
from getpass import getpass

from cipher import __version__
from cipher.cipher import KDF, Cipher, KDFType


def get_parser():
    parser = argparse.ArgumentParser(description="Cipher CLI")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v" + __version__)

    # add commands
    subparsers = parser.add_subparsers(dest="command")

    # add encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument(
        "-t",
        "--input-type",
        help="Input type. Support binary file or plaintext",
        choices=["file", "string"],
        default="string",
    )
    encrypt_parser.add_argument(
        "--kdf",
        help="Key derivation function. pbkdf2 security lvl = 1, scrypt security lvl = 2, argon2 security lvl = 3",
        choices=["pbkdf2", "scrypt", "argon2"],
        default="pbkdf2",
    )
    encrypt_parser.add_argument("-o", "--output", help="Output file path")

    # add decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("data", help="Data to decrypt")
    decrypt_parser.add_argument(
        "-t",
        "--input-type",
        help="Input type. Support binary file or base64 string",
        choices=["file", "string"],
        default="string",
    )
    decrypt_parser.add_argument(
        "--kdf",
        help="Key derivation function",
        choices=["pbkdf2", "scrypt", "argon2"],
        default="pbkdf2",
    )
    decrypt_parser.add_argument("-o", "--output", help="Output file path")
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()

    if args.kdf == "pbkdf2":
        type = KDFType.PBKDF2
    elif args.kdf == "scrypt":
        type = KDFType.SCRYPT
    elif args.kdf == "argon2":
        type = KDFType.ARGON2

    if args.command == "encrypt":
        if args.input_type == "file":
            data_source = getpass("Enter file to encrypt: ")
            with open(data_source, "rb") as f:
                data = f.read()
        else:
            data_source = getpass("Enter b64 string to encrypt: ")
            data = data_source.encode("utf-8")

        key = getpass("Enter your password: ")

        cipher = Cipher(key.encode("utf-8"), kdf=KDF(type, 32))
        encrypted_data = cipher.encrypt_aesgcm(data)
        if args.output:
            with open(args.output, "wb") as f:
                f.write(encrypted_data)
        else:
            print(base64.b64encode(encrypted_data).decode("utf-8"))

    elif args.command == "decrypt":
        if args.input_type == "file":
            with open(args.data, "rb") as f:
                data = f.read()
        else:
            data = base64.b64decode(args.data.encode("utf-8"))

        key = getpass("Enter your password: ")
        cipher = Cipher(key.encode("utf-8"), kdf=KDF(type, 32))
        try:
            decrypted_data = cipher.decrypt_aesgcm(data)
        except ValueError:
            print("Incorrect password")
            return
        if args.output:
            with open(args.output, "wb") as f:
                f.write(decrypted_data)
        else:
            user_confirm = input("Do you want to print the decrypted data? (y/n): ")
            if user_confirm.lower() == "y":
                print(decrypted_data.decode("utf-8"))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
