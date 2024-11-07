import argparse
import base64
from getpass import getpass

from cipher.cipher import Cipher


def parser():
    parser = argparse.ArgumentParser(description="Cipher CLI")
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
    decrypt_parser.add_argument("-o", "--output", help="Output file path")
    return parser.parse_args()


def main():
    args = parser()
    key = getpass("Enter your password: ")
    if args.command == "encrypt":
        if args.input_type == "file":
            data_source = getpass("Enter file to encrypt: ")
            with open(data_source, "rb") as f:
                data = f.read()
        else:
            data_source = getpass("Enter b64 string to encrypt: ")
            data = data_source.encode("utf-8")

        cipher = Cipher(key.encode("utf-8"))
        encrypted_data = cipher.encrypt(data)
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

        cipher = Cipher(key.encode("utf-8"))
        try:
            decrypted_data = cipher.decrypt(data)
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


if __name__ == "__main__":
    main()
