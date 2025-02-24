# PyCipher
<img src="https://github.com/sean1832/py-cipher/blob/main/cipher/assets/icon.png" width="160">

PyCipher is a simple python application that allows you to encrypt and decrypt text using python's cryptography library.
It comes with a CLI and a GUI interface.

## Installation
```bash
git clone https://github.com/sean1832/py-cipher.git
pip install .
```

## GUI - Usage (Recommended)
Enter the following command in the terminal to launch the GUI interface after installation.
```bash
cipher-gui
```

> [!TIP]
> It is recommended to use the GUI interface as it is more secure since any input or output is not stored in the terminal history.
> It is also more user-friendly anyway.

## CLI - Usage
```bash
cipher [OPTIONS] COMMAND [ARGS]...
```
- `OPTIONS`
  - `-h`, `--help`: Show this message and exit.
  - `-v`, `--version`: Show the version and exit.
  

### Commands
| Command | Description  |
| ------- | ------------ |
| encrypt | Encrypt text |
| decrypt | Decrypt text |

### Encrypt
```bash
cipher encrypt [OPTIONS] TEXT
```
- `-t`, `--input-type`: Input type (file, text)
- `-o`, `--output`: Output as file. If not specified, output will be printed to console as base64 encoded string.
- `--kdf`: Key derivation function (pbkdf2, scrypt, argon2) [default: pbkdf2]

> [!NOTE]
> After entering arguments, you will be prompted to enter a password. This password will be used to encrypt the text.


### Decrypt
```bash
cipher decrypt [OPTIONS] TEXT
```
- `-t`, `--input-type`: Input type (file, text)
- `-o`, `--output`: Output as file. If not specified, output will be printed to console as decrypted text.
- `--kdf`: Key derivation function (pbkdf2, scrypt, argon2) [default: pbkdf2]

> [!NOTE]
> After entering arguments, you will be prompted to enter a password. This password will be used to decrypt the text.

