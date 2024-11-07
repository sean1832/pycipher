import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Cipher:
    def __init__(self, password: bytes):
        self.password = password

    def encrypt(self, data: bytes) -> bytes:
        salt = os.urandom(16)
        key = self._generate_key(self.password, salt)
        iv = os.urandom(16)  # AES block size is 16
        cipher = CryptoCipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        # Pad data to be a multiple of the block size (AES requires this)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()  # type: ignore
        padded_data = padder.update(data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Return salt + iv + encrypted_data
        return salt + iv + encrypted_data

    def decrypt(self, data: bytes) -> bytes:
        # Extract the salt, IV, and encrypted data
        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        key = self._generate_key(self.password, salt)
        cipher = CryptoCipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  # type: ignore
        original_data = unpadder.update(padded_data) + unpadder.finalize()

        return original_data

    def _generate_key(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300_000,
            backend=default_backend(),
        )
        return kdf.derive(password)
