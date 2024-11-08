import os
from enum import Enum
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class KDFType(Enum):
    """
    Enumeration for Key Derivation Function (KDF) types.

    Attributes:
        PBKDF2 (int): Represents the PBKDF2 key derivation function,
                      which uses HMAC with a configurable iteration count
                      to produce a derived key. Suitable for general-purpose
                      key derivation but not memory-hard.

        SCRYPT (int): Represents the scrypt key derivation function,
                      designed to be memory-hard and resistant to brute-force
                      attacks with specialized hardware like GPUs and ASICs.
                      Useful when memory hardness is desired.

        ARGON2 (int): Represents the Argon2 key derivation function,
                      specifically designed to be memory-hard, with different
                      variants (Argon2i, Argon2d, Argon2id) to balance
                      side-channel resistance and hardware attack resistance.
                      Argon2 is generally recommended for secure password
                      hashing.
    """

    PBKDF2 = 1
    SCRYPT = 2
    ARGON2 = 3


class KDF:
    def __init__(self, kdf_type: KDFType, length: int = 32):
        self.kdf_type = kdf_type
        if length != 16 and length != 32:
            raise ValueError("Invalid key length, must be 16 (128 bits) or 32 (256 bits)")
        self.length = length

    def derive(self, password: bytes, salt: bytes) -> bytes:
        if self.kdf_type == KDFType.PBKDF2:
            return self._derive_pbkdf2(password, salt)
        elif self.kdf_type == KDFType.SCRYPT:
            return self._derive_scrypt(password, salt)
        elif self.kdf_type == KDFType.ARGON2:
            return self._derive_argon2(password, salt)
        else:
            raise ValueError("Invalid KDF type")

    def _derive_pbkdf2(self, password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=salt,
            iterations=300_000,
            backend=default_backend(),
        )
        return kdf.derive(password)

    def _derive_scrypt(self, password: bytes, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=self.length,  # key length 256 bits or 128 bits
            n=2**14,  # CPU/memory cost parameter (higher is more expensive)
            r=8,  # block size parameter
            p=1,  # parallelization parameter
            backend=default_backend(),
        )
        return kdf.derive(password)

    def _derive_argon2(self, password: bytes, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=2,  # Number of iterations
            memory_cost=2**16,  # Memory cost in KB (2^16 = 64MB)
            parallelism=1,  # Number of threads
            hash_len=self.length,  # Output length
            type=Type.ID,  # Argon2id
        )


class Cipher:
    def __init__(self, password: bytes, kdf: Optional[KDF] = None):
        self.password = password
        self.kdf = kdf or KDF(KDFType.PBKDF2, 32)

    def encrypt_legacy(self, data: bytes) -> bytes:
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

    def decrypt_legacy(self, data: bytes) -> bytes:
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

    def encrypt_aesgcm(self, data: bytes) -> bytes:
        salt = os.urandom(16)
        key = self._generate_key(self.password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # GCM standard nonce size
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + encrypted_data

    def decrypt_aesgcm(self, data: bytes) -> bytes:
        try:
            salt = data[:16]
            nonce = data[16:28]
            encrypted_data = data[28:]
            key = self._generate_key(self.password, salt)
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, encrypted_data, None)
        except Exception as e:
            raise ValueError("Decryption failed.") from e

    def _generate_key(self, password: bytes, salt: bytes) -> bytes:
        return self.kdf.derive(password, salt)
