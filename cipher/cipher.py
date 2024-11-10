import os
import struct
from typing import Optional, Union

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class Pbkdf2Params:
    FORMAT: str = ">cI"
    BINARY_SIZE = struct.calcsize(FORMAT)

    def __init__(self, iterations: int) -> None:
        self.iterations = iterations

    @staticmethod
    def from_dict(params: dict) -> "Pbkdf2Params":
        return Pbkdf2Params(iterations=params["iterations"])

    def to_dict(self) -> dict:
        return {"kdf": "pbkdf2", "iter": self.iterations}

    def to_bytes(self) -> bytes:
        """Converts PBKDF2 parameters to bytes

        Returns:
            bytes: PBKDF2 parameters in bytes (13 bytes)
        """
        return struct.pack(self.FORMAT, b"p", self.iterations)  # 0,0 are dummy values for padding

    @staticmethod
    def from_bytes(data: bytes) -> "Pbkdf2Params":
        """Converts bytes to PBKDF2 parameters

        Args:
            data (bytes): PBKDF2 parameters in bytes

        Returns:
            Pbkdf2Params: PBKDF2 parameters
        """
        try:
            kdf, iterations = struct.unpack(Pbkdf2Params.FORMAT, data)
            return Pbkdf2Params(iterations)
        except struct.error:
            raise ValueError("Invalid PBKDF2 parameters")


class ScryptParams:
    FORMAT: str = ">cIHH"
    BINARY_SIZE = struct.calcsize(FORMAT)

    def __init__(self, n: int, r: int, p: int) -> None:
        self.n = n
        self.r = r
        self.p = p

    @staticmethod
    def from_dict(params: dict) -> "ScryptParams":
        return ScryptParams(n=params["n"], r=params["r"], p=params["p"])

    def to_dict(self) -> dict:
        return {"kdf": "scrypt", "n": self.n, "r": self.r, "p": self.p}

    def to_bytes(self) -> bytes:
        """Converts Scrypt parameters to bytes

        Returns:
            bytes: Scrypt parameters in bytes (13 bytes)
        """
        return struct.pack(self.FORMAT, b"s", self.n, self.r, self.p)

    @staticmethod
    def from_bytes(data: bytes) -> "ScryptParams":
        """Converts bytes to Scrypt parameters

        Args:
            data (bytes): Scrypt parameters in bytes

        Returns:
            ScryptParams: Scrypt parameters
        """
        try:
            kdf, n, r, p = struct.unpack(ScryptParams.FORMAT, data)
            return ScryptParams(n, r, p)
        except struct.error:
            raise ValueError("Invalid Scrypt parameters")


class Argon2Params:
    FORMAT: str = ">cHIH"
    BINARY_SIZE = struct.calcsize(FORMAT)

    def __init__(self, time_cost: int, memory_cost: int, parallelism: int) -> None:
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

    @staticmethod
    def from_dict(params: dict) -> "Argon2Params":
        return Argon2Params(
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
        )

    def to_dict(self) -> dict:
        return {
            "kdf": "argon2",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
        }

    def to_bytes(self) -> bytes:
        """Converts Argon2 parameters to bytes

        Returns:
            bytes: Argon2 parameters in bytes (13 bytes)
        """
        return struct.pack(self.FORMAT, b"a", self.time_cost, self.memory_cost, self.parallelism)

    @staticmethod
    def from_bytes(data: bytes) -> "Argon2Params":
        """Converts bytes to Argon2 parameters

        Args:
            data (bytes): Argon2 parameters in bytes

        Returns:
            Argon2Params: Argon2 parameters
        """
        try:
            kdf, time_cost, memory_cost, parallelism = struct.unpack(Argon2Params.FORMAT, data)
            return Argon2Params(time_cost, memory_cost, parallelism)
        except struct.error:
            raise ValueError("Invalid Argon2 parameters")


class KDF:
    def __init__(self, params: Union[Pbkdf2Params, ScryptParams, Argon2Params], length: int = 32):
        self.params = params
        if length != 16 and length != 32 and length != 64:
            raise ValueError(
                "Invalid key length, must be 16 (128 bits) or 32 (256 bits) or 64 (512 bits)"
            )
        self.length = length

    @staticmethod
    def from_bytes(data: bytes) -> "KDF":
        kdf = data[0:1]
        if kdf == b"p":
            params = Pbkdf2Params.from_bytes(data[: Pbkdf2Params.BINARY_SIZE])
        elif kdf == b"s":
            params = ScryptParams.from_bytes(data[: ScryptParams.BINARY_SIZE])
        elif kdf == b"a":
            params = Argon2Params.from_bytes(data[: Argon2Params.BINARY_SIZE])
        else:
            raise ValueError("Invalid KDF type")
        return KDF(params, 32)

    def derive(self, password: bytes, salt: bytes) -> bytes:
        if isinstance(self.params, Pbkdf2Params):
            return self._derive_pbkdf2(password, salt, self.params)
        elif isinstance(self.params, ScryptParams):
            return self._derive_scrypt(password, salt, self.params)
        elif isinstance(self.params, Argon2Params):
            return self._derive_argon2(password, salt, self.params)
        else:
            raise ValueError("Invalid KDF parameters")

    def _derive_pbkdf2(self, password: bytes, salt: bytes, params: Pbkdf2Params) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=salt,
            iterations=params.iterations,
            backend=default_backend(),
        )
        return kdf.derive(password)

    def _derive_scrypt(self, password: bytes, salt: bytes, params: ScryptParams) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=self.length,  # key length 256 bits or 128 bits
            n=params.n,  # CPU/memory cost parameter (higher is more expensive)
            r=params.r,  # block size parameter
            p=params.p,  # parallelization parameter
            backend=default_backend(),
        )
        return kdf.derive(password)

    def _derive_argon2(self, password: bytes, salt: bytes, params: Argon2Params) -> bytes:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=params.time_cost,  # Number of iterations
            memory_cost=params.memory_cost,  # Memory cost in KB (2 GiB)
            parallelism=params.parallelism,  # Number of threads
            hash_len=self.length,  # Output length
            type=Type.ID,  # Argon2id
        )


class Cipher:
    def __init__(
        self,
        password: bytes,
        kdf: Optional[KDF] = None,
    ):
        self.password = password
        self.kdf = kdf or KDF(Pbkdf2Params(300_000), 32)

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
