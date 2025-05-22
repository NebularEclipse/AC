from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

AES_IV_LEN = 16
AES_BLOCK_SIZE = 128  # In bits


def format_key_aes(user_key: str) -> bytes:
    key_bytes = user_key.encode()
    if len(key_bytes) <= 16:
        desired_length = 16
    elif len(key_bytes) <= 24:
        desired_length = 24
    else:
        desired_length = 32
    return key_bytes.ljust(desired_length, b"\0")[:desired_length]


def aes(data: str | bytes, user_key: str, operation: str, is_file: bool = False):
    key = format_key_aes(user_key)
    operation = operation.lower()

    if operation == "encrypt":
        iv = os.urandom(AES_IV_LEN)

        padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
        raw = data if is_file else data.encode()
        padded = padder.update(raw) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        output = iv + ciphertext

        return output if is_file else base64.b64encode(output).decode()

    elif operation == "decrypt":
        try:
            raw = data if is_file else base64.b64decode(data)
            iv = raw[:AES_IV_LEN]
            ciphertext = raw[AES_IV_LEN:]

            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()

            return plaintext if is_file else plaintext.decode()

        except Exception as e:
            return f"Error {str(e)}"


DES_IV_LEN = 8
DES_BLOCK_SIZE = 64


def format_key_des(user_key: str) -> bytes:
    key_bytes = user_key.encode()

    # TripleDES key must be either 16 or 24 bytes long
    if len(key_bytes) <= 16:
        key_bytes += b"\0" * (16 - len(key_bytes))
    elif len(key_bytes) <= 24:
        key_bytes += b"\0" * (24 - len(key_bytes))
    else:
        key_bytes = key_bytes[:24]

    return key_bytes


def triple_des(data, user_key: str, mode: str, is_file: bool = False):
    key = format_key_des(user_key)
    mode = mode.lower()

    if not isinstance(user_key, str):
        raise TypeError("Key must be a string")

    if mode not in ["encrypt", "decrypt"]:
        raise ValueError("Mode must be either 'encrypt' or 'decrypt'")

    if mode == "encrypt":
        iv = os.urandom(DES_IV_LEN)

        raw = data if is_file else data.encode()

        padder = padding.PKCS7(DES_BLOCK_SIZE).padder()
        padded_data = padder.update(raw) + padder.finalize()

        cipher = Cipher(
            algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        output = iv + ciphertext
        return output if is_file else base64.b64encode(output).decode()

    elif mode == "decrypt":
        try:
            raw = data if is_file else base64.b64decode(data)
            iv = raw[:DES_IV_LEN]
            ciphertext = raw[DES_IV_LEN:]

            cipher = Cipher(
                algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(DES_BLOCK_SIZE).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            return plaintext if is_file else plaintext.decode()
        except Exception as e:
            return f"Error: {str(e)}"


CHACHA20_KEY_LEN = 32
CHACHA20_NONCE_LEN = 16


def format_key_chacha20(user_key: str) -> bytes:
    key_bytes = user_key.encode()

    if len(key_bytes) < CHACHA20_KEY_LEN:
        key_bytes += b"\0" * (CHACHA20_KEY_LEN - len(key_bytes))
    else:
        key_bytes = key_bytes[:CHACHA20_KEY_LEN]

    return key_bytes


def chacha20(data, user_key: str, mode: str, is_file: bool = False):
    key = format_key_chacha20(user_key)
    mode = mode.lower()

    if not isinstance(user_key, str):
        raise TypeError("Key must be a string")

    if mode not in ["encrypt", "decrypt"]:
        raise ValueError("Mode must be either 'encrypt' or 'decrypt'")

    if mode == "encrypt":
        nonce = os.urandom(CHACHA20_NONCE_LEN)
        raw = data if is_file else data.encode()

        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(raw)

        result = nonce + ciphertext
        return result if is_file else base64.b64encode(result).decode()

    elif mode == "decrypt":
        try:
            raw = data if is_file else base64.b64decode(data)
            nonce = raw[:CHACHA20_NONCE_LEN]
            ciphertext = raw[CHACHA20_NONCE_LEN:]

            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext)

            return plaintext if is_file else plaintext.decode()
        except Exception as e:
            return f"Error: {str(e)}"
