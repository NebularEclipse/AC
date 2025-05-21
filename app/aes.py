from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

IV_LENGTH = 16
BLOCK_SIZE_BITS = 128

def format_key(user_key: str) -> bytes:
    key_bytes = user_key.encode()
    if len(key_bytes) <= 16:
        desired_length = 16
    elif len(key_bytes) <= 24:
        desired_length = 24
    else:
        desired_length = 32
    return key_bytes.ljust(desired_length, b'\0')[:desired_length]


def aes(data: str | bytes, user_key: str, operation: str, is_file: bool = False):
    key = format_key(user_key)
    operation = operation.lower()

    if operation not in ['encrypt', 'decrypt']:
        raise ValueError("Mode must be 'encrypt' or 'decrypt'")

    if operation == 'encrypt':
        iv = os.urandom(IV_LENGTH)

        padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
        raw = data if is_file else data.encode()
        padded = padder.update(raw) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        output = iv + ciphertext
        return output if is_file else base64.b64encode(output).decode()

    elif operation == 'decrypt':
        try:
            raw = data if is_file else base64.b64decode(data)
            iv = raw[:IV_LENGTH]
            ciphertext = raw[IV_LENGTH:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()

            return plaintext if is_file else plaintext.decode()
        except Exception as e:
            return f"Error: {str(e)}"

