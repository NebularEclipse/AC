from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

IV_LENGTH = 8
BLOCK_SIZE_BITS = 64  # 3DES block size in bits

def format_key(user_key: str) -> bytes:
    key_bytes = user_key.encode()

    # TripleDES key must be either 16 or 24 bytes long
    if len(key_bytes) <= 16:
        key_bytes += b'\0' * (16 - len(key_bytes))
    elif len(key_bytes) <= 24:
        key_bytes += b'\0' * (24 - len(key_bytes))
    else:
        key_bytes = key_bytes[:24]

    return key_bytes

def triple_des(data, user_key: str, mode: str, is_file: bool = False):
    key = format_key(user_key)
    mode = mode.lower()

    if not isinstance(user_key, str):
        raise TypeError("Key must be a string")

    if mode not in ['encrypt', 'decrypt']:
        raise ValueError("Mode must be either 'encrypt' or 'decrypt'")

    if mode == 'encrypt':
        iv = os.urandom(IV_LENGTH)

        raw = data if is_file else data.encode()

        padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
        padded_data = padder.update(raw) + padder.finalize()

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        output = iv + ciphertext
        return output if is_file else base64.b64encode(output).decode()

    elif mode == 'decrypt':
        try:
            raw = data if is_file else base64.b64decode(data)
            iv = raw[:IV_LENGTH]
            ciphertext = raw[IV_LENGTH:]

            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            return plaintext if is_file else plaintext.decode()
        except Exception as e:
            return f"Error: {str(e)}"

