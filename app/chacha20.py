from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os
import base64

KEY_LENGTH = 32  # ChaCha20 requires a 256-bit (32-byte) key
NONCE_LENGTH = 16  # ChaCha20 requires a 128-bit (16-byte) nonce

def format_key(user_key: str) -> bytes:
    key_bytes = user_key.encode()

    if len(key_bytes) < KEY_LENGTH:
        key_bytes += b'\0' * (KEY_LENGTH - len(key_bytes))
    else:
        key_bytes = key_bytes[:KEY_LENGTH]

    return key_bytes

def chacha20(data, user_key: str, mode: str, is_file: bool = False):
    key = format_key(user_key)
    mode = mode.lower()

    if not isinstance(user_key, str):
        raise TypeError("Key must be a string")

    if mode not in ['encrypt', 'decrypt']:
        raise ValueError("Mode must be either 'encrypt' or 'decrypt'")

    if mode == 'encrypt':
        nonce = os.urandom(NONCE_LENGTH)
        raw = data if is_file else data.encode()

        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(raw)

        result = nonce + ciphertext
        return result if is_file else base64.b64encode(result).decode()

    elif mode == 'decrypt':
        try:
            raw = data if is_file else base64.b64decode(data)
            nonce = raw[:NONCE_LENGTH]
            ciphertext = raw[NONCE_LENGTH:]

            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext)

            return plaintext if is_file else plaintext.decode()
        except Exception as e:
            return f"Error: {str(e)}"
