from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

import os
import base64

# ========== RSA Section ==========


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return priv_pem, pub_pem


def rsa_encrypt(public_pem: str, message: str) -> str:
    public_key = serialization.load_pem_public_key(public_pem.encode())
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return ciphertext.hex()


def rsa_decrypt(private_pem: str, ciphertext_hex: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_pem.encode(), password=None
    )
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return plaintext.decode()


# ========== ECC (ECIES) Section ==========


def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return priv_pem, pub_pem


def ecc_encrypt(public_pem: str, message: str) -> dict:
    recipient_public_key = serialization.load_pem_public_key(public_pem.encode())

    # Ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Shared secret
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies",
        backend=default_backend(),
    ).derive(shared_key)

    # Encrypt
    nonce = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(derived_key), modes.GCM(nonce), backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Serialize ephemeral public key
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "ephemeral_pub": base64.b64encode(ephemeral_pub_bytes).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }


def ecc_decrypt(private_pem: str, encrypted_data: dict) -> str:
    private_key = serialization.load_pem_private_key(
        private_pem.encode(), password=None
    )

    ephemeral_pub_bytes = base64.b64decode(encrypted_data["ephemeral_pub"])
    ephemeral_public_key = serialization.load_der_public_key(ephemeral_pub_bytes)

    # Shared secret
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies",
        backend=default_backend(),
    ).derive(shared_key)

    # Decrypt
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    decryptor = Cipher(
        algorithms.AES(derived_key), modes.GCM(nonce, tag), backend=default_backend()
    ).decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except InvalidTag:
        raise ValueError("Decryption failed: invalid tag or corrupted data")


# ========== Unified Interface ==========


def generate_key(mode: str):
    if mode == "rsa":
        return generate_rsa_keypair()
    elif mode == "ecc":
        return generate_ecc_keypair()
    else:
        raise ValueError("Unsupported mode. Use 'rsa' or 'ecc'.")


def encrypt(mode: str, public_key_pem: str, message: str):
    if mode == "rsa":
        return rsa_encrypt(public_key_pem, message)
    elif mode == "ecc":
        return ecc_encrypt(public_key_pem, message)
    else:
        raise ValueError("Unsupported mode. Use 'rsa' or 'ecc'.")


def decrypt(mode: str, private_key_pem: str, ciphertext):
    if mode == "rsa":
        return rsa_decrypt(private_key_pem, ciphertext)
    elif mode == "ecc":
        return ecc_decrypt(private_key_pem, ciphertext)
    else:
        raise ValueError("Unsupported mode. Use 'rsa' or 'ecc'.")


# def test_all():
#     # RSA test
#     priv_rsa, pub_rsa = generate_rsa_keypair()
#     print("RSA keys generated.")

#     msg = "Hello RSA!"
#     ciphertext_rsa = rsa_encrypt(pub_rsa, msg)
#     print("RSA ciphertext:", ciphertext_rsa)

#     plaintext_rsa = rsa_decrypt(priv_rsa, ciphertext_rsa)
#     print("RSA decrypted:", plaintext_rsa)

#     # ECC test
#     priv_ecc, pub_ecc = generate_ecc_keypair()
#     print("ECC keys generated.")

#     msg2 = "Hello ECC!"
#     ciphertext_ecc = ecc_encrypt(pub_ecc, msg2)
#     print("ECC ciphertext:", ciphertext_ecc)

#     plaintext_ecc = ecc_decrypt(priv_ecc, ciphertext_ecc)
#     print("ECC decrypted:", plaintext_ecc)


# test_all()
