import hashlib


def hash_data(data: bytes, algorithm: str) -> str:
    algo = algorithm.lower()

    if algo == "md5":
        hash_obj = hashlib.md5()
    elif algo == "sha1":
        hash_obj = hashlib.sha1()
    elif algo == "sha256":
        hash_obj = hashlib.sha256()
    elif algo == "sha512":
        hash_obj = hashlib.sha512()
    else:
        raise ValueError("Unsupported hashing algorithm.")

    hash_obj.update(data)
    return hash_obj.hexdigest()
