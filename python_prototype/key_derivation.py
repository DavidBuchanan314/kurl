# code from https://en.wikipedia.org/wiki/HKDF (!)

import hashlib
import hmac

hash_function = hashlib.sha256  # RFC5869 also includes SHA-1 test vectors


def hmac_digest(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hash_function).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if len(salt) == 0:
        salt = bytes([0] * hash_function().digest_size)
    return hmac_digest(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac_digest(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def hkdf_expand_label(secret, label, context, length: int):
    label_str = b"tls13 " + label
    hkdf_label = length.to_bytes(2, "big") + len(label_str).to_bytes() + label_str + len(context).to_bytes() + context
    print("hkdf_expand", hkdf_label, len(hkdf_label))
    return hkdf_expand(secret, hkdf_label, length)
