from cryptography.hazmat.primitives import hmac, hashes

def hash_message(message, hash_key):
    h = hmac.HMAC(hash_key, hashes.SHA256())
    h.update(message)
    return h.finalize()
