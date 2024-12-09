from cryptography.hazmat.primitives import hmac, hashes
import os  # for secure random generation
from cryptography.hazmat.primitives.constant_time import bytes_eq

def hash_message(message, hash_key):
    # Generate a random salt
    salt = os.urandom(16)  # 16 bytes of cryptographically secure random data
    
    h = hmac.HMAC(hash_key, hashes.SHA256())
    # Add salt before the message
    h.update(salt)
    h.update(message)
    
    # Return both salt and hash so verification is possible
    return salt + h.finalize()

def verify_hash(message, hash_key, salt_and_hash):
    # Split the salt and hash
    salt = salt_and_hash[:16]
    stored_hash = salt_and_hash[16:]
    
    # Recompute using same salt
    h = hmac.HMAC(hash_key, hashes.SHA256())
    h.update(salt)
    h.update(message)
    computed_hash = h.finalize()
    
    return bytes_eq(computed_hash, stored_hash)