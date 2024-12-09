import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import hmac
import struct
import time
import hashlib


def encrypt_message(message, aad, hash_key, private_key, storage_nonce_manager):   
    # Create timestamp and combine with message
    nonce = storage_nonce_manager.get_nonce()
    timestamp = struct.pack('>Q', int(time.time()))
    timestamped_message = timestamp + message
    
    # Generate signature for timestamped message
    signature = sign_message(timestamped_message, private_key)
    
    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, timestamped_message, aad)
    hash = hash_message(ct, hash_key)
    return ct, hash, aes_key, signature, nonce

def hash_message(message, hash_key):
    h = hmac.new(hash_key, message, digestmod=hashlib.sha256)
    return h.digest()

def decrypt_message(ct, nonce, aad, hash_key, original_hash, aes_key, signature, public_key, max_age=300):   
    if not hmac.compare_digest(hash_message(ct, hash_key), original_hash):
        raise ValueError("Invalid hash")
    
    # Decrypt message with embedded timestamp
    aesgcm = AESGCM(aes_key)
    timestamped_plaintext = aesgcm.decrypt(nonce, ct, aad)
    
    # Extract timestamp and message
    timestamp = timestamped_plaintext[:8]
    plaintext = timestamped_plaintext[8:]
    
    # Verify message age
    current_time = int(time.time())
    message_time = struct.unpack('>Q', timestamp)[0]
    if current_time - message_time > max_age:
        raise ValueError("Message too old")
    
    # Verify signature of timestamped message
    try:
        verify_signature(timestamped_plaintext, signature, public_key)
    except InvalidSignature:
        raise ValueError("Invalid signature")
    
    return plaintext

# Add these new functions for ECDSA operations
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(message, signature, public_key):
    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )

def sendEncryptedMessage(message, aad, hash_key, private_key, storage_nonce_manager, public_key_manager):
    private_key = public_key_manager.get_private_key()
    public_key = public_key_manager.get_public_key()
    return encrypt_message(message, aad, hash_key, private_key, storage_nonce_manager)

def receiveEncryptedMessage(ct, nonce, aad, hash_key, original_hash, aes_key, signature, public_key, max_age=300):
    return decrypt_message(ct, nonce, aad, hash_key, original_hash, aes_key, signature, public_key, max_age)