import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import hmac
import struct
import time
from StorageNonceManager import StorageNonceManager
import hashlib


def encrypt_message(self, message):   
    print("Encrypting Message")
    # Create timestamp and combine with message

    nonce = self.storage_nonce_manager.get_nonce()
    timestamp = struct.pack('>Q', int(time.time()))
    
    # Ensure message is in bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
    print("timestamp")
    timestamped_message = timestamp + message
    print("timestamp")

    
    # Generate signature for timestamped message
    # signature = sign_message(timestamped_message, self.private_key)
    
    # Ensure symmetric_key is in bytes
    if isinstance(self.symmetric_key, str):
        self.symmetric_key = self.symmetric_key.encode('utf-8')
    
    aesgcm = AESGCM(self.symmetric_key)
    ct = aesgcm.encrypt(nonce, timestamped_message, None)  # Add None for associated data if not used
    hash = hash_message(ct, self.symmetric_key)
    print("Here")
    # Combine the encrypted data and hash into a single byte string
    combined_message = ct + hash
    print("Here")
    # Return format matches socket.send_multipart expectations
    return combined_message

def hash_message(message, hash_key):
    h = hmac.new(hash_key, message, digestmod=hashlib.sha256)
    return h.digest()

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature
