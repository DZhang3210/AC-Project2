import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .hash_message import hash_message

def encrypt_message(self, message):   
    # Create timestamp and combine with message
    nonce = self.StorageNonceManager.get_nonce()
    timestamp = struct.pack('>Q', int(time.time()))
    # Encode the message as bytes before concatenation
    message_bytes = message.encode('utf-8')
    timestamped_message = timestamp + message_bytes
    
    # Encrypt the message using AES-GCM
    aesgcm = AESGCM(self.symmetric_key)
    ct = aesgcm.encrypt(nonce, timestamped_message, None)  # Added None as associated_data parameter
    hash = hash_message(ct, self.symmetric_key)
        
    # Combine nonce, encrypted data, and hash into a single byte string
    combined_message = nonce + ct + hash
    
    return combined_message




