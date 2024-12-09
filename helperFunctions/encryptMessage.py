import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .hash_message import hash_message


def encrypt_message(self, message):
    # Increment seq number
    seq_number_int = int.from_bytes(self.seq_number, byteorder='big') + 1
    self.seq_number = seq_number_int.to_bytes(8, byteorder='big')

    # Create timestamp and combine with message
    nonce = self.StorageNonceManager.get_nonce()
    timestamp = struct.pack('>Q', int(time.time()))
    # Encode the message as bytes before concatenation
    message_bytes = message.encode('utf-8')
    timestamped_message = timestamp + self.seq_number + message_bytes
    # Encrypt the message using AES-GCM
    aesgcm = AESGCM(self.symmetric_key)
    # Added None as associated_data parameter
    ct = aesgcm.encrypt(nonce, timestamped_message, None)
    hash = hash_message(ct, self.symmetric_key)
    # Combine nonce, encrypted data, and hash into a single byte string
    combined_message = nonce + ct + hash

    return combined_message
