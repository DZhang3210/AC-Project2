from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .hash_message import hash_message
import hmac
import struct
import time

def decrypt_message(self, encrypted_message):
        # Extract components using the same structure as encrypt_message
        nonce = encrypted_message[:12]
        ct = encrypted_message[12:-32]  # Everything between nonce and hash
        hash = encrypted_message[-32:]  # Hash is 32 bytes

        # Verify the hash
        expected_hash = hash_message(ct, self.symmetric_key)
        if not hmac.compare_digest(expected_hash, hash):
            raise ValueError("Hash verification failed")

        # Decrypt the message using the received nonce
        aesgcm = AESGCM(self.symmetric_key)
        timestamped_message = aesgcm.decrypt(nonce, ct, None)

        # Extract the timestamp and original message
        timestamp = struct.unpack('>Q', timestamped_message[:8])[0]
        message = timestamped_message[8:].decode('utf-8')

        # Use the instance's message_ttl
        if time.time() - timestamp > self.message_ttl:
            raise ValueError("Message is too old")

        return message