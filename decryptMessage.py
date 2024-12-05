from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import struct
import time

def decrypt_message(self, encrypted_message):
    # Extract components from the combined message
    ct = encrypted_message[:-96]  # Assuming 32 bytes for hash and 64 bytes for signature
    hash = encrypted_message[-96:-64]
    signature = encrypted_message[-64:]

    # Verify the hash
    expected_hash = hash_message(ct, self.symmetric_key)
    if not hmac.compare_digest(expected_hash, hash):
        raise ValueError("Hash verification failed")

    # Decrypt the message
    nonce = self.storage_nonce_manager.get_nonce()
    aesgcm = AESGCM(self.symmetric_key)
    timestamped_message = aesgcm.decrypt(nonce, ct)

    # Verify the signature
    try:
        self.other_public.verify(
            signature,
            timestamped_message,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        raise ValueError("Signature verification failed")

    # Extract the timestamp and original message
    timestamp = struct.unpack('>Q', timestamped_message[:8])[0]
    message = timestamped_message[8:]

    # Optionally, check if the message is too old
    if time.time() - timestamp > 60:  # 60 seconds tolerance
        raise ValueError("Message is too old")

    return message

def hash_message(message, hash_key):
    h = hmac.new(hash_key, message, digestmod=hashes.SHA256())
    return h.digest()
