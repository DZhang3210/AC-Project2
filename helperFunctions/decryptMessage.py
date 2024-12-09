from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .hash_message import verify_hash
import struct
import time


def decrypt_message(self, encrypted_message):
    # Extract components using the same structure as encrypt_message
    nonce = encrypted_message[:12]
    ct = encrypted_message[12:-48]  # Everything between nonce and hash
    hash = encrypted_message[-48:]  # Hash is 32 bytes
    # print("decrypt hash", hash)

    # Verify the hash
    if not verify_hash(ct, self.symmetric_key, hash):
        raise ValueError("Hash verification failed")

    # Decrypt the message using the received nonce
    aesgcm = AESGCM(self.symmetric_key)
    timestamped_message = aesgcm.decrypt(nonce, ct, None)

    # Verify sequence number
    expected_other_seq_number_int = int.from_bytes(
        self.other_seq_number, byteorder='big') + 1
    actual_other_seq_number_int = int.from_bytes(
        timestamped_message[8:16], byteorder='big')
    if not expected_other_seq_number_int == actual_other_seq_number_int:
        raise ValueError("Sequence number does not match expected")

    # Update other seq number
    self.other_seq_number = expected_other_seq_number_int.to_bytes(
        8, byteorder='big')

    # Extract the timestamp and original message
    timestamp = struct.unpack('>Q', timestamped_message[:8])[0]
    message = timestamped_message[16:].decode('utf-8')

    # Use the instance's message_ttl
    if time.time() - timestamp > self.message_ttl:
        raise ValueError("Message is too old")

    return message
