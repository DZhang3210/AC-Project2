import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from helperFunctions.hash_message import hash_message
from helperFunctions.verify_signature import verify_signature
import time


def handshake2_response(self, data):
    result = self.verify_signature(data, self.other_public)

    if not result:
        print("[HANDSHAKE2]: Handshake failed")
        return

    ephemeral_key = os.urandom(32)
    self.symmetric_key = ephemeral_key
    nonce = self.StorageNonceManager.get_nonce()
    # 8 byte sequence number for reordering attacks
    self.seq_number = os.urandom(8)

    # Concatenate before encryption
    timestamp = str(int(time.time())).zfill(10).encode()
    nonce_with_timestamp = nonce + timestamp
    message = self.seq_number + ephemeral_key + nonce_with_timestamp

    encrypted_message = self.other_public.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    mac = hash_message(encrypted_message, ephemeral_key)

    combined_message = nonce_with_timestamp + encrypted_message + mac

    # print(f"[HANDSHAKE2]: Continuing to KEY from {self.identity}")

    # final message is 12 + 10 + 8 + 32 + 12 + 10 + 48
    return self.socket.send_multipart([b"KEY", combined_message])
