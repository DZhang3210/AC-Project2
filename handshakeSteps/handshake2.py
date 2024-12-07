import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from helperFunctions.hash_message import hash_message

def handshake2_response(self):
    ephemeral_key = os.urandom(32)
    self.symmetric_key = ephemeral_key
    seq_number = os.urandom(4)
    self.our_seq = seq_number
    # Print sizes for debugging

    # Concatenate before encryption
    message = ephemeral_key + seq_number

    encrypted_message = self.other_public.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    mac = hash_message(encrypted_message, ephemeral_key)

    message_len = len(encrypted_message).to_bytes(4, 'big')
    combined_message = message_len + encrypted_message + mac

    # print(f"[HANDSHAKE2]: Continuing to KEY from {self.identity}")
    return self.socket.send_multipart([b"KEY", combined_message])
