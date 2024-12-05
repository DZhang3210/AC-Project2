import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def handshake2_response(self, msg_type, data, other_public):
    ephemeral_key = os.urandom(32)
    # print("Created Ephemeral Key", ephemeral_key)
    self.symmetric_key = ephemeral_key
    seq_number = os.urandom(4)
    # print("Created seq_number", seq_number)
    self.our_seq = seq_number
    # Print sizes for debugging
    # print(f"Key size: {len(ephemeral_key)}")
    # print(f"Seq size: {len(seq_number)}")
    
    # Concatenate before encryption
    message = ephemeral_key + seq_number
    # print(f"Combined message size: {len(message)}")
    
    encrypted_message = other_public.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # print("Ecnrytped CREATE", encrypted_message)
    # print(f"Encrypted size: {len(encrypted_message)}")
    
    h = hmac.HMAC(ephemeral_key, hashes.SHA256())
    h.update(encrypted_message)
    mac = h.finalize()
    # print("Created MAC", mac)
    # print(f"MAC size: {len(mac)}")
    # Add size prefix to help with parsing
    message_len = len(encrypted_message).to_bytes(4, 'big')
    combined_message = message_len + encrypted_message + mac
    # print(f"Total message size: {len(combined_message)}")
    
    return self.socket.send_multipart([b"KEY", combined_message])