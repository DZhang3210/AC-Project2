import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def key_response(self, data):
    message_len = int.from_bytes(data[:4], 'big')
    received_mac = data[4+message_len:]
    encrypted_data = data[4:4+message_len]

    # Decrypt the message to get ephemeral key and sequence number
    decrypted_data = self.private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ephemeral_key = decrypted_data[:32]
    seq_number = decrypted_data[32:]

    message_len = int.from_bytes(decrypted_data[:4], 'big')

    # Verify MAC
    h = hmac.HMAC(ephemeral_key, hashes.SHA256())
    h.update(encrypted_data[:4+message_len])
    try:
        h.verify(received_mac)
    except Exception:
        raise ValueError("[KEY]: MAC verification failed")

    # Store the session key and peer sequence number
    self.symmetric_key = ephemeral_key
    self.peer_sequence = int.from_bytes(seq_number, 'big')

    # Generate our initial sequence number
    our_seq = os.urandom(4)  # 4-byte, 32-bit sequence number
    self.our_sequence = int.from_bytes(our_seq, 'big')

    # Encrypt our sequence number
    encrypted_seq = self.other_public.encrypt(
        our_seq,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Create MAC for the encrypted sequence
    h = hmac.HMAC(ephemeral_key, hashes.SHA256())
    h.update(encrypted_seq)
    mac = h.finalize()
    combined_message = encrypted_seq + mac

    # Send ACK with encrypted sequence number and MAC
    print(f"[KEY]: Continuing to SEQ1 from {self.identity}")
    self.socket.send_multipart([b"SEQ1", combined_message])
