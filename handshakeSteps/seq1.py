from helperFunctions.hash_message import verify_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import time


def seq1_response(self, data):
    if not self.symmetric_key:
        raise ValueError("[SEQ1]: No symmetric key established")

    # Extract components from the message
    timestamp = int(data[12:22].decode())
    # First 22 bytes (26 nonce + 10 timestamp)
    nonce_with_timestamp = data[:22]
    received_mac = data[-48:]  # Last 32 bytes
    # Everything between nonce_with_timestamp and mac
    encrypted_ack = data[22:-48]

    if time.time() - timestamp > self.message_ttl:
        raise ValueError("Message is too old")

    # Verify MAC using symmetric key
    verified = verify_hash(encrypted_ack, self.symmetric_key, received_mac)
    if not verified:
        raise ValueError("[SEQ1]: MAC verification failed")

    try:
        # Decrypt just the encrypted_ack portion
        decrypted_ack = self.private_key.decrypt(
            encrypted_ack,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Verify ACK message format
        if not decrypted_ack.startswith(b"ACK"):
            raise ValueError("[SEQ1]: Invalid ACK message")

        # Verify nonce_with_timestamp matches\
        if decrypted_ack[11:33] != nonce_with_timestamp:
            raise ValueError("[SEQ1]: Nonce verification failed")

        # Obtain other seq number
        self.other_seq_number = decrypted_ack[3:11]

        # Continue with sequence
        encrypted_payload = self.encrypt_message("test")

        # Send the message
        self.socket.send_multipart([b"SEQ2", encrypted_payload])

    except ValueError as e:
        print(f"[SEQ1] Decryption error: {str(e)}")
        raise
