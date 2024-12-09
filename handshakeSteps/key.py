import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from helperFunctions.hash_message import hash_message, verify_hash
import time


def key_response(self, data):
    # Extract components from the message
    timestamp = int(data[12:22].decode())

    nonce_with_timestamp = data[:22]
    received_mac = data[-48:]
    encrypted_message = data[22:-48]

    if time.time() - timestamp > self.message_ttl:
        raise ValueError("Message is too old")

    # Decrypt the message to get seq and ephemeral key
    decrypted_data = self.private_key.decrypt(
        encrypted_message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Extract components from decrypted data
    ephemeral_key = decrypted_data[8:40]
    self.symmetric_key = ephemeral_key
    self.other_seq_number = decrypted_data[:8]

    # print("[KEY]: Symmetric key:", self.symmetric_key)
    # Verify MAC
    verified = verify_hash(encrypted_message, self.symmetric_key, received_mac)
    if not verified:
        raise ValueError("[KEY]: MAC verification failed")

    # Should match nonce_with_timestamp
    nonce_with_timestamp_from_decrypt = decrypted_data[40:]

    # Verify the nonce_with_timestamp matches
    if nonce_with_timestamp != nonce_with_timestamp_from_decrypt:
        raise ValueError("[KEY]: Nonce verification failed")

    # Generate and encrypt ACK message
    self.seq_number = os.urandom(8)
    nonce = self.StorageNonceManager.get_nonce()
    timestamp = str(int(time.time())).zfill(10).encode()
    nonce_with_timestamp = nonce + timestamp
    ack_message = b"ACK" + self.seq_number + nonce_with_timestamp
    encrypted_ack = self.other_public.encrypt(
        ack_message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Create MAC for the encrypted ACK
    mac = hash_message(encrypted_ack, ephemeral_key)
    combined_message = nonce_with_timestamp + encrypted_ack + mac

    # Send ACK with MAC
    self.socket.send_multipart([b"SEQ1", combined_message])
