import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def initiate_handshake(self):
    if self.symmetric_key:
        return True

    nonce = self.StorageNonceManager.get_nonce()
    # print("nonce", nonce)
    # Add current timestamp to the nonce
    timestamp = str(int(time.time())).zfill(10).encode()
    # print("timestamp", timestamp)
    nonce_with_timestamp = nonce + timestamp

    # Encrypt nonce and timestamp with private key
    encrypted_nonce = self.private_key.sign(
        nonce_with_timestamp,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # print("encrypted nonce", encrypted_nonce)
    # Concatenate nonce and encrypted nonce
    combined_nonce = nonce_with_timestamp + encrypted_nonce

    # Send the combined nonce as the second part of the message
    self.socket.send_multipart([b"HELO", combined_nonce])
