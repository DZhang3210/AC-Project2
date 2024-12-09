from cryptography.exceptions import InvalidSignature
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from helperFunctions.verify_signature import verify_signature


def helo_response(self, data):
    result = self.verify_signature(data, self.other_public)
    if not result:
        print("[HELO]: Helo failed")
        return

    nonce = self.StorageNonceManager.get_nonce()
    # Add current timestamp to the nonce
    timestamp = str(int(time.time())).zfill(10).encode()
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
    combined_nonce = nonce_with_timestamp + encrypted_nonce

    # print(f"[HELO]: Continuing to HANDSHAKE1 from {self.identity}")
    self.socket.send_multipart([b"HANDSHAKE2", combined_nonce])
