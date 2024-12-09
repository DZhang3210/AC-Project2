from cryptography.exceptions import InvalidSignature
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def verify_signature(self, data, peer_public_key):
    # print("Verifying Signature")
    try:
        combined_nonce = data
        if len(combined_nonce) < 16:
            return False

        # Extract nonce, timestamp, and signature
        nonce = combined_nonce[:12]  # Adjust size for actual nonce
        # print("nonce", nonce)
        timestamp = int(combined_nonce[12:22].decode())  # Extract timestamp
        # print("timestamp", timestamp)
        nonce_with_timestamp = combined_nonce[:22]
        signature = combined_nonce[22:]
        # print("signature", signature)

        # Verify timestamp is within acceptable range
        current_time = int(time.time())
        if abs(current_time - timestamp) > self.message_ttl:
            print("Handshake failed: Timestamp too old")
            return  False

        # Verify signature using just the nonce
        try:
            peer_public_key.verify(
                signature,
                nonce_with_timestamp,  # Changed: only verify the nonce
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("Handshake failed: Invalid signature")
            return False

        return nonce, True

    except Exception as e:
        print(f"Handshake error: {str(e)}")
        return False
