from cryptography.exceptions import InvalidSignature
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def verify_signature(data, peer_public_key, max_age_seconds=5):
    try:
        combined_nonce = data
        if len(combined_nonce) < 16:
            return None, False
            
        # Extract nonce, timestamp, and signature
        nonce = combined_nonce[:26]  # Adjust size for actual nonce
        timestamp = int(combined_nonce[16:26].decode())  # Extract timestamp
        signature = combined_nonce[26:]
        
        # Verify timestamp is within acceptable range
        current_time = int(time.time())
        if abs(current_time - timestamp) > max_age_seconds:
            print("Handshake failed: Timestamp too old")
            return None, False
        
        # Verify signature using just the nonce
        try:
            peer_public_key.verify(
                signature,
                nonce,  # Changed: only verify the nonce
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("Handshake failed: Invalid signature")
            return None, False
            
        return nonce, True
        
    except Exception as e:
        print(f"Handshake error: {str(e)}")
        return None, False