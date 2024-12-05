from cryptography.exceptions import InvalidSignature
import time
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import os    

def helo_response(self, msg_type, data, private_key, other_public):
    print("Helo_Response")
    nonce, result = verify_signature(data, other_public)
    if not result:
        print("Helo failed")
        return 
    print("Verified Helo")



    nonce = os.urandom(16)
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


    print(f"Sending HANDSHAKE1 from {self.identity}")
    self.socket.send_multipart([b"HANDSHAKE1", combined_nonce])


def verify_signature(data, peer_public_key, max_age_seconds=5):
    print("Verifying Signature")
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