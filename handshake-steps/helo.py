from cryptography.exceptions import InvalidSignature
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import os    
from helperFunctions.verify_signature import verify_signature

def helo_response(self, data):
    print("Helo_Response")
    nonce, result = verify_signature(data, self.other_public)
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


