import time
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    
def helo_response(self, msg_type, data):
    timestamp = str(int(time.time())).encode()
    nonce_with_timestamp = data + timestamp
    
    # Include certificate in response
    response_data = {
        "nonce_timestamp": nonce_with_timestamp,
        "certificate": self.certificate
    }
    
    # Encrypt nonce and timestamp with private key
    encrypted_nonce = self.private_key.sign(
        nonce_with_timestamp,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print(f"Sending handshake to {self.identity}")
    self.socket.send_multipart([b"HANDSHAKE1", encrypted_nonce])
