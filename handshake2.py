import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
import time
from cryptography.hazmat.primitives import asym_padding

def handshake2_response(self, msg_type, data):
     # Generate ephemeral session key and initial sequence number
    session_key = os.urandom(32)  # 256-bit key
    initial_seq = int.from_bytes(os.urandom(4), 'big')  # Random 32-bit integer
    
    # Create MAC for session key
    key_mac = hmac.HMAC(self.symmetric_key, hashes.SHA256())
    key_mac.update(session_key)
    key_mac_value = key_mac.finalize()
    
    # Encrypt sequence number and create its MAC
    seq_mac = hmac.HMAC(self.symmetric_key, hashes.SHA256())
    seq_mac.update(initial_seq.to_bytes(4, 'big'))
    seq_mac_value = seq_mac.finalize()
    
    # Encrypt session key and sequence number with peer's public key
    encrypted_key = self.peer_public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    encrypted_seq = self.peer_public_key.encrypt(
        initial_seq.to_bytes(4, 'big'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Combine all components
    message = encrypted_key + key_mac_value + encrypted_seq + seq_mac_value
    
    # Update local state
    self.symmetric_key = session_key
    self.seq_number = initial_seq
    
    # Send to peer
    self.socket.send_multipart([b"KEY", message])