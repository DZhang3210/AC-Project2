import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
def key_response(self, data):
    # Split received message into components
    key_size = 256  # RSA-2048 encrypted size
    mac_size = 32   # SHA-256 MAC size
    
    encrypted_key = data[:key_size]
    key_mac = data[key_size:key_size + mac_size]
    encrypted_seq = data[key_size + mac_size:key_size * 2 + mac_size]
    seq_mac = data[key_size * 2 + mac_size:]
    
    # Decrypt session key and sequence number
    session_key = self.private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    initial_seq = int.from_bytes(
        self.private_key.decrypt(
            encrypted_seq,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ),
        'big'
    )
    
    # Verify MACs
    key_mac_verify = hmac.HMAC(session_key, hashes.SHA256())
    key_mac_verify.update(session_key)
    key_mac_verify.verify(key_mac)
    
    seq_mac_verify = hmac.HMAC(session_key, hashes.SHA256())
    seq_mac_verify.update(initial_seq.to_bytes(4, 'big'))
    seq_mac_verify.verify(seq_mac)
    
    # Generate and encrypt response sequence number
    response_seq = int.from_bytes(os.urandom(4), 'big')
    
    # Create MAC for response sequence
    resp_seq_mac = hmac.HMAC(session_key, hashes.SHA256())
    resp_seq_mac.update(response_seq.to_bytes(4, 'big'))
    resp_seq_mac_value = resp_seq_mac.finalize()
    
    # Encrypt response sequence with peer's public key
    encrypted_resp_seq = self.peer_public_key.encrypt(
        response_seq.to_bytes(4, 'big'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Store the keys and sequence numbers
    self.symmetric_key = session_key
    self.seq_number = initial_seq
    
    # Send to peer
    self.socket.send_multipart([b"KEY", encrypted_resp_seq + resp_seq_mac_value])