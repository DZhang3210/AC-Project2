import os
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def seq1_response(self, data):
    # Split the received data into encrypted payload and MAC
    encrypted_seq = data[:-32]  # MAC is 32 bytes (SHA256)
    received_mac = data[-32:]
    
    # Verify MAC using symmetric key
    h = hmac.HMAC(self.symmetric_key, hashes.SHA256())
    h.update(encrypted_seq)
    try:
        h.verify(received_mac)
    except Exception:
        raise ValueError("MAC verification failed")
    
    # # Trying to code {encrypted(random initial seq # + ack)} + MAC
    # initial_seq = os.urandom(4)

    # # Prep payload
    # ack = b"ACK"
    # payload = ack + initial_seq

    # # Encrypting payload using AES
    # iv = os.urandom(16)
    # cipher = Cipher(algorithms.AES(self.symmetric_key),
    #                 modes.CBC(iv))
    # encryptor = cipher.encryptor()

    # padder = padding.PKCS7(128).padder()
    # padded_data = padder.update(payload) + padder.finalize()
    # encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()

    # # Create new MAC for our response
    # h = hmac.HMAC(self.symmetric_key, hashes.SHA256())
    # h.update(iv + encrypted_payload)
    # new_mac = h.finalize()

    # Send the message
    encrypted_payload = self.encrypt_message("test")
    print("Sending SEQ2 from", self.identity)
    self.socket.send_multipart([b"SEQ2", encrypted_payload])
