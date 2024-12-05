import os
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def seq1_response(self, msg_type, data):
    self.seq_number = data

    # Trying to code {encrypted(random initial seq # + ack)} + MAC
    initial_seq = os.urandom(4)

    # Grab MAC
    mac = data[256:]

    # Prep payload
    ack = b"ACK"
    payload = ack + initial_seq

    # Encrypting payload using AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(self.symmetric_key),
                    modes.CBC(iv))  # TODO Should we switch to GCM?
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload) + padder.finalize()
    encrypted_payload = encryptor.update(padded_data) + encryptor.finalize()

    # Send the message
    # TODO Don't know if we need to create a new MAC
    self.socket.send_multipart([b"SEQ1", iv + encrypted_payload + mac])
