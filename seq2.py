import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def seq2_response(self, msg_type, data):
    # Seperate data
    iv = data[:16]
    encrypted_payload = data[16:-32]
    mac = data[-32:]

    # Decrypt payload
    cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Remove padding
    padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    payload = unpadder.update(padded_data) + unpadder.finalize()

    # Seperate acknowledgement and random sequence
    ack = payload[:3]
    random_seq = payload[3:]

    # Prep new payload
    test_msg = b"testing, testing, 1, 2, 3"
    new_payload = test_msg + random_seq

    # Encrypting new payload using AES
    new_iv = os.urandom(16)
    new_cipher = Cipher(algorithms.AES(self.symmetric_key),
                        modes.CBC(new_iv))
    encryptor = new_cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    new_padded_data = padder.update(new_payload) + padder.finalize()
    new_encrypted_payload = encryptor.update(
        new_padded_data) + encryptor.finalize()

    # Send the test message
    self.socket.send_multipart([b"SEQ2", new_iv + new_encrypted_payload + mac])
