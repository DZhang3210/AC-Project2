import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def test1_response(self, msg_type, data):
    # Seperate data
    iv = data[:16]
    encrypted_payload = data[16:-32]
    mac = data[-32:]

    # TODO Should we verify MAC?

    # Decrypt payload
    cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Remove padding
    padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    payload = unpadder.update(padded_data) + unpadder.finalize()

    # Seperate test message and random sequence
    test_msg = payload[:-4]
    random_seq = payload[-4:]

    print(f"Test message recieved: {test_msg.decode()}")

    # Prep new payload
    ack = b"ACK"
    new_payload = ack + random_seq

    # Encrypting new payload using AES
    new_iv = os.urandom(16)
    new_cipher = Cipher(algorithms.AES(self.symmetric_key),
                        modes.CBC(new_iv))
    encryptor = new_cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    new_padded_data = padder.update(new_payload) + padder.finalize()
    new_encrypted_payload = encryptor.update(
        new_padded_data) + encryptor.finalize()

    # Send the acknowledgement message
    self.socket.send_multipart(
        [b"TEST1", new_iv + new_encrypted_payload + mac])


def test2_response(self, msg_type, data):
    print("end of communication")   # TODO Do we stop here?
