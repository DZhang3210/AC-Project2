import zmq
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import threading
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from StorageNonceManager import StorageNonceManager
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from key import key_response
from handshake2 import handshake2_response
from helo import helo_response
from seq1 import seq1_response
from handshake1 import handshake1_response
from encryptMessage import hash_message, sign_message
from seq2 import seq2_response

class SecurePeer:
    def __init__(self, my_port, peer_port, identity):
        self.public_key = None
        self.private_key = None
        self.identity = identity
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.bind(f"tcp://*:{my_port}")

        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.connect(f"tcp://localhost:{peer_port}")
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")

        self.symmetric_key = None
        self.listening = True
        self.listener_thread = threading.Thread(
            target=self.listen_for_messages)
        self.listener_thread.start()
        self.other_public = None
        self.our_seq = None
        self.peer_seq = None
        self.StorageNonceManager = StorageNonceManager()
        self.generate_keys()

    # Helo
    # INIT
    # HANDSHAKE1
    # HANDSHAKE2
    # KEY
    # SEQ1 (SEND KEY AND SEQ NUMBER)
    # SEQ2
    # TEST1
    # TEST2

    # Public Key
    # - Ask for Public Key

    def handleHandshake(self, msg_type, data, other_public):
        if msg_type == b"HELO":
            helo_response(self, msg_type,  data, self.private_key, other_public)
        elif msg_type == b"HANDSHAKE1":
            handshake1_response(self, msg_type, data, self.other_public)
        elif msg_type == b"HANDSHAKE2":
            handshake2_response(self, msg_type,  data, self.other_public)
        elif msg_type == b"KEY":
            key_response(self, msg_type,  data, self.other_public)
        elif msg_type == b"SEQ1":
            seq1_response(self, msg_type, data)
        elif msg_type == b"SEQ2":
            print(seq2_response(self, msg_type, data))
        elif msg_type == b"TEST":
            print("YOU MADE IT TO THE END!!, TEST1")

    # Public Key

    def askForPublicKey(self, initiate=False):
        # Serialize the public key to PEM format
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if initiate:
            # print(f"Sending public key to {self.identity}")
            self.socket.send_multipart([b"PUBLIC_KEY", public_pem])
        else:
            print(f"Sending public key response to {self.identity}")
            self.socket.send_multipart([b"PUBLIC_KEY_RESPONSE", public_pem])

    def listen_for_messages(self):
        while self.listening:
            try:
                recv = self.subscriber.recv_multipart(flags=zmq.NOBLOCK)
                # print(f"Received from {self.identity}: {recv}")
                if not recv or len(recv) != 2:
                    print(f"Invalid message format from {self.identity}")
                    continue

                msg_type, data = recv

                self.handleHandshake(msg_type, data, self.other_public)

                if msg_type == b"MESSAGE" and self.symmetric_key:
                    decrypted = self.decrypt_message(data)
                    print(f"Received: {decrypted}")

                if msg_type == b"PUBLIC_KEY":
                    self.askForPublicKey()
                    public_key = serialization.load_pem_public_key(data)
                    self.other_public = public_key
                    print(
                        f"Received public key for {self.identity}", public_key)
                elif msg_type == b"PUBLIC_KEY_RESPONSE":
                    public_key = serialization.load_pem_public_key(data)
                    self.other_public = public_key
                    print(
                        f"Received public key for {self.identity}", public_key)
            except zmq.Again:
                time.sleep(0.1)
            except Exception as e:
                print(f"Error in listener {self.identity}: {e}")

    def initiate_handshake(self):
        if self.symmetric_key:
            return True

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

        # Concatenate nonce and encrypted nonce
        combined_nonce = nonce_with_timestamp + encrypted_nonce
        
        print(f"Sending handshake to {self.identity}")
        # Send the combined nonce as the second part of the message
        self.socket.send_multipart([b"HELO", combined_nonce])

        # Wait for peer response with timeout
        start_time = time.time()
        while time.time() - start_time < 5:  # 5 second timeout
            if self.symmetric_key:
                return True
            time.sleep(0.1)
        print(f"Handshake to {self.identity} timed out")
        return False

    def encrypt_message(self, message):   
        # Create timestamp and combine with message
        nonce = self.StorageNonceManager.get_nonce()
        timestamp = struct.pack('>Q', int(time.time()))
        # Encode the message as bytes before concatenation
        message_bytes = message.encode('utf-8')
        timestamped_message = timestamp + message_bytes
        
        # Encrypt the message using AES-GCM
        aesgcm = AESGCM(self.symmetric_key)
        ct = aesgcm.encrypt(nonce, timestamped_message, None)  # Added None as associated_data parameter
        hash = hash_message(ct, self.symmetric_key)
        
        # Combine nonce, encrypted data, and hash into a single byte string
        combined_message = nonce + ct + hash
        
        return combined_message

    def decrypt_message(self, encrypted_message):
        # Extract components using the same structure as encrypt_message
        nonce = encrypted_message[:12]
        ct = encrypted_message[12:-32]  # Everything between nonce and hash
        hash = encrypted_message[-32:]  # Hash is 32 bytes

        # Verify the hash
        expected_hash = hash_message(ct, self.symmetric_key)
        if not hmac.compare_digest(expected_hash, hash):
            raise ValueError("Hash verification failed")

        # Decrypt the message using the received nonce
        aesgcm = AESGCM(self.symmetric_key)
        timestamped_message = aesgcm.decrypt(nonce, ct, None)  # Added None as associated_data parameter

        # Extract the timestamp and original message
        timestamp = struct.unpack('>Q', timestamped_message[:8])[0]
        message = timestamped_message[8:].decode('utf-8')

        # Optionally, check if the message is too old
        if time.time() - timestamp > 60:  # 60 seconds tolerance
            raise ValueError("Message is too old")

        return message

    def send_message(self, message):
        if not self.symmetric_key:
            if not self.initiate_handshake():
                raise Exception(f"Handshake failed from {self.identity}")
        encrypted = self.encrypt_message(message)
        self.socket.send_multipart([b"MESSAGE", encrypted])

    def close(self):
        self.listening = False
        self.listener_thread.join()
        self.socket.close()
        self.subscriber.close()
        self.context.term()

    def generate_keys(self):
        # Generate a new RSA private key with 2048 bits
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Get the public key from the private key
        self.public_key = self.private_key.public_key()

        # Create a dummy certificate (in real applications, this would be signed by a CA)
        self.certificate = {
            "subject": f"peer_{self.identity}",
            "public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "valid_from": time.time(),
            "valid_until": time.time() + (365 * 24 * 60 * 60),  # Valid for 1 year
            "issuer": "DummyCA",
            "serial_number": os.urandom(8).hex()
        }

        # Sign the certificate with our private key (in real applications, this would be signed by a CA)
        cert_data = str(self.certificate).encode()
        self.certificate["signature"] = self.private_key.sign(
            cert_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
