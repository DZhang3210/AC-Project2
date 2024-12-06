import zmq
import time
import threading
import hmac
from cryptography.hazmat.primitives import serialization
from StorageNonceManager import StorageNonceManager
from handshakeSteps.handleHandshake import handleHandshake
from handshakeSteps.initiate_handshake import initiate_handshake
from helperFunctions.encryptMessage import encrypt_message
from helperFunctions.decryptMessage import decrypt_message
from helperFunctions.generateKeys import generate_keys
from helperFunctions.hash_message import hash_message

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
        self.message_ttl = 60
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

                handleHandshake(self, msg_type, data)

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
        return initiate_handshake(self)

    
    def encrypt_message(self, message):
        return encrypt_message(self, message)

    def decrypt_message(self, encrypted_message):
        return decrypt_message(self, encrypted_message)

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
        return generate_keys(self)