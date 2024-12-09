import zmq
import time
import threading
from cryptography.hazmat.primitives import serialization
from StorageNonceManager import StorageNonceManager
from handshakeSteps.handleHandshake import handleHandshake
from handshakeSteps.initiate_handshake import initiate_handshake
from helperFunctions.encryptMessage import encrypt_message
from helperFunctions.decryptMessage import decrypt_message
from helperFunctions.generateKeys import generate_keys
from helperFunctions.publicKey import public_key_handler
from helperFunctions.verify_signature import verify_signature

class SecurePeer:
    def __init__(self, my_port, peer_port, identity):
        
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.bind(f"tcp://*:{my_port}")
        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.connect(f"tcp://localhost:{peer_port}")
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")

        #Listening
        self.listening = True
        self.listener_thread = threading.Thread(
            target=self.listen_for_messages)
        self.listener_thread.start()

        #Constants
        self.message_ttl = 60
        self.public_key = None
        self.private_key = None
        self.identity = identity    #Name of the peer
        self.StorageNonceManager = StorageNonceManager()

        #Session specific
        self.symmetric_key = None
        self.other_public = None
        self.peer_seq = None
        self.live_port = False
        self.handshake_complete = False
        self.seq_number = None
        self.other_seq_number = None
        

        self.generate_keys()

    # Helo
    # INIT
    # HANDSHAKE2
    # KEY
    # SEQ1 (SEND KEY AND SEQ NUMBER)
    # SEQ2

    # Public Key
    # - Ask for Public Key

 

    #Toggle live port
    def messagesReady(self):
        return self.symmetric_key is not None and self.other_public is not None and self.handshake_complete
    def toggle_live_port(self):
        self.live_port = not self.live_port
    def get_live_port(self):
        return self.live_port
    def live_ping(self, respond=False):
        
        if respond:
            # print(self.identity, "pinging")
            self.socket.send_multipart([b"LIVE_PONG", b""])
        else:
            # print(self.identity, "ponging")
            self.socket.send_multipart([b"LIVE_PING", b""])
            
    def askForPublicKey(self, initiate=False):
        # Serialize the public key to PEM format
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if initiate:
            # print(f"Sending public key to {self.identity}")
            self.socket.send_multipart([b"PUBLIC_KEY", public_pem])
            print(f"Sent public key to {self.public_key} from {self.identity}")
        else:
            # print(f"Sending public key response to {self.identity}")
            self.socket.send_multipart([b"PUBLIC_KEY_RESPONSE", public_pem])
            print(f"Sent public key response to {self.public_key} from {self.identity}")

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
                    
                    print("RECEIVED", decrypted)
                elif msg_type == b"LIVE_PING" or msg_type == b"LIVE_PONG":
                    self.toggle_live_port()
                    if msg_type == b"LIVE_PING":
                        self.live_ping(respond=True)
                    elif msg_type == b"LIVE_PONG":
                        print("PING AND HANDSHAKE")
                        print("Asking for public key")
                        self.askForPublicKey(True)
                        time.sleep(0.5)
                        print("Initiating handshake")
                        self.initiate_handshake()
                        time.sleep(0.5)
                        print("Handshake complete")
                   
                else:
                    public_key_handler(self, msg_type, data)
                
            except zmq.Again:
                time.sleep(0.1)
            except Exception as e:
                print(f"Error in listener {self.identity}: {e}")

    def initiate_handshake(self):
        return initiate_handshake(self)

    def verify_signature(self, data, peer_public_key):
        return verify_signature(self, data, peer_public_key)
    
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