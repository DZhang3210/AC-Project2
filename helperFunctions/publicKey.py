from cryptography.hazmat.primitives import serialization


def public_key_handler(self, msg_type, data):
    if msg_type == b"PUBLIC_KEY":
        self.askForPublicKey()
        public_key = serialization.load_pem_public_key(data)
        self.other_public = public_key
        print(f"Received public key for {self.identity}", public_key)
    elif msg_type == b"PUBLIC_KEY_RESPONSE":
        public_key = serialization.load_pem_public_key(data)
        self.other_public = public_key
        print(f"Received public key for {self.identity}", public_key)