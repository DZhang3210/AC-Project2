class PublicKeyManager:
    def __init__(self):
        self.public_key = os.urandom(16)
        self.private_key = os.urandom(16)

