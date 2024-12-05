from threading import Lock
import os
class StorageNonceManager:
    def __init__(self):
        self.used_nonces = set()
        self.lock = Lock()
    
    def get_nonce(self):
        with self.lock:
            while True:
                nonce = os.urandom(12)
                if nonce not in self.used_nonces:
                    self.used_nonces.add(nonce)
                    return nonce