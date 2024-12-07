from .key import key_response
from .handshake2 import handshake2_response
from .helo import helo_response
from .seq1 import seq1_response
from .handshake1 import handshake1_response
from .seq2 import seq2_response


def handleHandshake(self, msg_type, data):
    if msg_type == b"HELO":
        print(f"[HELO]: Received from {self.identity}")
        helo_response(self, data)
    elif msg_type == b"HANDSHAKE1":
        print(f"[HANDSHAKE1]: Received from {self.identity}")
        handshake1_response(self, data)
    elif msg_type == b"HANDSHAKE2":
        print(f"[HANDSHAKE2]: Received from {self.identity}")
        handshake2_response(self)
    elif msg_type == b"KEY":
        print(f"[KEY]: Received from {self.identity}")
        key_response(self, data)
    elif msg_type == b"SEQ1":
        seq1_response(self, data)
    elif msg_type == b"SEQ2":
        print(f"[SEQ2]: Received from {self.identity}")
        seq2_response(self, data)
        print("[SEQ2]: Test finished, secure comms channel established")
    elif msg_type == b"TEST":
        print("[TEST]: Test finished, secure comms channel established")
