from .key import key_response
from .handshake2 import handshake2_response
from .helo import helo_response
from .seq1 import seq1_response
from .handshake1 import handshake1_response
from .seq2 import seq2_response


def handleHandshake(self, msg_type, data):
    if msg_type == b"HELO":
        helo_response(self, data)
    elif msg_type == b"HANDSHAKE1":
        handshake1_response(self, data)
    elif msg_type == b"HANDSHAKE2":
        handshake2_response(self)
    elif msg_type == b"KEY":
        key_response(self, data)
    elif msg_type == b"SEQ1":
        seq1_response(self, data)
    elif msg_type == b"SEQ2":
        seq2_response(self, data)
    elif msg_type == b"TEST":
        print("[TEST]: Test finished, secure comms channel established")
