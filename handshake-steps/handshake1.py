from helperFunctions.verify_signature import verify_signature

def handshake1_response(self, data):
    nonce, result = verify_signature(data, self.other_public)
    if not result:
        print("Helo failed")
    print("Verified handshake1")

    print(f"Sending HANDSHAKE2 from {self.identity}")
    self.socket.send_multipart([b"HANDSHAKE2", b"TODO:Certificate"])


