from helperFunctions.verify_signature import verify_signature


def handshake1_response(self, data):
    nonce, result = verify_signature(data, self.other_public)
    if not result:
        print("[HANDSHAKE1]: HELO failed")
        return
    # print("[HANDSHAKE1]: Verified handshake request")

    print(f"[HANDSHAKE1]: Continuing to  HANDSHAKE2 from {self.identity}")
    # b'0' is just a placeholder, doesn't actually do anything
    self.socket.send_multipart([b"HANDSHAKE2", b'0'])
