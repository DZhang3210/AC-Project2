
def seq2_response(self, data):
    self.decrypt_message(data)
    
    # print(f"[SEQ2]: Continuing to TEST from {self.identity}")
    # b'0' is just a placeholder, doesn't actually do anything
    self.socket.send_multipart([b"TEST", b'0'])
