def seq2_response(self, data):
    self.decrypt_message(data)

    self.socket.send_multipart([b"TEST", b"Finished"])

