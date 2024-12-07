from helperFunctions.hash_message import verify_hash

def seq1_response(self, data):
    # Split the received data into encrypted payload and MAC
    encrypted_seq = data[:-48]  # MAC is 32 bytes (SHA256)
    received_mac = data[-48:]

    # Verify MAC using symmetric key
    verified = verify_hash(encrypted_seq, self.symmetric_key, received_mac) 
    if not verified:
        raise ValueError("[SEQ1]: MAC verification failed")

    encrypted_payload = self.encrypt_message("test")

    # Send the message
    print(f"[SEQ1]: Continuing to SEQ2 from {self.identity}")
    self.socket.send_multipart([b"SEQ2", encrypted_payload])
