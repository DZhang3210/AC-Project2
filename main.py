import time
from CommunicationNode import SecurePeer

peer1 = SecurePeer(5555, 5556, "peer1")
peer2 = SecurePeer(5556, 5555, "peer2")

time.sleep(0.5)

print("Initiating handshake")
peer1.askForPublicKey(True)
time.sleep(0.5)
peer1.initiate_handshake()
time.sleep(0.5)


print("Sending messages")
# Send messages (handshake will happen automatically)
peer1.send_message("Hello from peer 1")
peer2.send_message("Hello from peer 2")

time.sleep(1)

print("Closing peers")
# Clean up
peer1.close()
peer2.close()