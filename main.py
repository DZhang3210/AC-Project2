import time
from CommunicationNode import SecurePeer


# peer1 = SecurePeer(5555, 5556, "peer1")
# peer2 = SecurePeer(5556, 5555, "peer2")
peer1 = None

main_port = input("Choose main port: ")
sub_port = input("Choose sub port: ")
peer1 = SecurePeer(main_port, sub_port, "peer1")

time.sleep(1)
while not peer1.get_live_port():
    peer1.live_ping()
    print("Waiting for live response")
    time.sleep(0.3)

print("Live port found")

while not peer1.messagesReady():
    time.sleep(0.3)
print("Handshake complete")

print("Sending messages")
print("(q to quit or type anything else to send message to send): ")
while True:
    message = input("")
    if message.lower() == "q":
        break
    
    peer1.send_message(message)


print("Closing peers")
# Clean up
peer1.close()
