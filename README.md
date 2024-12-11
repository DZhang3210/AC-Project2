# AC-Project2

This app is a proof of concept for a secure messaging system using ZeroMQ and python crypto libraries. It is a hybrid encryption system that uses RSA for key exchange and AES symmetric encryption. It is designed to use non-deterministic nonce values for all encryption and hashing operations. We also made sure to secure against a Nonce-reuse attack by establishing a StorageNonceManager that stores and references nonce values in a set, to prevent the same nonce from being used twice. Additionally, we prevented timing attacks by using a constant time comparison function for all cryptographic operations. It also timestamps all messages to prevent replay attacks. Additionally, seq# are used, in order to prevent recordering attacks. One possible exploit in our system is the public key exchange which is not secure and could be exploited by an attacker to gain access to the system. A better implementation would be to build a PKI to sign the public keys and verify identities.

Relevant sizes:

- RSA key: 2048 bits
- AES key: 256 bits
- SHA256 key: 256 bits
- Nonce: 96 bits
- Timestamp: 64 bits
- Sequence number: 32 bits

Pinging
First node will constantly send a ping message to the other node, and the other node will respond with a pong message. This is used to keep the connection alive and to check if the other node is still alive. Upon being pinged, the node will toggle its live port, which is used to send and receive messages.

Public Key Exchange (In order to build a PKI we'd require a CA to sign the public keys and verify identities which we're not doing here)
A -> B: public_key_A
B -> A: public_key_B

Handshake Flow
A -> B: signed_Private{nonce A + timestamp A}
B -> A: signed_Private{nonce B + timestamp B}

[Timestamp verification - must be within acceptable window]
[A verifies B's nonce using B's public key]
[B verifies A's nonce using A's public key]

A -> B: Encrypted_Public(ephemeral session key + Aseq# nonce + timestamp) + MAC (w/ Nonce)
B -> A: (Encrypted_Public{ ACK + Bseq# nonce + timestamp}) + MAC (w/ Nonce)

[Begin test messages with seq# + 1]
[you increment seq number by 1 for each packet]
[Sender send a packet, increment their own seq # by 1, receiver gets packet they increment sender’s seq # locally by 1]

A -> B: Encrypted_Symmetric(Aseq# + Test message + nonce + timestamp) + MAC(w /Nonce)
B -> A: Encrypted_Symmetric(Bseq# + Test message + nonce + timestamp) + MAC(w /Nonce)

[A and B increment their own seq # by 1]

Ongoing session
A -> B: Encrypted_Symmetric(Aseq# + Message_A + nonce + timestamp) + MAC(w /Nonce)
B -> A: Encrypted_Symmetric(Bseq# + Message_B + nonce + timestamp) + MAC(w /Nonce)

[A and B increment their own seq # by 1]

How to run:
Run the server (main.py) first in it's own terminal, then run the client (also main.py) in another terminal. Then when specifying main and sub ports, specify the main port for the server and the sub port for the client. So, for example, if the server is running on main port 5555 and sub port 5556, then the client should be running on main port 5556 and sub port 5555. After both clients are running, it will complete the brief handshake and you can start sending messages between the two clients.
