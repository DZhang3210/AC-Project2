import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


def generate_keys(self):
    # Generate a new RSA private key with 2048 bits
    self.private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Get the public key from the private key
    self.public_key = self.private_key.public_key()

    # Create a dummy certificate (in real applications, this would be signed by a CA)
    self.certificate = {
        "subject": f"peer_{self.identity}",
        "public_key": self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "valid_from": time.time(),
        "valid_until": time.time() + (365 * 24 * 60 * 60),  # Valid for 1 year
        "issuer": "DummyCA",
        "serial_number": os.urandom(8).hex()
    }

    # Sign the certificate with our private key (in real applications, this would be signed by a CA)
    cert_data = str(self.certificate).encode()
    self.certificate["signature"] = self.private_key.sign(
        cert_data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
