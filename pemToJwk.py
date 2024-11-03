import json
import base64
from cryptography.hazmat.primitives import serialization

def to_base64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")

def rsa_key_to_jwk(private_key):
    numbers = private_key.private_numbers()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "n": to_base64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')),
        "e": to_base64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')),
        "d": to_base64url(numbers.d.to_bytes((numbers.d.bit_length() + 7) // 8, byteorder='big')),
        "p": to_base64url(numbers.p.to_bytes((numbers.p.bit_length() + 7) // 8, byteorder='big')),
        "q": to_base64url(numbers.q.to_bytes((numbers.q.bit_length() + 7) // 8, byteorder='big')),
        "dp": to_base64url(numbers.dmp1.to_bytes((numbers.dmp1.bit_length() + 7) // 8, byteorder='big')),
        "dq": to_base64url(numbers.dmq1.to_bytes((numbers.dmq1.bit_length() + 7) // 8, byteorder='big')),
        "qi": to_base64url(numbers.iqmp.to_bytes((numbers.iqmp.bit_length() + 7) // 8, byteorder='big')),
        "alg": "RS256",
        "kid": "your-key-id"  # Optionally include a key ID
    }

# Load private key from PEM file
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

jwk_private = rsa_key_to_jwk(private_key)
jwk_public = {
    "kty": "RSA",
    "n": jwk_private["n"],
    "e": jwk_private["e"],
    "alg": "RS256",
    "kid": "your-key-id"  # Public key ID can be the same as private key ID
}

print("Private JWK:", json.dumps(jwk_private, indent=2))
print("Public JWK:", json.dumps(jwk_public, indent=2))
