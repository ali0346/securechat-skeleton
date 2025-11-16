# """RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
# raise NotImplementedError("students: implement RSA helpers")


"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
# Per assignment spec, we must use RSA with SHA-256 and PKCS#1 v1.5 padding
SIGNATURE_PADDING = padding.PKCS1v15()
SIGNATURE_HASH_ALGO = hashes.SHA256()

def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Signs data using the provided RSA private key.
    (Data is typically a SHA-256 hash, but the `sign` function hashes it).
    
    Per PDF (1.3): sig = RSA_SIGN(SHA256(seqno || ts || ct))
    The `sign` method computes the hash internally.
    """
    return private_key.sign(
        data,
        SIGNATURE_PADDING,
        SIGNATURE_HASH_ALGO
    )

def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verifies an RSA signature using the provided public key.
    Returns True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            SIGNATURE_PADDING,
            SIGNATURE_HASH_ALGO
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error during signature verification: {e}")
        return False

def get_public_key_from_cert(cert: x509.Certificate) -> rsa.RSAPublicKey:
    """Extracts the RSA public key from an X.509 certificate."""
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Certificate does not contain an RSA public key")
    return public_key