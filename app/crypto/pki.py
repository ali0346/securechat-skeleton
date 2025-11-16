# """X.509 validation: signed-by-CA, validity window, CN/SAN.""" 
# raise NotImplementedError("students: implement PKI checks")


"""X.509 validation: signed-by-CA, validity window, CN/SAN."""


import datetime
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

# --- Globals ---
CA_CERT_FILE = Path("certs/ca-cert.pem")
g_ca_cert = None
g_ca_public_key = None

def load_ca_cert():
    """Loads the global Root CA certificate from file."""
    global g_ca_cert, g_ca_public_key
    if g_ca_cert:
        return g_ca_cert

    try:
        with open(CA_CERT_FILE, "rb") as f:
            g_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            g_ca_public_key = g_ca_cert.public_key()
            print(f"Root CA '{g_ca_cert.subject.rfc4514_string()}' loaded.")
            return g_ca_cert
    except FileNotFoundError:
        print(f"Error: Root CA cert {CA_CERT_FILE} not found.", file=sys.stderr)
        print("Please run 'python scripts/gen_ca.py' first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading Root CA cert: {e}", file=sys.stderr)
        sys.exit(1)

def load_cert_and_key(cert_path_str: str, key_path_str: str):
    """Loads an entity's certificate and private key from PEM files."""
    try:
        cert_path = Path(cert_path_str)
        key_path = Path(key_path_str)
        
        # 1. Load Certificate
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
        # 2. Load Private Key
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # 3. Load PEM data as bytes
        cert_pem_bytes = cert_path.read_bytes()

        return cert, private_key, cert_pem_bytes

    except FileNotFoundError as e:
        print(f"Error: Missing certificate or key file: {e.filename}", file=sys.stderr)
        print("Please run 'python scripts/gen_cert.py' first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading cert/key: {e}", file=sys.stderr)
        sys.exit(1)

def parse_certificate(cert_pem_bytes: bytes) -> x509.Certificate | None:
    """Parses a PEM-encoded certificate from bytes."""
    try:
        return x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
    except Exception as e:
        print(f"Error parsing certificate: {e}", file=sys.stderr)
        return None

def validate_certificate(
    cert: x509.Certificate,
    expected_cn: str | None
) -> tuple[bool, str]:
    """
    Validates a given certificate against our Root CA.
    Per Req 2.1 / PDF Page 6:
    i. Signature chain validity (trusted CA)
    ii. Expiry date and validity period
    iii. Common Name (CN) or hostname match
    """
    if not g_ca_public_key or not g_ca_cert:
        load_ca_cert()
        
    # i. Signature chain validity
    try:
        g_ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False, "BAD_CERT: Signature is invalid (not signed by our CA)"
    except Exception as e:
        return False, f"BAD_CERT: Signature verification failed: {e}"

    # ii. Expiry date and validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, f"BAD_CERT: Certificate is not yet valid (valid from {cert.not_valid_before_utc})"
    if now > cert.not_valid_after_utc:
        return False, f"BAD_CERT: Certificate has expired (expired on {cert.not_valid_after_utc})"

    # iii. Common Name (CN) match
    if expected_cn:
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cn != expected_cn:
                return False, f"BAD_CERT: Common Name mismatch (expected '{expected_cn}', got '{cn}')"
        except x509.ExtensionNotFound:
            return False, "BAD_CERT: No Common Name (CN) found in certificate"

    # All checks passed
    return True, "OK: Certificate is valid"