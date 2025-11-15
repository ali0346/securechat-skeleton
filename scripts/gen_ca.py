# """Create Root CA (RSA + self-signed X.509) using cryptography.""" 
# raise NotImplementedError("students: implement CA generation")


"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Ensure certs directory exists
Path("certs").mkdir(exist_ok=True)
CA_KEY_FILE = Path("certs/ca-key.pem")
CA_CERT_FILE = Path("certs/ca-cert.pem")
DEFAULT_CA_NAME = "SecureChat Root CA"

def generate_ca(common_name: str, key_size: int = 2048, validity_days: int = 3650):
    """
    Generates a new Root CA private key and a self-signed certificate.
    """
    print(f"Generating {key_size}-bit RSA private key for Root CA...")
    
    # 1. Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # 2. Save Private Key
    with open(CA_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Root CA private key saved to {CA_KEY_FILE}")

    # 3. Create a self-signed certificate
    print(f"Generating self-signed Root CA certificate for '{common_name}'...")
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Issuer is the same as subject for a self-signed root cert
    issuer = subject

    # Build the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Set validity (e.g., 10 years)
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
    ).add_extension(
        # Basic Constraints: Mark this as a CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        # Key Usage: Mark for signing certificates and CRLs
        x509.KeyUsage(
            key_cert_sign=True, 
            crl_sign=True,
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).sign(private_key, hashes.SHA256(), default_backend())

    # 4. Save Certificate
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Root CA certificate saved to {CA_CERT_FILE}")
    print("\nRoot CA generation complete.")

def main():
    parser = argparse.ArgumentParser(description="Generate a Root CA private key and self-signed certificate.")
    parser.add_argument(
        "--name", 
        type=str, 
        default=DEFAULT_CA_NAME,
        help=f"Common Name (CN) for the Root CA. Default: '{DEFAULT_CA_NAME}'"
    )
    args = parser.parse_args()

    if CA_KEY_FILE.exists() or CA_CERT_FILE.exists():
        print(f"Error: {CA_KEY_FILE} or {CA_CERT_FILE} already exists.", file=sys.stderr)
        print("Please delete existing CA files if you want to regenerate.", file=sys.stderr)
        sys.exit(1)
        
    generate_ca(args.name)

if __name__ == "__main__":
    main()