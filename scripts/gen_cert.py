# """Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
# raise NotImplementedError("students: implement cert issuance")


"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration ---
CA_KEY_FILE = Path("certs/ca-key.pem")
CA_CERT_FILE = Path("certs/ca-cert.pem")
DEFAULT_VALIDITY_DAYS = 365
DEFAULT_KEY_SIZE = 2048

def load_ca(key_path: Path, cert_path: Path):
    """Loads the CA private key and certificate."""
    print(f"Loading Root CA from {key_path} and {cert_path}...")
    try:
        # Load Private Key
        with open(key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load Certificate
        with open(cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
        return ca_private_key, ca_cert
    except FileNotFoundError as e:
        print(f"Error: Missing CA file: {e.filename}", file=sys.stderr)
        print("Please run 'python scripts/gen_ca.py' first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading CA: {e}", file=sys.stderr)
        sys.exit(1)

def generate_signed_certificate(
    common_name: str, 
    output_prefix: Path, 
    ca_key, 
    ca_cert
):
    """
    Generates a new keypair and a certificate signed by the provided CA.
    """
    key_file = output_prefix.with_suffix(".key.pem")
    cert_file = output_prefix.with_suffix(".cert.pem")

    print(f"Generating new {DEFAULT_KEY_SIZE}-bit RSA key for '{common_name}'...")
    
    # 1. Generate new Private Key for the subject
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=DEFAULT_KEY_SIZE,
        backend=default_backend()
    )

    # 2. Save new Private Key
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Saved new key to {key_file}")

    # 3. Generate the certificate signed by the CA
    print(f"Generating certificate for '{common_name}'...")
    
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat User"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # The issuer is the subject of the CA's certificate
    issuer_name = ca_cert.subject

    # Build the certificate
    cert_builder = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        issuer_name
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Set validity (e.g., 1 year)
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=DEFAULT_VALIDITY_DAYS)
    ).add_extension(
        # Per assignment: SAN=DNSName(CN)
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).add_extension(
        # Basic Constraints: This is NOT a CA
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension(
        # Key Usage: For digital signature and key encipherment (e.g., for RSA)
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True, # For RSA key transport (though we use DH)
            data_encipherment=False,
            key_agreement=False, # We use DH, not RSA key agreement
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).add_extension(
        # Extended Key Usage: Mark for Client and Server Auth
        x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False
    )
    
    # Sign the certificate with the CA's private key
    signed_cert = cert_builder.sign(ca_key, hashes.SHA256(), default_backend())

    # 4. Save Certificate
    with open(cert_file, "wb") as f:
        f.write(signed_cert.public_bytes(serialization.Encoding.PEM))
    print(f"Saved signed certificate to {cert_file}")


def main():
    parser = argparse.ArgumentParser(description="Issue a new certificate signed by the Root CA.")
    parser.add_argument(
        "--cn", 
        type=str, 
        required=True,
        help="Common Name (CN) for the certificate (e.g., 'server.local' or 'client.local')."
    )
    parser.add_argument(
        "--out", 
        type=str,
        required=True,
        help="Output file prefix (e.g., 'certs/server'). Will create 'certs/server.key.pem' and 'certs/server.cert.pem'."
    )
    args = parser.parse_args()

    output_prefix = Path(args.out)
    
    # Ensure output directory exists
    output_prefix.parent.mkdir(parents=True, exist_ok=True)

    key_file = output_prefix.with_suffix(".key.pem")
    cert_file = output_prefix.with_suffix(".cert.pem")

    if key_file.exists() or cert_file.exists():
        print(f"Error: Output files {key_file} or {cert_file} already exist.", file=sys.stderr)
        print("Please delete existing files if you want to regenerate.", file=sys.stderr)
        sys.exit(1)

    # 1. Load CA
    ca_key, ca_cert = load_ca(CA_KEY_FILE, CA_CERT_FILE)
    
    # 2. Generate signed certificate
    generate_signed_certificate(args.cn, output_prefix, ca_key, ca_cert)
    print(f"\nSuccessfully issued certificate for '{args.cn}'.")

if __name__ == "__main__":
    main()