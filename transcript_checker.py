"""
Offline tool to verify the SessionReceipt against the transcript log file.
Checks:
1. Receipt signature is valid (signed by the peer's RSA key).
2. Transcript hash in the receipt matches the hash recomputed from the log file.
"""
import argparse
import sys
import json
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature

from app.crypto.sign import verify, get_public_key_from_cert
from app.common.utils import b64d
from app.common import protocol as proto

def load_certificate(cert_path: Path) -> x509.Certificate:
    """Loads and returns an X.509 certificate."""
    try:
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except FileNotFoundError:
        print(f"[ERROR] Certificate file not found: {cert_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to load certificate: {e}", file=sys.stderr)
        sys.exit(1)

def recompute_transcript_hash(log_path: Path) -> str:
    """Computes the SHA-256 hash of the entire transcript file content."""
    h = sha256()
    try:
        with open(log_path, 'r') as f:
            for line in f:
                # IMPORTANT: Skip the header line(s) starting with '#'
                if not line.startswith('#'):
                    # The hash is computed over the concatenation of the raw log lines
                    h.update(line.encode('utf-8'))
        return h.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] Transcript log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to read log file: {e}", file=sys.stderr)
        sys.exit(1)

def verify_session_receipt(receipt_path: Path, log_path: Path, peer_cert_path: Path):
    """Performs full non-repudiation verification."""
    print(f"--- Verifying Session Receipt: {receipt_path} ---")

    # 1. Load Certificate and Public Key
    peer_cert = load_certificate(peer_cert_path)
    peer_pubkey = get_public_key_from_cert(peer_cert)
    
    # 2. Recompute Transcript Hash
    recomputed_hash = recompute_transcript_hash(log_path)
    print(f"[INFO] Recomputed Transcript Hash: {recomputed_hash}")

    # 3. Load Receipt
    try:
        with open(receipt_path, 'r') as f:
            receipt_data = json.load(f)
        receipt = proto.Receipt.model_validate(receipt_data)
    except FileNotFoundError:
        print(f"[ERROR] Receipt file not found: {receipt_path}", file=sys.stderr)
        return
    except Exception as e:
        print(f"[ERROR] Failed to parse receipt JSON: {e}", file=sys.stderr)
        return
        
    receipt_hash = receipt.transcript_sha256
    
    # 4. Check Hash Match
    if receipt_hash != recomputed_hash:
        print("\n[VERIFICATION FAILED: INTEGRITY LOSS]")
        print(f"Receipt Hash ({receipt.peer}): {receipt_hash}")
        print(f"Recomputed Hash: {recomputed_hash}")
        print("Reason: The transcript file was modified after the receipt was signed.")
        return

    # 5. Verify Signature
    # The signature is over the hex-encoded transcript hash
    is_valid = verify(
        public_key=peer_pubkey,
        signature=b64d(receipt.sig),
        data=receipt_hash.encode('utf-8')
    )

    if is_valid:
        print("\n[VERIFICATION SUCCESSFUL: NON-REPUDIATION ESTABLISHED]")
        print(f"Hash matches and signature is valid.")
    else:
        print("\n[VERIFICATION FAILED: AUTHENTICITY LOSS]")
        print("Reason: Receipt signature is invalid (forged or wrong key used).")
    
# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline utility for verifying a SessionReceipt against its Transcript.")
    parser.add_argument("--receipt", type=Path, required=True, help="Path to the SessionReceipt JSON file.")
    parser.add_argument("--log", type=Path, required=True, help="Path to the corresponding transcript log file.")
    parser.add_argument("--cert", type=Path, required=True, help="Path to the PEER's public certificate (e.g., certs/client.cert.pem).")
    
    args = parser.parse_args()
    verify_session_receipt(args.receipt, args.log, args.cert)