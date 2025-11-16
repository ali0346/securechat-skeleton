# """Append-only transcript + TranscriptHash helpers.""" 
# raise NotImplementedError("students: implement transcript layer")


"""Append-only transcript + TranscriptHash helpers."""

import os
import sys
from pathlib import Path
from hashlib import sha256
from app.common.utils import sha256_hex
from app.crypto.sign import sign

# Ensure transcripts directory exists
Path("transcripts").mkdir(exist_ok=True)

class TranscriptLogger:
    """
    Manages the append-only transcript file for a single session.
    """
    def __init__(self, peer_name: str, session_id: str):
        self.filename = Path(f"transcripts/{peer_name}_{session_id}.log")
        self.transcript_hash_obj = sha256()
        
        try:
            # Clear the file on init to ensure a fresh log for this session
            with open(self.filename, "w") as f:
                f.write(f"# --- Session Transcript for {peer_name} ({session_id}) ---\n")
            print(f"Transcript logger initialized. Logging to {self.filename}")
        except IOError as e:
            print(f"Error: Could not write to transcript file {self.filename}: {e}", file=sys.stderr)
            sys.exit(1)

    def log_message(
        self, 
        peer_name: str, 
        seqno: int, 
        ts: int, 
        ct_b64: str, 
        sig_b64: str,
        peer_cert_fingerprint: str
    ):
        """
        Logs a single message to the transcript file in the format specified
        by Req 1.4 / PDF Page 5.
        
        Format: seqno | ts | ct | sig | peer-cert-fingerprint
        """
        log_line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_cert_fingerprint}\n"
        
        try:
            # 1. Append to file
            with open(self.filename, "a") as f:
                f.write(log_line)
                
            # 2. Update the running transcript hash
            # Per PDF (1.4): Transcript Hash = SHA256(concatenation of transcript lines)
            self.transcript_hash_obj.update(log_line.encode('utf-8'))
            
        except IOError as e:
            print(f"Error: Could not write to transcript file: {e}", file=sys.stderr)

    def get_transcript_hash(self) -> str:
        """
        Returns the hex-encoded SHA-256 hash of the entire transcript.
        """
        return self.transcript_hash_obj.hexdigest()