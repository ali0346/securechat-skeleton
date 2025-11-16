# """Helper signatures: now_ms, b64e, b64d, sha256_hex."""

# def now_ms(): raise NotImplementedError

# def b64e(b: bytes): raise NotImplementedError

# def b64d(s: str): raise NotImplementedError

# def sha256_hex(data: bytes): raise NotImplementedError



"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import time
from hashlib import sha256

def now_ms() -> int:
    """Returns the current time in milliseconds since the Unix epoch."""
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    """Encodes bytes to a URL-safe base64 string."""
    return base64.urlsafe_b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    """Decodes a URL-safe base64 string back to bytes."""
    try:
        return base64.urlsafe_b64decode(s.encode('utf-8'))
    except (base64.binascii.Error, TypeError) as e:
        print(f"Error decoding base64: {e}")
        # Return a value that's unlikely to be valid to cause downstream failures
        return b'\x00'

def sha256_hex(data: bytes) -> str:
    """Computes the SHA-256 hash of the data and returns it as a hex string."""
    return sha256(data).hexdigest()