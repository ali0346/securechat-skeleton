# """Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
# raise NotImplementedError("students: define pydantic models")

"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel, Field
from typing import Annotated # We need this for Pydantic v2

# --- Pydantic v2 Type Definitions ---

# A type for non-empty, non-whitespace strings
NonEmptyStr = Annotated[str, Field(strip_whitespace=True, min_length=1)]

# A type for Base64 encoded strings
B64Str = NonEmptyStr

# --- 1.1 Control Plane (Negotiation and Authentication) ---

class Hello(BaseModel):
    """Client -> Server: Initiates connection with certificate."""
    type: Annotated[str, Field(pattern=r"^hello$")] = "hello"
    client_cert: B64Str # PEM-encoded X.509 cert
    nonce: B64Str

class ServerHello(BaseModel):
    """Server -> Client: Responds with its certificate."""
    type: Annotated[str, Field(pattern=r"^server_hello$")] = "server_hello"
    server_cert: B64Str # PEM-encoded X.509 cert
    nonce: B64Str

# --- NEW: Wrapper for Encrypted Auth ---
# This is the model we were missing!

class EncryptedAuthRequest(BaseModel):
    """Client -> Server: A wrapper for the encrypted auth payload."""
    type: Annotated[str, Field(pattern=r"^encrypted_auth_request$")] = "encrypted_auth_request"
    payload: B64Str # b64(AES(Register or Login JSON))

class EncryptedAuthResponse(BaseModel):
    """Server -> Client: A wrapper for the encrypted auth response."""
    type: Annotated[str, Field(pattern=r"^encrypted_auth_response$")] = "encrypted_auth_response"
    payload: B64Str # b64(AES(AuthResponse JSON))

# --- Payloads *inside* encryption ---

class Register(BaseModel):
    """Client -> Server: Encrypted registration request."""
    type: Annotated[str, Field(pattern=r"^register$")] = "register"
    email: NonEmptyStr
    username: NonEmptyStr
    pwd: NonEmptyStr # Plaintext password, will be encrypted

class Login(BaseModel):
    """Client -> Server: Encrypted login request."""
    type: Annotated[str, Field(pattern=r"^login$")] = "login"
    email: NonEmptyStr
    pwd: NonEmptyStr # Plaintext password, will be encrypted

class AuthResponse(BaseModel):
    """Server -> Client: Response to register/login."""
    type: Annotated[str, Field(pattern=r"^auth_response$")] = "auth_response"
    success: bool
    message: str

# --- 1.2 Key Agreement (Post-Authentication) ---

class DHClient(BaseModel):
    """Client -> Server: Sends DH parameters and public value A."""
    type: Annotated[str, Field(pattern=r"^dh_client$")] = "dh_client"
    g: int
    p: int
    A: int # A = g^a mod p

class DHServer(BaseModel):
    """Server -> Client: Responds with public value B."""
    type: Annotated[str, Field(pattern=r"^dh_server$")] = "dh_server"
    B: int # B = g^b mod p

# --- 1.3 Data Plane (Encrypted Message Exchange) ---

class Msg(BaseModel):
    """Client <-> Server: An encrypted and signed chat message."""
    type: Annotated[str, Field(pattern=r"^msg$")] = "msg"
    seqno: Annotated[int, Field(ge=0)] # Sequence number (ge=0)
    ts: Annotated[int, Field(ge=0)]    # Timestamp (unix ms)
    ct: B64Str          # Ciphertext (AES-encrypted)
    sig: B64Str         # Signature (RSA-signed)

# --- 1.4 Non-Repudiation (Session Evidence) ---

class Receipt(BaseModel):
    """Client <-> Server: A signed receipt of the session transcript."""
    type: Annotated[str, Field(pattern=r"^receipt$")] = "receipt"
    peer: Annotated[str, Field(pattern=r"^(client|server)$")]
    first_seq: int
    last_seq: int
    transcript_sha256: str # Hex-encoded SHA-256 hash
    sig: B64Str            # RSA-signed hash
