# # """Client skeleton — plain TCP; no TLS. See assignment spec."""

# # def main():
# #     raise NotImplementedError("students: implement client workflow")

# # if __name__ == "__main__":
# #     main()



# """Client skeleton — plain TCP; no TLS. See assignment spec."""

# import json
# import os
# import socket
# import sys
# import threading
# from rich.console import Console
# from rich.panel import Panel
# from rich.prompt import Prompt, Confirm

# # --- Pydantic and Protocol ---
# from pydantic import ValidationError, BaseModel
# from app.common import protocol as proto
# from app.common.utils import b64e, b64d, sha256_hex, now_ms

# # --- Cryptography ---
# from app.crypto import aes, dh, pki, sign
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import rsa

# # --- Storage ---
# from app.storage import transcript

# # --- Constants ---
# SERVER_HOST = "127.0.0.1"  # Connect to loopback
# SERVER_PORT = 9999
# CLIENT_CERT_PATH = "certs/client.cert.pem"
# CLIENT_KEY_PATH = "certs/client.key.pem"
# EXPECTED_SERVER_CN = "server.local" # Per Req 2.1

# # --- Global Rich Console ---
# console = Console()

# class ClientState:
#     """Helper class to hold all state for the client connection."""
#     def __init__(self, sock: socket.socket, addr):
#         self.sock = sock
#         self.addr = addr
#         self.session_id = f"{addr[0]}:{addr[1]}_{now_ms()}"
        
#         console.log(f"Session {self.session_id}: Connecting to {addr}")
        
#         # --- PKI State ---
#         self.client_cert, self.client_key, self.client_cert_pem = pki.load_cert_and_key(
#             CLIENT_CERT_PATH, CLIENT_KEY_PATH
#         )
#         self.server_cert: x509.Certificate | None = None
#         self.server_pubkey: rsa.RSAPublicKey | None = None
        
#         # --- Auth State ---
#         self.auth_aes_key: bytes | None = None # For Register/Login
        
#         # --- Session State ---
#         self.session_aes_key: bytes | None = None # For main chat
#         self.seqno_rx = 0 # Received sequence number
#         self.seqno_tx = 0 # Transmitted sequence number
#         self.chat_active = True # To control the receiver thread
        
#         # --- Non-Repudiation ---
#         self.transcript = transcript.TranscriptLogger("client", self.session_id)
#         self.server_cert_fingerprint = "UNKNOWN"

# # --- Network Helpers ---

# def send_msg(state: ClientState, msg: BaseModel):
#     """Serializes, encodes, and sends a Pydantic message."""
#     try:
#         json_msg = msg.model_dump_json()
#         state.sock.sendall(json_msg.encode('utf-8') + b'\n')
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error sending message: {e}[/red]")

# def recv_msg(state: ClientState) -> dict | None:
#     """Receives, decodes, and deserializes a JSON message."""
#     try:
#         buffer = b""
#         while b'\n' not in buffer:
#             data = state.sock.recv(4096)
#             if not data:
#                 return None # Connection closed
#             buffer += data
        
#         line, _, _ = buffer.partition(b'\n')
#         return json.loads(line.decode('utf-8'))
    
#     except json.JSONDecodeError:
#         console.log(f"[red]Session {state.session_id}: Received invalid JSON[/red]")
#         return None
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error receiving message: {e}[/red]")
#         return None

# # --- Protocol Handlers ---

# def handle_mutual_auth(state: ClientState) -> bool:
#     """Phase 1.1: PKI_CONNECT and CERT_VERIFY"""
#     try:
#         # 1. Send Client Hello
#         console.log(f"Session {state.session_id}: Sending client 'hello'...")
#         client_hello = proto.Hello(
#             client_cert=b64e(state.client_cert_pem),
#             nonce=b64e(os.urandom(16))
#         )
#         send_msg(state, client_hello)
        
#         # 2. Receive Server Hello
#         server_hello_raw = recv_msg(state)
#         if not server_hello_raw: return False
        
#         server_hello = proto.ServerHello.model_validate(server_hello_raw)
        
#         # 3. Parse and validate server certificate
#         server_cert_pem = b64d(server_hello.server_cert)
#         state.server_cert = pki.parse_certificate(server_cert_pem)
#         if not state.server_cert:
#             return False
            
#         is_valid, reason = pki.validate_certificate(state.server_cert, EXPECTED_SERVER_CN)
#         if not is_valid:
#             console.log(f"[red]Session {state.session_id}: Server cert validation failed: {reason}[/red]")
#             return False
            
#         console.log(f"Session {state.session_id}: Server certificate OK. Subject: {state.server_cert.subject.rfc4514_string()}")
        
#         # Store for transcript (Req 1.4)
#         fingerprint = state.server_cert.fingerprint(hashes.SHA256())
#         state.server_cert_fingerprint = fingerprint.hex()
#         state.server_pubkey = sign.get_public_key_from_cert(state.server_cert)
        
#         return True
        
#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid auth message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Mutual auth failed: {e}[/red]")
#         return False

# def handle_auth_dh_exchange(state: ClientState) -> bool:
#     """Phase 1.2 / 2.2: DH_REGISTER_LOGIN_INIT (Temporary AES key)"""
#     try:
#         console.log(f"Session {state.session_id}: Performing temporary DH for auth...")
        
#         # 1. Client creates DH context
#         client_dh = dh.DHContext() # Uses built-in G and P
#         g, p = client_dh.get_public_params()
#         client_public_value_A = client_dh.get_public_value()
        
#         # 2. Send Client DH params
#         dh_client = proto.DHClient(g=g, p=p, A=client_public_value_A)
#         send_msg(state, dh_client)
        
#         # 3. Receive Server DH response
#         dh_server_raw = recv_msg(state)
#         if not dh_server_raw: return False
        
#         dh_server = proto.DHServer.model_validate(dh_server_raw)
        
#         # 4. Compute shared secret (Ks) and final AES key (K)
#         shared_secret_ks = client_dh.compute_shared_key(dh_server.B)
#         state.auth_aes_key = client_dh.derive_aes_key(shared_secret_ks)
        
#         console.log(f"Session {state.session_id}: Temporary AES auth key derived.")
#         return True

#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid DH message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Auth DH failed: {e}[/red]")
#         return False

# def handle_auth_flow(state: ClientState) -> bool:
#     """Phase 1.1 / 2.2: AUTH_CRED_ENCRYPT"""
#     try:
#         console.print(Panel("Welcome to SecureChat!", title="[green]Connect[/green]"))
#         choice = Prompt.ask("Do you want to", choices=["register", "login"], default="login")
        
#         email = Prompt.ask("Enter your email")
        
#         if choice == 'register':
#             username = Prompt.ask("Enter a username")
        
#         password = Prompt.ask("Enter your password", password=True)
        
#         # 1. Create Register or Login message
#         auth_req: BaseModel
#         if choice == 'register':
#             auth_req = proto.Register(email=email, username=username, pwd=password)
#         else:
#             auth_req = proto.Login(email=email, pwd=password)
            
#         # 2. Encrypt the auth message
#         plaintext = auth_req.model_dump_json().encode('utf-8')
#         ciphertext = aes.encrypt(state.auth_aes_key, plaintext)
        
#         # 3. Send encrypted payload
#         enc_request = proto.EncryptedAuthRequest(payload=b64e(ciphertext))
#         send_msg(state, enc_request)
        
#         # 4. Wait for encrypted response
#         console.log("Waiting for auth response...")
#         response_raw = recv_msg(state)
#         if not response_raw: return False
        
#         # 5. Decrypt response
#         enc_response = proto.EncryptedAuthResponse.model_validate(response_raw)
#         response_ciphertext = b64d(enc_response.payload)
#         response_plaintext = aes.decrypt(state.auth_aes_key, response_ciphertext)
        
#         if not response_plaintext or response_plaintext == b'\x00':
#             console.log("[red]Failed to decrypt auth response.[/red]")
#             return False
            
#         auth_response = proto.AuthResponse.model_validate_json(response_plaintext)
        
#         if auth_response.success:
#             console.log(f"[green]Auth OK: {auth_response.message}[/green]")
#             return True
#         else:
#             console.log(f"[red]Auth FAILED: {auth_response.message}[/red]")
#             return False
            
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Auth flow failed: {e}[/red]")
#         return False

# def handle_session_dh_exchange(state: ClientState) -> bool:
#     """Phase 1.2 / 2.3: DH_CHAT_INIT (Main Session AES key)"""
#     try:
#         console.log(f"Session {state.session_id}: Performing MAIN session DH...")
        
#         # 1. Client creates DH context
#         client_dh = dh.DHContext() # Uses built-in G and P
#         g, p = client_dh.get_public_params()
#         client_public_value_A = client_dh.get_public_value()
        
#         # 2. Send Client DH params
#         dh_client = proto.DHClient(g=g, p=p, A=client_public_value_A)
#         send_msg(state, dh_client)
        
#         # 3. Receive Server DH response
#         dh_server_raw = recv_msg(state)
#         if not dh_server_raw: return False
        
#         dh_server = proto.DHServer.model_validate(dh_server_raw)
        
#         # 4. Compute shared secret (Ks) and final AES key (K)
#         shared_secret_ks = client_dh.compute_shared_key(dh_server.B)
#         state.session_aes_key = client_dh.derive_aes_key(shared_secret_ks)
        
#         console.log(f"[green]Session {state.session_id}: MAIN session AES key derived. Chat is live.[/green]")
#         return True

#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid main DH message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Main DH failed: {e}[/red]")
#         return False

# def handle_chat_message(state: ClientState, msg: proto.Msg) -> str | None:
#     """
#     Phase 1.3 / 2.4: Handle an incoming 'msg'
#     1. Verify seqno (replay protection)
#     2. Verify signature (authenticity, integrity)
#     3. Decrypt (confidentiality)
#     4. Log to transcript (non-repudiation)
#     """
#     try:
#         # 1. Check seqno (replay protection)
#         if msg.seqno <= state.seqno_rx:
#             console.log(f"[red]Session {state.session_id}: REPLAY detected. Got {msg.seqno}, expected > {state.seqno_rx}[/red]")
#             return None
#         state.seqno_rx = msg.seqno
        
#         # 2. Verify signature
#         # h = SHA256(seqno || timestamp || ciphertext)
#         hash_data = str(msg.seqno).encode('utf-8') + str(msg.ts).encode('utf-8') + msg.ct.encode('utf-8')
        
#         is_valid_sig = sign.verify(
#             public_key=state.server_pubkey,
#             signature=b64d(msg.sig),
#             data=hash_data
#         )
        
#         if not is_valid_sig:
#             console.log(f"[red]Session {state.session_id}: SIG_FAIL detected. Message signature is invalid.[/red]")
#             return None
            
#         # 3. Decrypt
#         ciphertext = b64d(msg.ct)
#         plaintext_bytes = aes.decrypt(state.session_aes_key, ciphertext)
        
#         if not plaintext_bytes or plaintext_bytes == b'\x00':
#             console.log(f"[red]Session {state.session_id}: Decryption failed (wrong key or corrupt data)[/red]")
#             return None
            
#         plaintext = plaintext_bytes.decode('utf-8')
        
#         # 4. Log to transcript
#         state.transcript.log_message(
#             peer_name="server",
#             seqno=msg.seqno,
#             ts=msg.ts,
#             ct_b64=msg.ct,
#             sig_b64=msg.sig,
#             peer_cert_fingerprint=state.server_cert_fingerprint
#         )
        
#         return plaintext
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error handling chat message: {e}[/red]")
#         return None

# def send_secure_message(state: ClientState, plaintext: str):
#     """Helper to encrypt, sign, and send a chat message."""
#     try:
#         state.seqno_tx += 1
#         ts = now_ms()
        
#         # 1. Encrypt
#         ciphertext = aes.encrypt(state.session_aes_key, plaintext.encode('utf-8'))
#         ct_b64 = b64e(ciphertext)
        
#         # *** NEW PRINT STATEMENT AS REQUESTED ***
#         console.log(f"Sending encrypted message. ct_b64: {ct_b64[:30]}...")

#         # 2. Sign
#         # h = SHA256(seqno || timestamp || ciphertext)
#         hash_data = str(state.seqno_tx).encode('utf-8') + str(ts).encode('utf-8') + ct_b64.encode('utf-8')
#         signature = sign.sign(state.client_key, hash_data)
#         sig_b64 = b64e(signature)
        
#         # 3. Create 'msg'
#         msg = proto.Msg(
#             seqno=state.seqno_tx,
#             ts=ts,
#             ct=ct_b64,
#             sig=sig_b64
#         )
        
#         # 4. Log to transcript
#         state.transcript.log_message(
#             peer_name="client",
#             seqno=msg.seqno,
#             ts=msg.ts,
#             ct_b64=msg.ct,
#             sig_b64=msg.sig,
#             peer_cert_fingerprint="self"
#         )
        
#         # 5. Send
#         send_msg(state, msg)
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error sending secure message: {e}[/red]")

# def handle_session_receipt(state: ClientState):
#     """Phase 1.4 / 2.5: Generate and send the SessionReceipt"""
#     try:
#         console.log(f"Session {state.session_id}: Generating session receipt...")
#         transcript_hash = state.transcript.get_transcript_hash()
        
#         # Sign the transcript hash
#         sig_bytes = sign.sign(state.client_key, transcript_hash.encode('utf-8'))
        
#         receipt = proto.Receipt(
#             peer="client",
#             first_seq=1, # Simple placeholder
#             last_seq=state.seqno_tx,
#             transcript_sha256=transcript_hash,
#             sig=b64e(sig_bytes)
#         )
        
#         send_msg(state, receipt)
#         console.log(f"Session {state.session_id}: Session receipt sent.")
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error generating receipt: {e}[/red]")

# def receiver_thread(state: ClientState):
#     """
#     A dedicated thread to just receive and display messages from the server.
#     """
#     while state.chat_active:
#         try:
#             msg_raw = recv_msg(state)
#             if not msg_raw:
#                 console.log("[red]Server disconnected.[/red]")
#                 state.chat_active = False
#                 break
                
#             if msg_raw.get('type') == 'msg':
#                 msg = proto.Msg.model_validate(msg_raw)
#                 plaintext = handle_chat_message(state, msg)
                
#                 if plaintext:
#                     console.print(Panel(f"[yellow]Server:[/yellow] {plaintext}", title="Message Received", style="dim"))
                    
#                     if plaintext.strip() == "Goodbye!":
#                         console.log("Server initiated disconnect.")
#                         state.chat_active = False
            
#             elif msg_raw.get('type') == 'receipt':
#                 console.log("Server sent its receipt. Closing session.")
#                 state.chat_active = False

#         except Exception as e:
#             if state.chat_active:
#                 console.log(f"[red]Receiver thread error: {e}[/red]")
#             break
#     console.log("Receiver thread stopped.")

# def handle_chat_loop(state: ClientState):
#     """Phase 1.3 / 2.4: CHAT-LOOP"""
    
#     # Start the receiver thread
#     r_thread = threading.Thread(target=receiver_thread, args=(state,), daemon=True)
#     r_thread.start()
    
#     console.print(Panel("You are now in a secure chat. Type '/quit' to exit.", title="[green]Chat Active[/green]"))
    
#     try:
#         while state.chat_active:
#             plaintext = Prompt.ask(">") # Blocks here for user input
            
#             if not state.chat_active:
#                 break # Receiver thread might have stopped us
                
#             send_secure_message(state, plaintext)
            
#             if plaintext.strip() == "/quit":
#                 console.log("Disconnecting...")
#                 state.chat_active = False
#                 break
                
#     except KeyboardInterrupt:
#         console.log("\n[yellow]Caught Ctrl+C, sending /quit...[/yellow]")
#         if state.chat_active:
#             send_secure_message(state, "/quit")
#         state.chat_active = False
        
#     # Wait for receiver thread to finish
#     r_thread.join(timeout=2.0)


# # --- Main Connection Handler ---

# def run_client():
#     """
#     Handles a single, complete client connection from start to finish.
#     """
#     try:
#         # Load Root CA cert into memory
#         pki.load_ca_cert()
#     except Exception:
#         sys.exit(1) # Error printed by loader

#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.connect((SERVER_HOST, SERVER_PORT))
#         addr = (SERVER_HOST, SERVER_PORT)
#     except Exception as e:
#         console.log(f"[red]Error: Could not connect to server at {SERVER_HOST}:{SERVER_PORT}: {e}[/red]")
#         sys.exit(1)

#     state = ClientState(sock, addr)
#     try:
#         with sock:
#             # Phase 1: Mutual Auth
#             if not handle_mutual_auth(state):
#                 raise Exception("Mutual authentication failed")
            
#             # Phase 2: Temp DH for Auth
#             if not handle_auth_dh_exchange(state):
#                 raise Exception("Auth DH exchange failed")
                
#             # Phase 3: Register / Login
#             if not handle_auth_flow(state):
#                 # Auth failed, server will drop us
#                 raise Exception("User authentication failed")
                
#             # Phase 4: Main Session DH
#             if not handle_session_dh_exchange(state):
#                 raise Exception("Main session DH exchange failed")
                
#             # Phase 5: Chat Loop
#             handle_chat_loop(state)
            
#             # Phase 6: Non-Repudiation (Receipt)
#             handle_session_receipt(state)
            
#     except Exception as e:
#         console.log(f"[red]Session error: {e}[/red]")
#     finally:
#         state.chat_active = False
#         console.log("Session closed.")

# def main():
#     """Client skeleton — plain TCP; no TLS. See assignment spec."""
#     run_client()

# if __name__ == "__main__":
#     main()


"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import json
import os
import socket
import sys
import threading
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from pathlib import Path # Required for file saving

# --- Pydantic and Protocol ---
from pydantic import ValidationError, BaseModel
from app.common import protocol as proto
from app.common.utils import b64e, b64d, sha256_hex, now_ms

# --- Cryptography ---
from app.crypto import aes, dh, pki, sign
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Storage ---
from app.storage import transcript

# --- Constants ---
SERVER_HOST = "127.0.0.1"  # Connect to loopback
SERVER_PORT = 9999
CLIENT_CERT_PATH = "certs/client.cert.pem"
CLIENT_KEY_PATH = "certs/client.key.pem"
EXPECTED_SERVER_CN = "server.local" # Per Req 2.1

# --- Global Rich Console ---
console = Console()

class ClientState:
    """Helper class to hold all state for the client connection."""
    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.session_id = f"{addr[0]}:{addr[1]}_{now_ms()}"
        
        console.log(f"Session {self.session_id}: Connecting to {addr}")
        
        # --- PKI State ---
        self.client_cert, self.client_key, self.client_cert_pem = pki.load_cert_and_key(
            CLIENT_CERT_PATH, CLIENT_KEY_PATH
        )
        self.server_cert: x509.Certificate | None = None
        self.server_pubkey: rsa.RSAPublicKey | None = None
        
        # --- Auth State ---
        self.auth_aes_key: bytes | None = None # For Register/Login
        
        # --- Session State ---
        self.session_aes_key: bytes | None = None # For main chat
        self.seqno_rx = 0 # Received sequence number
        self.seqno_tx = 0 # Transmitted sequence number
        self.chat_active = True # To control the receiver thread
        
        # --- Non-Repudiation ---
        self.transcript = transcript.TranscriptLogger("client", self.session_id)
        self.server_cert_fingerprint = "UNKNOWN"

# --- Network Helpers ---

def send_msg(state: ClientState, msg: BaseModel):
    """Serializes, encodes, and sends a Pydantic message."""
    try:
        json_msg = msg.model_dump_json()
        state.sock.sendall(json_msg.encode('utf-8') + b'\n')
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error sending message: {e}[/red]")

def recv_msg(state: ClientState) -> dict | None:
    """Receives, decodes, and deserializes a JSON message."""
    try:
        buffer = b""
        while b'\n' not in buffer:
            data = state.sock.recv(4096)
            if not data:
                return None # Connection closed
            buffer += data
        
        line, _, _ = buffer.partition(b'\n')
        return json.loads(line.decode('utf-8'))
    
    except json.JSONDecodeError:
        console.log(f"[red]Session {state.session_id}: Received invalid JSON[/red]")
        return None
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error receiving message: {e}[/red]")
        return None

# --- Protocol Handlers ---

def handle_mutual_auth(state: ClientState) -> bool:
    """Phase 1.1: PKI_CONNECT and CERT_VERIFY"""
    try:
        # 1. Send Client Hello
        console.log(f"Session {state.session_id}: Sending client 'hello'...")
        client_hello = proto.Hello(
            client_cert=b64e(state.client_cert_pem),
            nonce=b64e(os.urandom(16))
        )
        send_msg(state, client_hello)
        
        # 2. Receive Server Hello
        server_hello_raw = recv_msg(state)
        if not server_hello_raw: return False
        
        server_hello = proto.ServerHello.model_validate(server_hello_raw)
        
        # 3. Parse and validate server certificate
        server_cert_pem = b64d(server_hello.server_cert)
        state.server_cert = pki.parse_certificate(server_cert_pem)
        if not state.server_cert:
            return False
            
        is_valid, reason = pki.validate_certificate(state.server_cert, EXPECTED_SERVER_CN)
        if not is_valid:
            console.log(f"[red]Session {state.session_id}: Server cert validation failed: {reason}[/red]")
            return False
            
        console.log(f"Session {state.session_id}: Server certificate OK. Subject: {state.server_cert.subject.rfc4514_string()}")
        
        # Store for transcript (Req 1.4)
        fingerprint = state.server_cert.fingerprint(hashes.SHA256())
        state.server_cert_fingerprint = fingerprint.hex()
        state.server_pubkey = sign.get_public_key_from_cert(state.server_cert)
        
        return True
        
    except ValidationError as e:
        console.log(f"[red]Session {state.session_id}: Invalid auth message: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Mutual auth failed: {e}[/red]")
        return False

def handle_auth_dh_exchange(state: ClientState) -> bool:
    """Phase 1.2 / 2.2: DH_REGISTER_LOGIN_INIT (Temporary AES key)"""
    try:
        console.log(f"Session {state.session_id}: Performing temporary DH for auth...")
        
        # 1. Client creates DH context
        client_dh = dh.DHContext() 
        g, p = client_dh.get_public_params()
        client_public_value_A = client_dh.get_public_value()
        
        # 2. Send Client DH params
        dh_client = proto.DHClient(g=g, p=p, A=client_public_value_A)
        send_msg(state, dh_client)
        
        # 3. Receive Server DH response
        dh_server_raw = recv_msg(state)
        if not dh_server_raw: return False
        
        dh_server = proto.DHServer.model_validate(dh_server_raw)
        
        # 4. Compute shared secret (Ks) and final AES key (K)
        shared_secret_ks = client_dh.compute_shared_key(dh_server.B)
        state.auth_aes_key = client_dh.derive_aes_key(shared_secret_ks)
        
        console.log(f"Session {state.session_id}: Temporary AES auth key derived.")
        return True

    except ValidationError as e:
        console.log(f"[red]Session {state.session_id}: Invalid DH message: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Auth DH failed: {e}[/red]")
        return False

def handle_auth_flow(state: ClientState) -> bool:
    """Phase 1.1 / 2.2: AUTH_CRED_ENCRYPT"""
    try:
        console.print(Panel("Welcome to SecureChat!", title="[green]Connect[/green]"))
        choice = Prompt.ask("Do you want to", choices=["register", "login"], default="login")
        
        email = Prompt.ask("Enter your email")
        
        if choice == 'register':
            username = Prompt.ask("Enter a username")
        
        password = Prompt.ask("Enter your password", password=True)
        
        # 1. Create Register or Login message
        auth_req: BaseModel
        if choice == 'register':
            auth_req = proto.Register(email=email, username=username, pwd=password)
        else:
            auth_req = proto.Login(email=email, pwd=password)
            
        # 2. Encrypt the auth message
        plaintext = auth_req.model_dump_json().encode('utf-8')
        ciphertext = aes.encrypt(state.auth_aes_key, plaintext)
        
        # 3. Send encrypted payload
        enc_request = proto.EncryptedAuthRequest(payload=b64e(ciphertext))
        send_msg(state, enc_request)
        
        # 4. Wait for encrypted response
        console.log("Waiting for auth response...")
        response_raw = recv_msg(state)
        if not response_raw: return False
        
        # 5. Decrypt response
        enc_response = proto.EncryptedAuthResponse.model_validate(response_raw)
        response_ciphertext = b64d(enc_response.payload)
        response_plaintext = aes.decrypt(state.auth_aes_key, response_ciphertext)
        
        if not response_plaintext or response_plaintext == b'\x00':
            console.log("[red]Failed to decrypt auth response.[/red]")
            return False
            
        auth_response = proto.AuthResponse.model_validate_json(response_plaintext)
        
        if auth_response.success:
            console.log(f"[green]Auth OK: {auth_response.message}[/green]")
            return True
        else:
            console.log(f"[red]Auth FAILED: {auth_response.message}[/red]")
            return False
            
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Auth flow failed: {e}[/red]")
        return False

def handle_session_dh_exchange(state: ClientState) -> bool:
    """Phase 1.2 / 2.3: DH_CHAT_INIT (Main Session AES key)"""
    try:
        console.log(f"Session {state.session_id}: Performing MAIN session DH...")
        
        # 1. Client creates DH context
        client_dh = dh.DHContext() 
        g, p = client_dh.get_public_params()
        client_public_value_A = client_dh.get_public_value()
        
        # 2. Send Client DH params
        dh_client = proto.DHClient(g=g, p=p, A=client_public_value_A)
        send_msg(state, dh_client)
        
        # 3. Receive Server DH response
        dh_server_raw = recv_msg(state)
        if not dh_server_raw: return False
        
        dh_server = proto.DHServer.model_validate(dh_server_raw)
        
        # 4. Compute shared secret (Ks) and final AES key (K)
        shared_secret_ks = client_dh.compute_shared_key(dh_server.B)
        state.session_aes_key = client_dh.derive_aes_key(shared_secret_ks)
        
        console.log(f"[green]Session {state.session_id}: MAIN session AES key derived. Chat is live.[/green]")
        return True

    except ValidationError as e:
        console.log(f"[red]Session {state.session_id}: Invalid main DH message: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Main DH failed: {e}[/red]")
        return False

def handle_chat_message(state: ClientState, msg: proto.Msg) -> str | None:
    """
    Phase 1.3 / 2.4: Handle an incoming 'msg'
    1. Verify seqno (replay protection)
    2. Verify signature (authenticity, integrity)
    3. Decrypt (confidentiality)
    4. Log to transcript (non-repudiation)
    """
    try:
        # 1. Check seqno (replay protection)
        if msg.seqno <= state.seqno_rx:
            console.log(f"[red]Session {state.session_id}: REPLAY detected. Got {msg.seqno}, expected > {state.seqno_rx}[/red]")
            return None
        state.seqno_rx = msg.seqno
        
        # 2. Verify signature
        hash_data = str(msg.seqno).encode('utf-8') + str(msg.ts).encode('utf-8') + msg.ct.encode('utf-8')
        
        is_valid_sig = sign.verify(
            public_key=state.server_pubkey,
            signature=b64d(msg.sig),
            data=hash_data
        )
        
        if not is_valid_sig:
            console.log(f"[red]Session {state.session_id}: SIG_FAIL detected. Message signature is invalid.[/red]")
            return None
            
        # 3. Decrypt
        ciphertext = b64d(msg.ct)
        plaintext_bytes = aes.decrypt(state.session_aes_key, ciphertext)
        
        if not plaintext_bytes or plaintext_bytes == b'\x00':
            console.log(f"[red]Session {state.session_id}: Decryption failed (wrong key or corrupt data)[/red]")
            return None
            
        plaintext = plaintext_bytes.decode('utf-8')
        
        # 4. Log to transcript
        state.transcript.log_message(
            peer_name="server",
            seqno=msg.seqno,
            ts=msg.ts,
            ct_b64=msg.ct,
            sig_b64=msg.sig,
            peer_cert_fingerprint=state.server_cert_fingerprint
        )
        
        return plaintext
        
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error handling chat message: {e}[/red]")
        return None

def send_secure_message(state: ClientState, plaintext: str):
    """Helper to encrypt, sign, and send a chat message."""
    try:
        state.seqno_tx += 1
        ts = now_ms()
        
        # 1. Encrypt
        ciphertext = aes.encrypt(state.session_aes_key, plaintext.encode('utf-8'))
        ct_b64 = b64e(ciphertext)
        
        # LOGGING FEATURE: Print encrypted data (ct)
        console.log(Panel(
            f"[yellow]Encrypted Ciphertext (ct):[/yellow] {ct_b64}",
            title=f"Sending Message {state.seqno_tx} Encrypted Payload",
            subtitle=f"[yellow]Plaintext:[/yellow] {plaintext}"
        ))

        # 2. Sign
        hash_data = str(state.seqno_tx).encode('utf-8') + str(ts).encode('utf-8') + ct_b64.encode('utf-8')
        signature = sign.sign(state.client_key, hash_data)
        sig_b64 = b64e(signature)
        
        # 3. Create 'msg'
        msg = proto.Msg(
            seqno=state.seqno_tx,
            ts=ts,
            ct=ct_b64,
            sig=sig_b64
        )
        
        # 4. Log to transcript
        state.transcript.log_message(
            peer_name="client",
            seqno=msg.seqno,
            ts=msg.ts,
            ct_b64=msg.ct,
            sig_b64=msg.sig,
            peer_cert_fingerprint="self"
        )
        
        # 5. Send
        send_msg(state, msg)
        
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error sending secure message: {e}[/red]")

def handle_session_receipt(state: ClientState):
    """Phase 1.4 / 2.5: Generate and save the SessionReceipt"""
    
    # --- FIX: SAVING RECEIPT TO FILE LOCALLY ---
    receipt_filepath = Path(f"transcripts/client_{state.session_id}_receipt.json")
    
    try:
        console.log(f"Session {state.session_id}: Generating session receipt...")
        transcript_hash = state.transcript.get_transcript_hash()
        
        # Sign the transcript hash
        sig_bytes = sign.sign(state.client_key, transcript_hash.encode('utf-8'))
        
        receipt = proto.Receipt(
            peer="client",
            first_seq=1, # Simple placeholder
            last_seq=state.seqno_tx,
            transcript_sha256=transcript_hash,
            sig=b64e(sig_bytes)
        )
        
        # Save the JSON file locally for offline verification
        with open(receipt_filepath, 'w') as f:
            json.dump(receipt.model_dump(), f, indent=4)
        console.log(f"[green]Session Receipt SAVED:[/green] {receipt_filepath}")
        
        # Send receipt to server (for server's log/record)
        send_msg(state, receipt)
        
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error generating receipt: {e}[/red]")

def receiver_thread(state: ClientState):
    """
    A dedicated thread to just receive and display messages from the server.
    """
    while state.chat_active:
        try:
            msg_raw = recv_msg(state)
            if not msg_raw:
                console.log("[red]Server disconnected.[/red]")
                state.chat_active = False
                break
                
            if msg_raw.get('type') == 'msg':
                msg = proto.Msg.model_validate(msg_raw)
                plaintext = handle_chat_message(state, msg)
                
                if plaintext:
                    console.print(Panel(f"[yellow]Server:[/yellow] {plaintext}", title="Message Received", style="dim"))
                    
                    if plaintext.strip() == "Goodbye!":
                        console.log("Server initiated disconnect.")
                        state.chat_active = False
            
            elif msg_raw.get('type') == 'receipt':
                console.log("Server sent its receipt. Closing session.")
                state.chat_active = False

        except Exception as e:
            if state.chat_active:
                console.log(f"[red]Receiver thread error: {e}[/red]")
            break
    console.log("Receiver thread stopped.")

def handle_chat_loop(state: ClientState):
    """Phase 1.3 / 2.4: CHAT-LOOP"""
    
    # Start the receiver thread
    r_thread = threading.Thread(target=receiver_thread, args=(state,), daemon=True)
    r_thread.start()
    
    console.print(Panel("You are now in a secure chat. Type '/quit' to exit.", title="[green]Chat Active[/green]"))
    
    try:
        while state.chat_active:
            plaintext = Prompt.ask(">") # Blocks here for user input
            
            if not state.chat_active:
                break # Receiver thread might have stopped us
                
            send_secure_message(state, plaintext)
            
            if plaintext.strip() == "/quit":
                console.log("Disconnecting...")
                state.chat_active = False
                break
                
    except KeyboardInterrupt:
        console.log("\n[yellow]Caught Ctrl+C, sending /quit...[/yellow]")
        if state.chat_active:
            send_secure_message(state, "/quit")
        state.chat_active = False
        
    # Wait for receiver thread to finish
    r_thread.join(timeout=2.0)


# --- Main Connection Handler ---

def run_client():
    """
    Handles a single, complete client connection from start to finish.
    """
    try:
        # Load Root CA cert into memory
        pki.load_ca_cert()
    except Exception:
        sys.exit(1) # Error printed by loader

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        addr = (SERVER_HOST, SERVER_PORT)
    except Exception as e:
        console.log(f"[red]Error: Could not connect to server at {SERVER_HOST}:{SERVER_PORT}: {e}[/red]")
        sys.exit(1)

    state = ClientState(sock, addr)
    try:
        with sock:
            # Phase 1: Mutual Auth
            if not handle_mutual_auth(state):
                raise Exception("Mutual authentication failed")
            
            # Phase 2: Temp DH for Auth
            if not handle_auth_dh_exchange(state):
                raise Exception("Auth DH exchange failed")
                
            # Phase 3: Register / Login
            if not handle_auth_flow(state):
                # Auth failed, server will drop us
                raise Exception("User authentication failed")
                
            # Phase 4: Main Session DH
            if not handle_session_dh_exchange(state):
                raise Exception("Main session DH exchange failed")
                
            # Phase 5: Chat Loop
            handle_chat_loop(state)
            
            # Phase 6: Non-Repudiation (Receipt)
            handle_session_receipt(state)
            
    except Exception as e:
        console.log(f"[red]Session error: {e}[/red]")
    finally:
        state.chat_active = False
        console.log("Session closed.")

def main():
    """Client skeleton — plain TCP; no TLS. See assignment spec."""
    run_client()
    

if __name__ == "__main__":
    main()