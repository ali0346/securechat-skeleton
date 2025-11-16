# # """Server skeleton — plain TCP; no TLS. See assignment spec."""

# # def main():
# #     raise NotImplementedError("students: implement server workflow")

# # if __name__ == "__main__":
# #     main()


# """Server skeleton — plain TCP; no TLS. See assignment spec."""

# import json
# import os
# import socket
# import sys
# from rich.console import Console
# from rich.panel import Panel

# # --- Pydantic and Protocol ---
# # We use pydantic for parsing and validating all incoming JSON
# from pydantic import ValidationError, BaseModel
# from app.common import protocol as proto
# from app.common.utils import b64e, b64d, sha256_hex, now_ms

# # --- Cryptography ---
# from app.crypto import aes, dh, pki, sign
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import rsa

# # --- Storage ---
# from app.storage import db, transcript
# from pymysql.connections import Connection as DbConnection

# # --- Constants ---
# SERVER_HOST = "0.0.0.0"  # Listen on all interfaces
# SERVER_PORT = 9999
# SERVER_CERT_PATH = "certs/server.cert.pem"
# SERVER_KEY_PATH = "certs/server.key.pem"
# EXPECTED_CLIENT_CN = "client.local" # Per Req 2.1

# # --- Global Rich Console ---
# console = Console()

# class ServerState:
#     """Helper class to hold all state for a single client connection."""
#     def __init__(self, conn: DbConnection, sock: socket.socket, addr):
#         self.db_conn = conn
#         self.sock = sock
#         self.addr = addr
#         self.session_id = f"{addr[0]}:{addr[1]}_{now_ms()}"
        
#         console.log(f"Session {self.session_id}: New connection from {addr}")
        
#         # --- PKI State ---
#         self.server_cert, self.server_key, self.server_cert_pem = pki.load_cert_and_key(
#             SERVER_CERT_PATH, SERVER_KEY_PATH
#         )
#         self.client_cert: x509.Certificate | None = None
#         self.client_pubkey: rsa.RSAPublicKey | None = None
        
#         # --- Auth State ---
#         self.auth_aes_key: bytes | None = None # For Register/Login
#         self.authed_user_email: str | None = None
        
#         # --- Session State ---
#         self.session_aes_key: bytes | None = None # For main chat
#         self.seqno_rx = 0 # Received sequence number
#         self.seqno_tx = 0 # Transmitted sequence number
        
#         # --- Non-Repudiation ---
#         self.transcript = transcript.TranscriptLogger("server", self.session_id)
#         self.client_cert_fingerprint = "UNKNOWN"

# # --- Network Helpers ---

# def send_msg(state: ServerState, msg: BaseModel):
#     """Serializes, encodes, and sends a Pydantic message."""
#     try:
#         json_msg = msg.model_dump_json()
#         state.sock.sendall(json_msg.encode('utf-8') + b'\n')
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error sending message: {e}[/red]")

# def recv_msg(state: ServerState) -> dict | None:
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

# def handle_mutual_auth(state: ServerState) -> bool:
#     """Phase 1.1: PKI_CONNECT and CERT_VERIFY"""
#     try:
#         # 1. Receive Client Hello
#         console.log(f"Session {state.session_id}: Waiting for client 'hello'...")
#         client_hello_raw = recv_msg(state)
#         if not client_hello_raw: return False
        
#         client_hello = proto.Hello.model_validate(client_hello_raw)
        
#         # 2. Parse and validate client certificate
#         client_cert_pem = b64d(client_hello.client_cert)
#         state.client_cert = pki.parse_certificate(client_cert_pem)
#         if not state.client_cert:
#             return False
            
#         is_valid, reason = pki.validate_certificate(state.client_cert, EXPECTED_CLIENT_CN)
#         if not is_valid:
#             console.log(f"[red]Session {state.session_id}: Client cert validation failed: {reason}[/red]")
#             return False
            
#         console.log(f"Session {state.session_id}: Client certificate OK. Subject: {state.client_cert.subject.rfc4514_string()}")
        
#         # Store for transcript (Req 1.4)
#         fingerprint = state.client_cert.fingerprint(hashes.SHA256())
#         state.client_cert_fingerprint = fingerprint.hex()
#         state.client_pubkey = sign.get_public_key_from_cert(state.client_cert)
        
#         # 3. Send Server Hello
#         server_hello = proto.ServerHello(
#             server_cert=b64e(state.server_cert_pem),
#             nonce=b64e(os.urandom(16))
#         )
#         send_msg(state, server_hello)
#         return True
        
#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid auth message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Mutual auth failed: {e}[/red]")
#         return False

# def handle_auth_dh_exchange(state: ServerState) -> bool:
#     """Phase 1.2 / 2.2: DH_REGISTER_LOGIN_INIT (Temporary AES key)"""
#     try:
#         console.log(f"Session {state.session_id}: Performing temporary DH for auth...")
        
#         # 1. Receive Client DH params
#         dh_client_raw = recv_msg(state)
#         if not dh_client_raw: return False
        
#         dh_client = proto.DHClient.model_validate(dh_client_raw)
        
#         # 2. Server computes its keys
#         server_dh = dh.DHContext(g=dh_client.g, p=dh_client.p)
#         server_public_value_B = server_dh.get_public_value()
        
#         # 3. Compute shared secret (Ks) and final AES key (K)
#         shared_secret_ks = server_dh.compute_shared_key(dh_client.A)
#         state.auth_aes_key = server_dh.derive_aes_key(shared_secret_ks)
        
#         # 4. Send Server DH response
#         dh_server = proto.DHServer(B=server_public_value_B)
#         send_msg(state, dh_server)
        
#         console.log(f"Session {state.session_id}: Temporary AES auth key derived.")
#         return True

#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid DH message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Auth DH failed: {e}[/red]")
#         return False

# def handle_registration(state: ServerState, register: proto.Register):
#     """Handles a registration request."""
#     # 1. Generate salt
#     salt = os.urandom(16) # 16 bytes, per Req 2.2
    
#     # 2. Compute pwd_hash = SHA256(salt || password)
#     pwd_hash = sha256_hex(salt + register.pwd.encode('utf-8'))
    
#     # 3. Create user
#     success = db.create_user(
#         state.db_conn,
#         register.email,
#         register.username,
#         salt,
#         pwd_hash
#     )
    
#     if success:
#         console.log(f"Session {state.session_id}: New user registered: {register.email}")
#         return proto.AuthResponse(success=True, message="Registration successful.")
#     else:
#         console.log(f"Session {state.session_id}: Registration failed (user may exist): {register.email}")
#         return proto.AuthResponse(success=False, message="Registration failed: Email or username already exists.")
        
# def handle_login(state: ServerState, login: proto.Login):
#     """Handles a login request."""
#     # 1. Fetch user from DB
#     user = db.get_user_by_email(state.db_conn, login.email)
    
#     if not user:
#         console.log(f"Session {state.session_id}: Login failed (user not found): {login.email}")
#         return proto.AuthResponse(success=False, message="Login failed: Invalid email or password.")
        
#     # 2. Re-compute hash: test_hash = SHA256(salt || provided_password)
#     salt = user['salt']
#     stored_hash = user['pwd_hash']
#     test_hash = sha256_hex(salt + login.pwd.encode('utf-8'))
    
#     # 3. Securely compare hashes
#     if test_hash == stored_hash:
#         console.log(f"Session {state.session_id}: User login successful: {login.email}")
#         state.authed_user_email = login.email # Mark as authenticated
#         return proto.AuthResponse(success=True, message="Login successful.")
#     else:
#         console.log(f"Session {state.session_id}: Login failed (wrong password): {login.email}")
#         return proto.AuthResponse(success=False, message="Login failed: Invalid email or password.")


# def handle_auth_flow(state: ServerState) -> bool:
#     """Phase 1.1 / 2.2: AUTH_CRED_DECRYPT_VERIFY"""
#     try:
#         console.log(f"Session {state.session_id}: Waiting for encrypted auth request...")
        
#         # 1. Receive encrypted message
#         auth_req_raw = recv_msg(state)
#         if not auth_req_raw: return False
        
#         # *** THIS IS THE FIX ***
#         # We now parse using our new, valid model
#         enc_request = proto.EncryptedAuthRequest.model_validate(auth_req_raw)
        
#         # 2. Decrypt the payload
#         ciphertext = b64d(enc_request.payload)
#         plaintext = aes.decrypt(state.auth_aes_key, ciphertext)
        
#         if not plaintext or plaintext == b'\x00':
#             console.log(f"[red]Session {state.session_id}: Failed to decrypt auth message (wrong key?)[/red]")
#             return False
            
#         auth_data = json.loads(plaintext.decode('utf-8'))
        
#         # 3. Handle Register or Login
#         response_msg: proto.AuthResponse
#         if auth_data['type'] == 'register':
#             register_req = proto.Register.model_validate(auth_data)
#             response_msg = handle_registration(state, register_req)
#         elif auth_data['type'] == 'login':
#             login_req = proto.Login.model_validate(auth_data)
#             response_msg = handle_login(state, login_req)
#         else:
#             raise Exception(f"Unknown auth type: {auth_data.get('type')}")
        
#         # 4. Encrypt and send response
#         response_plaintext = response_msg.model_dump_json().encode('utf-8')
#         response_ciphertext = aes.encrypt(state.auth_aes_key, response_plaintext)
        
#         # *** THIS IS THE FIX ***
#         # We now use our new, valid model
#         enc_response = proto.EncryptedAuthResponse(payload=b64e(response_ciphertext))
#         send_msg(state, enc_response)
        
#         return response_msg.success

#     except (ValidationError, json.JSONDecodeError) as e:
#         console.log(f"[red]Session {state.session_id}: Invalid auth payload: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Auth flow failed: {e}[/red]")
#         return False

# def handle_session_dh_exchange(state: ServerState) -> bool:
#     """Phase 1.2 / 2.3: DH_CHAT_INIT (Main Session AES key)"""
#     try:
#         console.log(f"Session {state.session_id}: Performing MAIN session DH...")
        
#         # 1. Receive Client DH params
#         dh_client_raw = recv_msg(state)
#         if not dh_client_raw: return False
        
#         dh_client = proto.DHClient.model_validate(dh_client_raw)
        
#         # 2. Server computes its keys
#         server_dh = dh.DHContext(g=dh_client.g, p=dh_client.p)
#         server_public_value_B = server_dh.get_public_value()
        
#         # 3. Compute shared secret (Ks) and final AES key (K)
#         shared_secret_ks = server_dh.compute_shared_key(dh_client.A)
#         state.session_aes_key = server_dh.derive_aes_key(shared_secret_ks)
        
#         # 4. Send Server DH response
#         dh_server = proto.DHServer(B=server_public_value_B)
#         send_msg(state, dh_server)
        
#         console.log(f"[green]Session {state.session_id}: MAIN session AES key derived. Chat is live.[/green]")
#         return True

#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid main DH message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Main DH failed: {e}[/red]")
#         return False

# def handle_chat_message(state: ServerState, msg: proto.Msg) -> str | None:
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
#         # Note: Pydantic gives us int/str, we must convert to bytes
#         hash_data = str(msg.seqno).encode('utf-8') + str(msg.ts).encode('utf-8') + msg.ct.encode('utf-8')
        
#         is_valid_sig = sign.verify(
#             public_key=state.client_pubkey,
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
#             peer_name="client",
#             seqno=msg.seqno,
#             ts=msg.ts,
#             ct_b64=msg.ct,
#             sig_b64=msg.sig,
#             peer_cert_fingerprint=state.client_cert_fingerprint
#         )
        
#         return plaintext
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error handling chat message: {e}[/red]")
#         return None


# def handle_chat_loop(state: ServerState):
#     """Phase 1.3 / 2.4: CHAT-LOOP"""
#     console.log(f"Session {state.session_id}: Entering chat loop with {state.authed_user_email}...")
    
#     # Send a welcome message
#     server_welcome = f"Welcome, {state.authed_user_email}! You are connected to the server. Type /quit to exit."
    
#     # We must send messages using the same secure format
#     send_secure_message(state, server_welcome)
    
#     while True:
#         msg_raw = recv_msg(state)
#         if not msg_raw:
#             console.log(f"Session {state.session_id}: Client disconnected.")
#             break
            
#         try:
#             # Check for message type
#             if msg_raw.get('type') == 'msg':
#                 msg = proto.Msg.model_validate(msg_raw)
#                 plaintext = handle_chat_message(state, msg)
                
#                 if plaintext:
#                     console.print(Panel(f"[cyan]{state.authed_user_email}:[/cyan] {plaintext}", title="Message Received"))
                    
#                     # Check for quit command
#                     if plaintext.strip() == "/quit":
#                         console.log(f"Session {state.session_id}: Client requested /quit.")
#                         send_secure_message(state, "Goodbye!")
#                         break
                    
#                     # Echo back for this simple server
#                     # server_reply = f"Server received: '{plaintext}'"
#                     # send_secure_message(state, server_reply)
            
#             elif msg_raw.get('type') == 'receipt':
#                 # Handle receipt if needed
#                 console.log(f"Session {state.session_id}: Received client receipt.")
#                 break # End session on receipt
                
#             else:
#                 console.log(f"[yellow]Session {state.session_id}: Received unknown message type: {msg_raw.get('type')}[/yellow]")
                
#         except ValidationError as e:
#             console.log(f"[red]Session {state.session_id}: Invalid chat message: {e}[/red]")
#         except Exception as e:
#             console.log(f"[red]Session {state.session_id}: Chat loop error: {e}[/red]")
#             break

# def send_secure_message(state: ServerState, plaintext: str):
#     """Helper to encrypt, sign, and send a chat message."""
#     try:
#         state.seqno_tx += 1
#         ts = now_ms()
        
#         # 1. Encrypt
#         ciphertext = aes.encrypt(state.session_aes_key, plaintext.encode('utf-8'))
#         ct_b64 = b64e(ciphertext)
        
#         # 2. Sign
#         # h = SHA256(seqno || timestamp || ciphertext)
#         hash_data = str(state.seqno_tx).encode('utf-8') + str(ts).encode('utf-8') + ct_b64.encode('utf-8')
#         signature = sign.sign(state.server_key, hash_data)
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
#             peer_name="server",
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


# def handle_session_receipt(state: ServerState):
#     """Phase 1.4 / 2.5: Generate and send the SessionReceipt"""
#     try:
#         console.log(f"Session {state.session_id}: Generating session receipt...")
#         transcript_hash = state.transcript.get_transcript_hash()
        
#         # Sign the transcript hash
#         sig_bytes = sign.sign(state.server_key, transcript_hash.encode('utf-8'))
        
#         receipt = proto.Receipt(
#             peer="server",
#             first_seq=1, # Simple placeholder
#             last_seq=state.seqno_tx,
#             transcript_sha256=transcript_hash,
#             sig=b64e(sig_bytes)
#         )
        
#         send_msg(state, receipt)
#         console.log(f"Session {state.session_id}: Session receipt sent.")
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error generating receipt: {e}[/red]")

# # --- Main Connection Handler ---

# def handle_client_connection(sock: socket.socket, addr, db_conn: DbConnection):
#     """
#     Handles a single, complete client connection from start to finish.
#     """
#     state = ServerState(db_conn, sock, addr)
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
#                 raise Exception("User authentication failed")
                
#             # Phase 4: Main Session DH
#             if not handle_session_dh_exchange(state):
#                 raise Exception("Main session DH exchange failed")
                
#             # Phase 5: Chat Loop
#             handle_chat_loop(state)
            
#             # Phase 6: Non-Repudiation (Receipt)
#             handle_session_receipt(state)

#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Connection error: {e}[/red]")
#     finally:
#         console.log(f"Session {state.session_id}: Connection closed.")


# def main():
#     """Server skeleton — plain TCP; no TLS. See assignment spec."""
    
#     # Load Root CA cert into memory
#     try:
#         pki.load_ca_cert()
#     except Exception:
#         sys.exit(1) # Error printed by loader
        
#     # Get DB connection
#     try:
#         db_conn = db.get_db_conn()
#     except Exception:
#         console.log("[red]Error: Could not connect to MySQL database.[/red]")
#         console.log("Is the Docker container running? (sudo docker start securechat-db)")
#         console.log("Is your .env file correct?")
#         sys.exit(1)

#     # Create server socket
#     server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
#     try:
#         server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         server_sock.bind((SERVER_HOST, SERVER_PORT))
#         server_sock.listen()
        
#         console.log(f"[green]Server listening on {SERVER_HOST}:{SERVER_PORT}...[/green]")
        
#         while True:
#             try:
#                 client_sock, client_addr = server_sock.accept()
#                 # We don't use threading, so this server can only
#                 # handle one client at a time, per the assignment.
#                 handle_client_connection(client_sock, client_addr, db_conn)
                
#             except Exception as e:
#                 console.log(f"[red]Error accepting connection: {e}[/red]")
    
#     except KeyboardInterrupt:
#         console.log("\n[yellow]Server shutting down.[/yellow]")
#     except Exception as e:
#         console.log(f"[red]Unhandled server error: {e}[/red]")
#     finally:
#         if db_conn:
#             db_conn.close()
#         server_sock.close()
#         console.log("Server stopped.")

# if __name__ == "__main__":
#     main()


# """Server skeleton — plain TCP; no TLS. See assignment spec."""

# import json
# import os
# import socket
# import sys
# from rich.console import Console
# from rich.panel import Panel

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
# from app.storage import db, transcript
# from pymysql.connections import Connection as DbConnection

# # --- Constants ---
# SERVER_HOST = "0.0.0.0"  # Listen on all interfaces
# SERVER_PORT = 9999
# SERVER_CERT_PATH = "certs/server.cert.pem"
# SERVER_KEY_PATH = "certs/server.key.pem"
# EXPECTED_CLIENT_CN = "client.local" # Per Req 2.1

# # --- Global Rich Console ---
# console = Console()

# class ServerState:
#     """Helper class to hold all state for a single client connection."""
#     def __init__(self, conn: DbConnection, sock: socket.socket, addr):
#         self.db_conn = conn
#         self.sock = sock
#         self.addr = addr
#         self.session_id = f"{addr[0]}:{addr[1]}_{now_ms()}"
        
#         console.log(f"Session {self.session_id}: New connection from {addr}")
        
#         # --- PKI State ---
#         self.server_cert, self.server_key, self.server_cert_pem = pki.load_cert_and_key(
#             SERVER_CERT_PATH, SERVER_KEY_PATH
#         )
#         self.client_cert: x509.Certificate | None = None
#         self.client_pubkey: rsa.RSAPublicKey | None = None
        
#         # --- Auth State ---
#         self.auth_aes_key: bytes | None = None # For Register/Login
#         self.authed_user_email: str | None = None
        
#         # --- Session State ---
#         self.session_aes_key: bytes | None = None # For main chat
#         self.seqno_rx = 0 # Received sequence number
#         self.seqno_tx = 0 # Transmitted sequence number
        
#         # --- Non-Repudiation ---
#         self.transcript = transcript.TranscriptLogger("server", self.session_id)
#         self.client_cert_fingerprint = "UNKNOWN"

# # --- Network Helpers ---

# def send_msg(state: ServerState, msg: BaseModel):
#     """Serializes, encodes, and sends a Pydantic message."""
#     try:
#         json_msg = msg.model_dump_json()
#         state.sock.sendall(json_msg.encode('utf-8') + b'\n')
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error sending message: {e}[/red]")

# def recv_msg(state: ServerState) -> dict | None:
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

# def handle_mutual_auth(state: ServerState) -> bool:
#     """Phase 1.1: PKI_CONNECT and CERT_VERIFY"""
#     try:
#         # 1. Receive Client Hello
#         console.log(f"Session {state.session_id}: Waiting for client 'hello'...")
#         client_hello_raw = recv_msg(state)
#         if not client_hello_raw: return False
        
#         client_hello = proto.Hello.model_validate(client_hello_raw)
        
#         # 2. Parse and validate client certificate
#         client_cert_pem = b64d(client_hello.client_cert)
#         state.client_cert = pki.parse_certificate(client_cert_pem)
#         if not state.client_cert:
#             return False
            
#         is_valid, reason = pki.validate_certificate(state.client_cert, EXPECTED_CLIENT_CN)
#         if not is_valid:
#             console.log(f"[red]Session {state.session_id}: Client cert validation failed: {reason}[/red]")
#             return False
            
#         console.log(f"Session {state.session_id}: Client certificate OK. Subject: {state.client_cert.subject.rfc4514_string()}")
        
#         # Store for transcript (Req 1.4)
#         fingerprint = state.client_cert.fingerprint(hashes.SHA256())
#         state.client_cert_fingerprint = fingerprint.hex()
#         state.client_pubkey = sign.get_public_key_from_cert(state.client_cert)
        
#         # 3. Send Server Hello
#         server_hello = proto.ServerHello(
#             server_cert=b64e(state.server_cert_pem),
#             nonce=b64e(os.urandom(16))
#         )
#         send_msg(state, server_hello)
#         return True
        
#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid auth message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Mutual auth failed: {e}[/red]")
#         return False

# def handle_auth_dh_exchange(state: ServerState) -> bool:
#     """Phase 1.2 / 2.2: DH_REGISTER_LOGIN_INIT (Temporary AES key)"""
#     try:
#         console.log(f"Session {state.session_id}: Performing temporary DH for auth...")
        
#         # 1. Receive Client DH params
#         dh_client_raw = recv_msg(state)
#         if not dh_client_raw: return False
        
#         dh_client = proto.DHClient.model_validate(dh_client_raw)
        
#         # 2. Server computes its keys
#         server_dh = dh.DHContext(g=dh_client.g, p=dh_client.p)
#         server_public_value_B = server_dh.get_public_value()
        
#         # 3. Compute shared secret (Ks) and final AES key (K)
#         shared_secret_ks = server_dh.compute_shared_key(dh_client.A)
#         state.auth_aes_key = server_dh.derive_aes_key(shared_secret_ks)
        
#         # 4. Send Server DH response
#         dh_server = proto.DHServer(B=server_public_value_B)
#         send_msg(state, dh_server)
        
#         console.log(f"Session {state.session_id}: Temporary AES auth key derived.")
#         return True

#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid DH message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Auth DH failed: {e}[/red]")
#         return False

# def handle_registration(state: ServerState, register: proto.Register):
#     """Handles a registration request."""
#     # 1. Generate salt
#     salt = os.urandom(16) # 16 bytes, per Req 2.2
    
#     # 2. Compute pwd_hash = SHA256(salt || password)
#     pwd_hash = sha256_hex(salt + register.pwd.encode('utf-8'))
    
#     # 3. Create user
#     success = db.create_user(
#         state.db_conn,
#         register.email,
#         register.username,
#         salt,
#         pwd_hash
#     )
    
#     if success:
#         console.log(f"Session {state.session_id}: New user registered: {register.email}")
        
#         # *** BUG #1 FIX ***
#         # We must set the email in the state so the chat loop knows who this is.
#         state.authed_user_email = register.email
        
#         return proto.AuthResponse(success=True, message="Registration successful.")
#     else:
#         console.log(f"Session {state.session_id}: Registration failed (user may exist): {register.email}")
#         return proto.AuthResponse(success=False, message="Registration failed: Email or username already exists.")
        
# def handle_login(state: ServerState, login: proto.Login):
#     """Handles a login request."""
#     # 1. Fetch user from DB
#     user = db.get_user_by_email(state.db_conn, login.email)
    
#     if not user:
#         console.log(f"Session {state.session_id}: Login failed (user not found): {login.email}")
#         return proto.AuthResponse(success=False, message="Login failed: Invalid email or password.")
        
#     # 2. Re-compute hash: test_hash = SHA256(salt || provided_password)
#     salt = user['salt']
#     stored_hash = user['pwd_hash']
#     test_hash = sha256_hex(salt + login.pwd.encode('utf-8'))
    
#     # 3. Securely compare hashes
#     if test_hash == stored_hash:
#         console.log(f"Session {state.session_id}: User login successful: {login.email}")
#         state.authed_user_email = login.email # Mark as authenticated
#         return proto.AuthResponse(success=True, message="Login successful.")
#     else:
#         console.log(f"Session {state.session_id}: Login failed (wrong password): {login.email}")
#         return proto.AuthResponse(success=False, message="Login failed: Invalid email or password.")


# def handle_auth_flow(state: ServerState) -> bool:
#     """Phase 1.1 / 2.2: AUTH_CRED_DECRYPT_VERIFY"""
#     try:
#         console.log(f"Session {state.session_id}: Waiting for encrypted auth request...")
        
#         # 1. Receive encrypted message
#         auth_req_raw = recv_msg(state)
#         if not auth_req_raw: return False
        
#         enc_request = proto.EncryptedAuthRequest.model_validate(auth_req_raw)
        
#         # 2. Decrypt the payload
#         ciphertext = b64d(enc_request.payload)
#         plaintext = aes.decrypt(state.auth_aes_key, ciphertext)
        
#         if not plaintext or plaintext == b'\x00':
#             console.log(f"[red]Session {state.session_id}: Failed to decrypt auth message (wrong key?)[/red]")
#             return False
            
#         auth_data = json.loads(plaintext.decode('utf-8'))
        
#         # 3. Handle Register or Login
#         response_msg: proto.AuthResponse
#         if auth_data['type'] == 'register':
#             register_req = proto.Register.model_validate(auth_data)
#             response_msg = handle_registration(state, register_req)
#         elif auth_data['type'] == 'login':
#             login_req = proto.Login.model_validate(auth_data)
#             response_msg = handle_login(state, login_req)
#         else:
#             raise Exception(f"Unknown auth type: {auth_data.get('type')}")
        
#         # 4. Encrypt and send response
#         response_plaintext = response_msg.model_dump_json().encode('utf-8')
#         response_ciphertext = aes.encrypt(state.auth_aes_key, response_plaintext)
        
#         enc_response = proto.EncryptedAuthResponse(payload=b64e(response_ciphertext))
#         send_msg(state, enc_response)
        
#         return response_msg.success

#     except (ValidationError, json.JSONDecodeError) as e:
#         console.log(f"[red]Session {state.session_id}: Invalid auth payload: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Auth flow failed: {e}[/red]")
#         return False

# def handle_session_dh_exchange(state: ServerState) -> bool:
#     """Phase 1.2 / 2.3: DH_CHAT_INIT (Main Session AES key)"""
#     try:
#         console.log(f"Session {state.session_id}: Performing MAIN session DH...")
        
#         # 1. Receive Client DH params
#         dh_client_raw = recv_msg(state)
#         if not dh_client_raw: return False
        
#         dh_client = proto.DHClient.model_validate(dh_client_raw)
        
#         # 2. Server computes its keys
#         server_dh = dh.DHContext(g=dh_client.g, p=dh_client.p)
#         server_public_value_B = server_dh.get_public_value()
        
#         # 3. Compute shared secret (Ks) and final AES key (K)
#         shared_secret_ks = server_dh.compute_shared_key(dh_client.A)
#         state.session_aes_key = server_dh.derive_aes_key(shared_secret_ks)
        
#         # 4. Send Server DH response
#         dh_server = proto.DHServer(B=server_public_value_B)
#         send_msg(state, dh_server)
        
#         console.log(f"[green]Session {state.session_id}: MAIN session AES key derived. Chat is live.[/green]")
#         return True

#     except ValidationError as e:
#         console.log(f"[red]Session {state.session_id}: Invalid main DH message: {e}[/red]")
#         return False
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Main DH failed: {e}[/red]")
#         return False

# def handle_chat_message(state: ServerState, msg: proto.Msg) -> str | None:
#     """
#     Phase 1.3 / 2.4: Handle an incoming 'msg'
#     1. Verify seqno (replay protection)
#     2. Verify signature (authenticity, integrity)
#     3. Decrypt (confidentiality)
#     4. Log to transcript (non-repudiation)
#     """
#     try:
#         # *** NEW PRINT STATEMENT AS REQUESTED ***
#         console.log(f"Received raw msg. ct_b64: {msg.ct[:30]}... sig_b64: {msg.sig[:30]}...")

#         # 1. Check seqno (replay protection)
#         if msg.seqno <= state.seqno_rx:
#             console.log(f"[red]Session {state.session_id}: REPLAY detected. Got {msg.seqno}, expected > {state.seqno_rx}[/red]")
#             return None
#         state.seqno_rx = msg.seqno
        
#         # 2. Verify signature
#         # h = SHA256(seqno || timestamp || ciphertext)
#         # Note: Pydantic gives us int/str, we must convert to bytes
#         hash_data = str(msg.seqno).encode('utf-8') + str(msg.ts).encode('utf-8') + msg.ct.encode('utf-8')
        
#         is_valid_sig = sign.verify(
#             public_key=state.client_pubkey,
#             signature=b64d(msg.sig),
#             data=hash_data
#         )
        
#         if not is_valid_sig:
#             console.log(f"[red]Session {state.session_id}: SIG_FAIL detected. Message signature is invalid.[/red]")
#             return None
            
#         # 3. Decrypt
#         console.log("Signature OK. Decrypting...")
#         ciphertext = b64d(msg.ct)
#         plaintext_bytes = aes.decrypt(state.session_aes_key, ciphertext)
        
#         if not plaintext_bytes or plaintext_bytes == b'\x00':
#             console.log(f"[red]Session {state.session_id}: Decryption failed (wrong key or corrupt data)[/red]")
#             return None
            
#         plaintext = plaintext_bytes.decode('utf-8')
        
#         # 4. Log to transcript
#         state.transcript.log_message(
#             peer_name="client",
#             seqno=msg.seqno,
#             ts=msg.ts,
#             ct_b64=msg.ct,
#             sig_b64=msg.sig,
#             peer_cert_fingerprint=state.client_cert_fingerprint
#         )
        
#         return plaintext
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error handling chat message: {e}[/red]")
#         return None


# def handle_chat_loop(state: ServerState):
#     """Phase 1.3 / 2.4: CHAT-LOOP"""
#     console.log(f"Session {state.session_id}: Entering chat loop with {state.authed_user_email}...")
    
#     # We remove the server's automatic welcome message to prevent the sync bug.
    
#     while True:
#         msg_raw = recv_msg(state)
#         if not msg_raw:
#             console.log(f"Session {state.session_id}: Client disconnected.")
#             break
            
#         try:
#             # Check for message type
#             if msg_raw.get('type') == 'msg':
#                 msg = proto.Msg.model_validate(msg_raw)
#                 plaintext = handle_chat_message(state, msg)
                
#                 if plaintext:
#                     console.print(Panel(f"[cyan]{state.authed_user_email}:[/cyan] {plaintext}", title="Message Received"))
                    
#                     # Check for quit command
#                     if plaintext.strip() == "/quit":
#                         console.log(f"Session {state.session_id}: Client requested /quit.")
#                         send_secure_message(state, "Goodbye!")
#                         break
            
#             elif msg_raw.get('type') == 'receipt':
#                 # Handle receipt if needed
#                 console.log(f"Session {state.session_id}: Received client receipt.")
#                 break # End session on receipt
                
#             else:
#                 console.log(f"[yellow]Session {state.session_id}: Received unknown message type: {msg_raw.get('type')}[/yellow]")
                
#         except ValidationError as e:
#             console.log(f"[red]Session {state.session_id}: Invalid chat message: {e}[/red]")
#         except Exception as e:
#             console.log(f"[red]Session {state.session_id}: Chat loop error: {e}[/red]")
#             break

# def send_secure_message(state: ServerState, plaintext: str):
#     """Helper to encrypt, sign, and send a chat message."""
#     try:
#         state.seqno_tx += 1
#         ts = now_ms()
        
#         # 1. Encrypt
#         ciphertext = aes.encrypt(state.session_aes_key, plaintext.encode('utf-8'))
#         ct_b64 = b64e(ciphertext)
        
#         # 2. Sign
#         # h = SHA256(seqno || timestamp || ciphertext)
#         hash_data = str(state.seqno_tx).encode('utf-8') + str(ts).encode('utf-8') + ct_b64.encode('utf-8')
#         signature = sign.sign(state.server_key, hash_data)
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
#             peer_name="server",
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


# def handle_session_receipt(state: ServerState):
#     """Phase 1.4 / 2.5: Generate and send the SessionReceipt"""
#     try:
#         console.log(f"Session {state.session_id}: Generating session receipt...")
#         transcript_hash = state.transcript.get_transcript_hash()
        
#         # Sign the transcript hash
#         sig_bytes = sign.sign(state.server_key, transcript_hash.encode('utf-8'))
        
#         receipt = proto.Receipt(
#             peer="server",
#             first_seq=1, # Simple placeholder
#             last_seq=state.seqno_tx,
#             transcript_sha256=transcript_hash,
#             sig=b64e(sig_bytes)
#         )
        
#         send_msg(state, receipt)
#         console.log(f"Session {state.session_id}: Session receipt sent.")
        
#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Error generating receipt: {e}[/red]")

# # --- Main Connection Handler ---

# def handle_client_connection(sock: socket.socket, addr, db_conn: DbConnection):
#     """
#     Handles a single, complete client connection from start to finish.
#     """
#     state = ServerState(db_conn, sock, addr)
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
#                 raise Exception("User authentication failed")
                
#             # Phase 4: Main Session DH
#             if not handle_session_dh_exchange(state):
#                 raise Exception("Main session DH exchange failed")
                
#             # Phase 5: Chat Loop
#             handle_chat_loop(state)
            
#             # Phase 6: Non-Repudiation (Receipt)
#             handle_session_receipt(state)

#     except Exception as e:
#         console.log(f"[red]Session {state.session_id}: Connection error: {e}[/red]")
#     finally:
#         console.log(f"Session {state.session_id}: Connection closed.")


# def main():
#     """Server skeleton — plain TCP; no TLS. See assignment spec."""
    
#     # Load Root CA cert into memory
#     try:
#         pki.load_ca_cert()
#     except Exception:
#         sys.exit(1) # Error printed by loader
        
#     # Get DB connection
#     try:
#         db_conn = db.get_db_conn()
#     except Exception:
#         console.log("[red]Error: Could not connect to MySQL database.[/red]")
#         console.log("Is the Docker container running? (sudo docker start securechat-db)")
#         console.log("Is your .env file correct?")
#         sys.exit(1)

#     # Create server socket
#     server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
#     try:
#         server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         server_sock.bind((SERVER_HOST, SERVER_PORT))
#         server_sock.listen()
        
#         console.log(f"[green]Server listening on {SERVER_HOST}:{SERVER_PORT}...[/green]")
        
#         while True:
#             try:
#                 client_sock, client_addr = server_sock.accept()
#                 # We don't use threading, so this server can only
#                 # handle one client at a time, per the assignment.
#                 handle_client_connection(client_sock, client_addr, db_conn)
                
#             except Exception as e:
#                 console.log(f"[red]Error accepting connection: {e}[/red]")
    
#     except KeyboardInterrupt:
#         console.log("\n[yellow]Server shutting down.[/yellow]")
#     except Exception as e:
#         console.log(f"[red]Unhandled server error: {e}[/red]")
#     finally:
#         if db_conn:
#             db_conn.close()
#         server_sock.close()
#         console.log("Server stopped.")

# if __name__ == "__main__":
#     main()

"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import json
import os
import socket
import sys
from rich.console import Console
from rich.panel import Panel
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
from app.storage import db, transcript
from pymysql.connections import Connection as DbConnection

# --- Constants ---
SERVER_HOST = "0.0.0.0"  # Listen on all interfaces
SERVER_PORT = 9999
SERVER_CERT_PATH = "certs/server.cert.pem"
SERVER_KEY_PATH = "certs/server.key.pem"
EXPECTED_CLIENT_CN = "client.local" # Per Req 2.1

# --- Global Rich Console ---
console = Console()

class ServerState:
    """Helper class to hold all state for a single client connection."""
    def __init__(self, conn: DbConnection, sock: socket.socket, addr):
        self.db_conn = conn
        self.sock = sock
        self.addr = addr
        self.session_id = f"{addr[0]}:{addr[1]}_{now_ms()}"
        
        console.log(f"Session {self.session_id}: New connection from {addr}")
        
        # --- PKI State ---
        self.server_cert, self.server_key, self.server_cert_pem = pki.load_cert_and_key(
            SERVER_CERT_PATH, SERVER_KEY_PATH
        )
        self.client_cert: x509.Certificate | None = None
        self.client_pubkey: rsa.RSAPublicKey | None = None
        
        # --- Auth State ---
        self.auth_aes_key: bytes | None = None # For Register/Login
        self.authed_user_email: str | None = None
        
        # --- Session State ---
        self.session_aes_key: bytes | None = None # For main chat
        self.seqno_rx = 0 # Received sequence number
        self.seqno_tx = 0 # Transmitted sequence number
        
        # --- Non-Repudiation ---
        self.transcript = transcript.TranscriptLogger("server", self.session_id)
        self.client_cert_fingerprint = "UNKNOWN"

# --- Network Helpers ---

def send_msg(state: ServerState, msg: BaseModel):
    """Serializes, encodes, and sends a Pydantic message."""
    try:
        json_msg = msg.model_dump_json()
        state.sock.sendall(json_msg.encode('utf-8') + b'\n')
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error sending message: {e}[/red]")

def recv_msg(state: ServerState) -> dict | None:
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

def handle_mutual_auth(state: ServerState) -> bool:
    """Phase 1.1: PKI_CONNECT and CERT_VERIFY"""
    try:
        # 1. Receive Client Hello
        console.log(f"Session {state.session_id}: Waiting for client 'hello'...")
        client_hello_raw = recv_msg(state)
        if not client_hello_raw: return False
        
        client_hello = proto.Hello.model_validate(client_hello_raw)
        
        # 2. Parse and validate client certificate
        client_cert_pem = b64d(client_hello.client_cert)
        state.client_cert = pki.parse_certificate(client_cert_pem)
        if not state.client_cert:
            return False
            
        is_valid, reason = pki.validate_certificate(state.client_cert, EXPECTED_CLIENT_CN)
        if not is_valid:
            console.log(f"[red]Session {state.session_id}: Client cert validation failed: {reason}[/red]")
            return False
            
        console.log(f"Session {state.session_id}: Client certificate OK. Subject: {state.client_cert.subject.rfc4514_string()}")
        
        # Store for transcript (Req 1.4)
        fingerprint = state.client_cert.fingerprint(hashes.SHA256())
        state.client_cert_fingerprint = fingerprint.hex()
        state.client_pubkey = sign.get_public_key_from_cert(state.client_cert)
        
        # 3. Send Server Hello
        server_hello = proto.ServerHello(
            server_cert=b64e(state.server_cert_pem),
            nonce=b64e(os.urandom(16))
        )
        send_msg(state, server_hello)
        return True
        
    except ValidationError as e:
        console.log(f"[red]Session {state.session_id}: Invalid auth message: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Mutual auth failed: {e}[/red]")
        return False

def handle_auth_dh_exchange(state: ServerState) -> bool:
    """Phase 1.2 / 2.2: DH_REGISTER_LOGIN_INIT (Temporary AES key)"""
    try:
        console.log(f"Session {state.session_id}: Performing temporary DH for auth...")
        
        # 1. Receive Client DH params
        dh_client_raw = recv_msg(state)
        if not dh_client_raw: return False
        
        dh_client = proto.DHClient.model_validate(dh_client_raw)
        
        # 2. Server computes its keys using client's g and p parameters
        server_dh = dh.DHContext(g=dh_client.g, p=dh_client.p) 
        server_public_value_B = server_dh.get_public_value()
        
        # 3. Compute shared secret (Ks) and final AES key (K)
        shared_secret_ks = server_dh.compute_shared_key(dh_client.A)
        state.auth_aes_key = server_dh.derive_aes_key(shared_secret_ks)
        
        # 4. Send Server DH response
        dh_server = proto.DHServer(B=server_public_value_B)
        send_msg(state, dh_server)
        
        console.log(f"Session {state.session_id}: Temporary AES auth key derived.")
        return True

    except ValidationError as e:
        console.log(f"[red]Session {state.session_id}: Invalid DH message: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Auth DH failed: {e}[/red]")
        return False

def handle_registration(state: ServerState, register: proto.Register):
    """Handles a registration request."""
    # 1. Generate salt
    salt = os.urandom(16) # 16 bytes, per Req 2.2
    
    # 2. Compute pwd_hash = SHA256(salt || password)
    pwd_hash = sha256_hex(salt + register.pwd.encode('utf-8'))
    
    # 3. Create user
    success = db.create_user(
        state.db_conn,
        register.email,
        register.username,
        salt,
        pwd_hash
    )
    
    if success:
        console.log(f"Session {state.session_id}: New user registered: {register.email}")
        
        # FIX: Set the email here so the chat loop knows who this is
        state.authed_user_email = register.email
        
        return proto.AuthResponse(success=True, message="Registration successful.")
    else:
        console.log(f"Session {state.session_id}: Registration failed (user may exist): {register.email}")
        return proto.AuthResponse(success=False, message="Registration failed: Email or username already exists.")
        
def handle_login(state: ServerState, login: proto.Login):
    """Handles a login request."""
    # 1. Fetch user from DB
    user = db.get_user_by_email(state.db_conn, login.email)
    
    if not user:
        console.log(f"Session {state.session_id}: Login failed (user not found): {login.email}")
        return proto.AuthResponse(success=False, message="Login failed: Invalid email or password.")
        
    # 2. Re-compute hash: test_hash = SHA256(salt || provided_password)
    salt = user['salt']
    stored_hash = user['pwd_hash']
    test_hash = sha256_hex(salt + login.pwd.encode('utf-8'))
    
    # 3. Securely compare hashes
    if test_hash == stored_hash:
        console.log(f"Session {state.session_id}: User login successful: {login.email}")
        state.authed_user_email = login.email # Mark as authenticated
        return proto.AuthResponse(success=True, message="Login successful.")
    else:
        console.log(f"Session {state.session_id}: Login failed (wrong password): {login.email}")
        return proto.AuthResponse(success=False, message="Login failed: Invalid email or password.")


def handle_auth_flow(state: ServerState) -> bool:
    """Phase 1.1 / 2.2: AUTH_CRED_DECRYPT_VERIFY"""
    try:
        console.log(f"Session {state.session_id}: Waiting for encrypted auth request...")
        
        # 1. Receive encrypted message
        auth_req_raw = recv_msg(state)
        if not auth_req_raw: return False
        
        enc_request = proto.EncryptedAuthRequest.model_validate(auth_req_raw)
        
        # 2. Decrypt the payload
        ciphertext = b64d(enc_request.payload)
        plaintext = aes.decrypt(state.auth_aes_key, ciphertext)
        
        if not plaintext or plaintext == b'\x00':
            console.log(f"[red]Session {state.session_id}: Failed to decrypt auth message (wrong key?)[/red]")
            return False
            
        auth_data = json.loads(plaintext.decode('utf-8'))
        
        # 3. Handle Register or Login
        response_msg: proto.AuthResponse
        if auth_data['type'] == 'register':
            register_req = proto.Register.model_validate(auth_data)
            response_msg = handle_registration(state, register_req)
        elif auth_data['type'] == 'login':
            login_req = proto.Login.model_validate(auth_data)
            response_msg = handle_login(state, login_req)
        else:
            raise Exception(f"Unknown auth type: {auth_data.get('type')}")
        
        # 4. Encrypt and send response
        response_plaintext = response_msg.model_dump_json().encode('utf-8')
        response_ciphertext = aes.encrypt(state.auth_aes_key, response_plaintext)
        
        enc_response = proto.EncryptedAuthResponse(payload=b64e(response_ciphertext))
        send_msg(state, enc_response)
        
        return response_msg.success

    except (ValidationError, json.JSONDecodeError) as e:
        console.log(f"[red]Session {state.session_id}: Invalid auth payload: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Auth flow failed: {e}[/red]")
        return False

def handle_session_dh_exchange(state: ServerState) -> bool:
    """Phase 1.2 / 2.3: DH_CHAT_INIT (Main Session AES key)"""
    try:
        console.log(f"Session {state.session_id}: Performing MAIN session DH...")
        
        # 1. Receive Client DH params
        dh_client_raw = recv_msg(state)
        if not dh_client_raw: return False
        
        dh_client = proto.DHClient.model_validate(dh_client_raw)
        
        # 2. Server computes its keys using client's g and p parameters
        server_dh = dh.DHContext(g=dh_client.g, p=dh_client.p) 
        server_public_value_B = server_dh.get_public_value()
        
        # 3. Compute shared secret (Ks) and final AES key (K)
        shared_secret_ks = server_dh.compute_shared_key(dh_client.A)
        state.session_aes_key = server_dh.derive_aes_key(shared_secret_ks)
        
        # 4. Send Server DH response
        dh_server = proto.DHServer(B=server_public_value_B)
        send_msg(state, dh_server)
        
        console.log(f"[green]Session {state.session_id}: MAIN session AES key derived. Chat is live.[/green]")
        return True

    except ValidationError as e:
        console.log(f"[red]Session {state.session_id}: Invalid main DH message: {e}[/red]")
        return False
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Main DH failed: {e}[/red]")
        return False

def handle_chat_message(state: ServerState, msg: proto.Msg) -> str | None:
    """
    Phase 1.3 / 2.4: Handle an incoming 'msg'
    1. Verify seqno (replay protection)
    2. Verify signature (authenticity, integrity)
    3. Decrypt (confidentiality)
    4. Log to transcript (non-repudiation)
    """
    try:
        # LOGGING FEATURE: Print encrypted data (ct and sig)
        console.log(Panel(
            f"[yellow]Encrypted Ciphertext (ct):[/yellow] {msg.ct}",
            title=f"Received Message {msg.seqno} Encrypted Payload",
            subtitle=f"[yellow]Signature (sig):[/yellow] {msg.sig[:60]}..."
        ))

        # 1. Check seqno (replay protection)
        if msg.seqno <= state.seqno_rx:
            console.log(f"[red]Session {state.session_id}: REPLAY detected. Got {msg.seqno}, expected > {state.seqno_rx}[/red]")
            return None
        state.seqno_rx = msg.seqno
        
        # --- START TAMPER INJECTION (for testing only) ---
        # This code deliberately tampers with message seqno 2 to test SIG_FAIL
        # Uncomment the code below to enable SIG_FAIL testing
        # if msg.seqno == 2:  # Only tamper with the second message
        #     msg.ct = msg.ct[:-1] + ('A' if msg.ct[-1] != 'A' else 'B')
        #     console.log("[red]>>> DEBUG: TAMPERED CIPHERTEXT! SIG_FAIL EXPECTED! <<<[/red]")
        # --- END TAMPER INJECTION ---
        
        # 2. Verify signature
        hash_data = str(msg.seqno).encode('utf-8') + str(msg.ts).encode('utf-8') + msg.ct.encode('utf-8')
        
        is_valid_sig = sign.verify(
            public_key=state.client_pubkey,
            signature=b64d(msg.sig),
            data=hash_data
        )
        
        if not is_valid_sig:
            console.log(f"[red]Session {state.session_id}: SIG_FAIL detected. Message signature is invalid.[/red]")
            return None
            
        # 3. Decrypt
        console.log("[green]Signature OK.[/green] Decrypting...")
        ciphertext = b64d(msg.ct)
        plaintext_bytes = aes.decrypt(state.session_aes_key, ciphertext)
        
        if not plaintext_bytes or plaintext_bytes == b'\x00':
            console.log(f"[red]Session {state.session_id}: Decryption failed (wrong key or corrupt data)[/red]")
            return None
            
        plaintext = plaintext_bytes.decode('utf-8')
        
        # 4. Log to transcript
        state.transcript.log_message(
            peer_name="client",
            seqno=msg.seqno,
            ts=msg.ts,
            ct_b64=msg.ct,
            sig_b64=msg.sig,
            peer_cert_fingerprint=state.client_cert_fingerprint
        )
        
        return plaintext
        
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error handling chat message: {e}[/red]")
        return None


def handle_chat_loop(state: ServerState):
    """Phase 1.3 / 2.4: CHAT-LOOP"""
    console.log(f"Session {state.session_id}: Entering chat loop with {state.authed_user_email}...")
    
    # Send a welcome message as the first message
    server_welcome = f"Welcome, {state.authed_user_email}! You are connected to the server. Type /quit to exit."
    send_secure_message(state, server_welcome)
    
    while True:
        msg_raw = recv_msg(state)
        if not msg_raw:
            console.log(f"Session {state.session_id}: Client disconnected.")
            break
            
        try:
            # Check for message type
            if msg_raw.get('type') == 'msg':
                msg = proto.Msg.model_validate(msg_raw)
                plaintext = handle_chat_message(state, msg)
                
                if plaintext:
                    console.print(Panel(f"[cyan]{state.authed_user_email}:[/cyan] {plaintext}", title="Decrypted Message"))
                    
                    # Check for quit command
                    if plaintext.strip() == "/quit":
                        console.log(f"Session {state.session_id}: Client requested /quit.")
                        send_secure_message(state, "Goodbye!")
                        break
            
            elif msg_raw.get('type') == 'receipt':
                # Handle receipt if needed
                console.log(f"Session {state.session_id}: Received client receipt.")
                break # End session on receipt
                
            else:
                console.log(f"[yellow]Session {state.session_id}: Received unknown message type: {msg_raw.get('type')}[/yellow]")
                
        except ValidationError as e:
            console.log(f"[red]Session {state.session_id}: Invalid chat message: {e}[/red]")
        except Exception as e:
            console.log(f"[red]Session {state.session_id}: Chat loop error: {e}[/red]")
            break

def send_secure_message(state: ServerState, plaintext: str):
    """Helper to encrypt, sign, and send a chat message."""
    try:
        state.seqno_tx += 1
        ts = now_ms()
        
        # 1. Encrypt
        ciphertext = aes.encrypt(state.session_aes_key, plaintext.encode('utf-8'))
        ct_b64 = b64e(ciphertext)
        
        # 2. Sign
        hash_data = str(state.seqno_tx).encode('utf-8') + str(ts).encode('utf-8') + ct_b64.encode('utf-8')
        signature = sign.sign(state.server_key, hash_data)
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
            peer_name="server",
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


def handle_session_receipt(state: ServerState):
    """Phase 1.4 / 2.5: Generate and save the SessionReceipt"""
    
    # FIX: Define the file path to save the receipt
    receipt_filepath = Path(f"transcripts/server_{state.session_id}_receipt.json")
    
    try:
        console.log(f"Session {state.session_id}: Generating session receipt...")
        transcript_hash = state.transcript.get_transcript_hash()
        
        # Sign the transcript hash
        sig_bytes = sign.sign(state.server_key, transcript_hash.encode('utf-8'))
        
        receipt = proto.Receipt(
            peer="server",
            first_seq=1, # Simple placeholder
            last_seq=state.seqno_tx,
            transcript_sha256=transcript_hash,
            sig=b64e(sig_bytes)
        )
        
        # Save the JSON file locally for offline verification
        with open(receipt_filepath, 'w') as f:
            json.dump(receipt.model_dump(), f, indent=4)
        console.log(f"[green]Session Receipt SAVED:[/green] {receipt_filepath}")
        
        # Send receipt to client (for client's log/record)
        send_msg(state, receipt)
        
    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Error generating receipt: {e}[/red]")

# --- Main Connection Handler ---

def handle_client_connection(sock: socket.socket, addr, db_conn: DbConnection):
    """
    Handles a single, complete client connection from start to finish.
    """
    state = ServerState(db_conn, sock, addr)
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
                raise Exception("User authentication failed")
                
            # Phase 4: Main Session DH
            if not handle_session_dh_exchange(state):
                raise Exception("Main session DH exchange failed")
                
            # Phase 5: Chat Loop
            handle_chat_loop(state)
            
            # Phase 6: Non-Repudiation (Receipt)
            handle_session_receipt(state)

    except Exception as e:
        console.log(f"[red]Session {state.session_id}: Connection error: {e}[/red]")
    finally:
        console.log(f"Session {state.session_id}: Connection closed.")


def main():
    """Server skeleton — plain TCP; no TLS. See assignment spec."""
    
    # Load Root CA cert into memory
    try:
        pki.load_ca_cert()
    except Exception:
        sys.exit(1) # Error printed by loader
        
    # Get DB connection
    try:
        db_conn = db.get_db_conn()
    except Exception:
        console.log("[red]Error: Could not connect to MySQL database.[/red]")
        console.log("Is the Docker container running? (sudo docker start securechat-db)")
        console.log("Is your .env file correct?")
        sys.exit(1)

    # Create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((SERVER_HOST, SERVER_PORT))
        server_sock.listen()
        
        console.log(f"[green]Server listening on {SERVER_HOST}:{SERVER_PORT}...[/green]")
        
        while True:
            try:
                client_sock, client_addr = server_sock.accept()
                # We don't use threading, so this server can only
                # handle one client at a time, per the assignment.
                handle_client_connection(client_sock, client_addr, db_conn)
                
            except Exception as e:
                console.log(f"[red]Error accepting connection: {e}[/red]")
    
    except KeyboardInterrupt:
        console.log("\n[yellow]Server shutting down.[/yellow]")
    except Exception as e:
        console.log(f"[red]Unhandled server error: {e}[/red]")
    finally:
        if db_conn:
            db_conn.close()
        server_sock.close()
        console.log("Server stopped.")

if __name__ == "__main__":
    main()