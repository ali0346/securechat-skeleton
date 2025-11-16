
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository implements a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🧩 Overview

This is a fully implemented secure chat application that uses:
- **PKI (Public Key Infrastructure)** for mutual authentication via X.509 certificates
- **Diffie-Hellman Key Exchange** for symmetric key establishment (AES-128)
- **AES-128-ECB** encryption for message confidentiality
- **RSA signatures** (PKCS#1 v1.5 with SHA-256) for message integrity and authenticity
- **Sequence numbers** for replay attack prevention
- **Signed transcripts** for non-repudiation

The system follows a strict protocol flow:
1. **Mutual Authentication**: Client and server exchange and validate certificates
2. **Temporary DH Key Exchange**: Establish encrypted channel for authentication
3. **User Authentication**: Register/Login with encrypted credentials
4. **Session DH Key Exchange**: Establish main chat encryption key
5. **Secure Chat**: Encrypted and signed message exchange
6. **Session Receipt**: Signed transcript hash for non-repudiation

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

### Prerequisites

- Python 3.8 or higher
- MySQL 8.0 (via Docker recommended)
- OpenSSL (for certificate generation)

### 1. Clone and Setup Environment

```bash
# Clone the repository
git clone <your-fork-url>
cd securechat-skeleton

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env
# Edit .env with your database credentials
```

### 2. Database Setup (Docker Recommended)

```bash
# Start MySQL container
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8

# Initialize database tables
python -m app.storage.db --init
```

### 3. Certificate Generation

```bash
# Generate Root CA certificate
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

**Note**: Certificates are generated in the `certs/` directory. The Root CA must be trusted by both client and server.

### 4. Configuration

Edit `.env` file with your database credentials:
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=scuser
DB_PASS=scpass
DB_NAME=securechat
```

### 5. Running the Application

**Start the Server:**
```bash
python -m app.server
```

The server will listen on `0.0.0.0:9999` by default.

**Start the Client** (in another terminal):
```bash
python -m app.client
```

The client will connect to `127.0.0.1:9999` by default.

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 📖 Usage Guide

### Basic Usage

1. **Start the server** (Terminal 1):
   ```bash
   python -m app.server
   ```
   Wait for: `[green]Server listening on 0.0.0.0:9999...[/green]`

2. **Start the client** (Terminal 2):
   ```bash
   python -m app.client
   ```

3. **Authentication Flow**:
   - Choose to register or login
   - Enter your email (e.g., `ali@gmail.com`)
   - If registering, enter a username
   - Enter your password (hidden input)

4. **Chat Session**:
   - After successful authentication, you'll enter the chat loop
   - Type messages and press Enter
   - Messages are encrypted and signed automatically
   - Type `/quit` to end the session

5. **Session Receipts**:
   - After ending a session, receipts are automatically saved in `transcripts/`
   - Client receipt: `transcripts/client_[session_id]_receipt.json`
   - Server receipt: `transcripts/server_[session_id]_receipt.json`

## 🧪 Testing Instructions

### A. Non-Repudiation Verification Test

**Purpose**: Verify that transcripts and receipts can be verified offline.

**Steps**:

1. Run a complete chat session (register/login, send messages, quit)

2. **Verify Client Receipt** (Happy Path):
   ```bash
   python transcript_checker.py \
       --receipt transcripts/client_[session_id]_receipt.json \
       --log transcripts/client_[session_id].log \
       --cert certs/client.cert.pem
   ```
   **Expected Output**: `[VERIFICATION SUCCESSFUL: NON-REPUDIATION ESTABLISHED]`

3. **Verify Integrity Failure** (Modified Transcript):
   - Edit the transcript log file and change one character in a ciphertext field
   - Run the same verification command
   - **Expected Output**: `[VERIFICATION FAILED: INTEGRITY LOSS]`

### B. Invalid Certificate Test (BAD_CERT)

**Purpose**: Verify that the server rejects certificates not signed by the Root CA.

**Steps**:

1. Generate a forged certificate:
   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes \
     -keyout certs/attacker-key.pem \
     -out certs/attacker-cert.pem \
     -subj "/CN=EVIL_CLIENT"
   ```

2. Replace client certificates (backup first):
   ```bash
   cd certs
   mv client.cert.pem client.cert.bak
   mv client.key.pem client.key.bak
   cp attacker-cert.pem client.cert.pem
   cp attacker-key.pem client.key.pem
   ```

3. Start server and try to connect with client

4. **Expected Output** (Server):
   ```
   Session [...]: Client cert validation failed: BAD_CERT: Signature is invalid (not signed by our CA)
   Session [...]: Connection error: Mutual authentication failed
   ```

5. Restore original certificates:
   ```bash
   cd certs
   rm client.cert.pem client.key.pem
   mv client.cert.bak client.cert.pem
   mv client.key.bak client.key.pem
   ```
   
   Or use the restore script:
   ```bash
   ./RESTORE_CERTIFICATES.sh
   ```

### C. Tampering Test (SIG_FAIL)

**Purpose**: Verify that message integrity is protected via signatures.

**Steps**:

1. Enable tamper code in `app/server.py` (lines 1466-1468):
   - Uncomment the tamper injection code in `handle_chat_message` function

2. Start server and client, authenticate

3. Send two messages:
   - First message: `message one` (seqno 1 - should work)
   - Second message: `message two` (seqno 2 - will be tampered)

4. **Expected Output** (Server):
   ```
   >>> DEBUG: TAMPERED CIPHERTEXT! SIG_FAIL EXPECTED! <<<
   [red]Session [...]: SIG_FAIL detected. Message signature is invalid.[/red]
   ```

5. **Cleanup**: Comment out the tamper code after testing

### D. Replay Test (REPLAY)

**Purpose**: Verify that replay attacks are prevented via sequence numbers.

**Implementation**: The server automatically rejects messages with `seqno <= state.seqno_rx`. This is built into the protocol and doesn't require special test code.

**Expected Behavior**: Any message with a sequence number less than or equal to the last received sequence number will be rejected with: `[red]Session [...]: REPLAY detected. Got [seqno], expected > [last_seqno][/red]`

## 🛠️ Key Implementation Details

### Protocol Flow

1. **Phase 1: Mutual Authentication**
   - Client sends `Hello` with client certificate
   - Server validates client certificate (CA signature, validity, CN)
   - Server sends `ServerHello` with server certificate
   - Client validates server certificate

2. **Phase 2: Temporary DH Key Exchange (for Auth)**
   - Client generates DH parameters (g, p, A)
   - Server uses same parameters to generate B
   - Both parties derive temporary AES key for authentication

3. **Phase 3: User Authentication**
   - Client encrypts Register/Login request with temporary AES key
   - Server decrypts and processes authentication
   - Response is encrypted with same temporary key

4. **Phase 4: Session DH Key Exchange**
   - Client generates new DH parameters (g, p, A)
   - Server uses same parameters to generate B
   - Both parties derive main session AES key for chat

5. **Phase 5: Secure Chat**
   - Each message is encrypted with AES-128-ECB
   - Each message is signed with RSA (SHA-256)
   - Sequence numbers prevent replay attacks
   - All messages logged to transcript

6. **Phase 6: Session Receipt**
   - Client and server compute transcript hash
   - Both sign their transcript hash
   - Receipts saved locally for offline verification

### Security Features

- **Confidentiality**: AES-128-ECB encryption (PKCS#7 padding)
- **Integrity**: RSA signatures (PKCS#1 v1.5 with SHA-256)
- **Authenticity**: X.509 certificate validation via Root CA
- **Non-Repudiation**: Signed session receipts with transcript hashes
- **Replay Protection**: Sequence number checking
- **Password Security**: Salted SHA-256 hashing

### File Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client implementation
│  ├─ server.py              # Server implementation
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128-ECB encryption
│  │  ├─ dh.py               # Diffie-Hellman key exchange
│  │  ├─ pki.py              # X.509 certificate validation
│  │  └─ sign.py             # RSA signature operations
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models
│  │  └─ utils.py            # Utility functions
│  └─ storage/
│     ├─ db.py               # MySQL database operations
│     └─ transcript.py       # Transcript logging
├─ scripts/
│  ├─ gen_ca.py              # Root CA generation
│  └─ gen_cert.py            # Certificate generation
├─ certs/                     # Certificate storage (gitignored)
├─ transcripts/               # Session logs and receipts (gitignored)
├─ transcript_checker.py      # Offline receipt verification tool
├─ test_bad_cert.sh          # BAD_CERT test helper
├─ RESTORE_CERTIFICATES.sh   # Certificate restoration helper
└─ requirements.txt           # Python dependencies
```

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records:
   ```bash
   mysqldump -u scuser -p securechat users > schema.sql
   ```
3. Updated **README.md** (this file).
4. `RollNumber-FullName-Report-A02.docx` (Design Document).
5. `RollNumber-FullName-TestReport-A02.docx` (Test Evidence Document).

## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline  

## 🔧 Troubleshooting

### Database Connection Issues

If you see `Error: Could not connect to MySQL database`:
- Check if Docker container is running: `docker ps`
- Start the container: `docker start securechat-db`
- Verify `.env` file has correct credentials

### Certificate Issues

If you see `Error: Root CA cert not found`:
- Run certificate generation scripts: `python scripts/gen_ca.py`
- Ensure certificates are in the `certs/` directory

### Import Errors

If you see `ModuleNotFoundError`:
- Ensure virtual environment is activated: `source .venv/bin/activate`
- Reinstall dependencies: `pip install -r requirements.txt`

## 📝 Notes

- The server can handle one client at a time (single-threaded by design)
- All cryptographic operations use industry-standard libraries (cryptography)
- Transcript files are automatically created in `transcripts/` directory
- Session receipts are saved as JSON files for offline verification

## 🔐 Security Considerations

- **DO NOT** commit `certs/`, `transcripts/`, or `.env` files to git
- Private keys should never be exposed
- The implementation uses standard cryptographic practices
- Certificate validation includes CA signature, validity period, and CN matching

---

**Author**: [Your Name]  
**Course**: CS-3002 Information Security  
**Semester**: Fall 2025
