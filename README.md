# IPsec Security Simulator
## Computer & Network Security (CNS) Educational Project

---

## 1. Project Title

**IPsec-Based Secure Packet Communication Simulator**

---

## 2. Objective

Build an interactive web application that visually demonstrates how IPsec protects network packets between a sender and receiver. The simulator covers Authentication Header (AH) and Encapsulating Security Payload (ESP) modes, packet transmission, attack simulation, receiver verification, and message recovery.

---

## 3. Problem Statement

IPsec is a critical network security protocol. However, understanding what actually happens during AH/ESP protection — authentication tag generation, encryption, tamper detection, and message recovery — is difficult from textbooks alone. This simulator makes those concepts visible and interactive.

---

## 4. Features

| Feature | Description |
|---|---|
| AH Simulation | HMAC-SHA256 authentication and integrity protection |
| ESP Simulation | AES-256-GCM authenticated encryption |
| Multi-phase lab | Separate Configure, Protect, Transmit, Verify, and Recover route views |
| Packet Visualization | Interactive conceptual AH / ESP packet structures with visual and structured views |
| Network Transmission | Animated packet traveling from sender to receiver |
| Attack Simulator | Modify payload, authentication tag, or header |
| Tamper Detection | Receiver verifies and rejects modified packets |
| Message Recovery | ESP decryption only after successful verification |
| Knowledge Base | A separate `/learn` route keeps detailed theory out of the simulator flow |
| Status System | READY, PROTECTED, IN TRANSIT, MODIFIED, VERIFIED, REJECTED, and RECOVERED states |

---

## 5. CNS Concepts Demonstrated

1. IP Security overview
2. IPsec architecture (AH and ESP)
3. Authentication Header (AH) — HMAC-SHA256
4. Encapsulating Security Payload (ESP) — AES-256-GCM
5. Authentication
6. Integrity
7. Confidentiality
8. Packet protection
9. Packet transmission
10. Packet modification and tampering
11. Detection of tampering
12. Receiver verification
13. Message recovery (ESP decryption)

---

## 6. Architecture

```
Browser (HTML/CSS/JavaScript)
         |
         | HTTP + JSON (Fetch API)
         |
    FastAPI Backend
         |
    +----+----+
    |         |
 AH Service  ESP Service
 (HMAC-SHA256) (AES-256-GCM)
    |         |
    +----+----+
         |
   Packet Service
         |
   Attack Service
         |
 Verification Service
         |
    +----+----+
    |         |
  VALID    INVALID
    |         |
 Recovery   Reject
```

---

## 7. Folder Structure

```
ipsec-security-simulator/
│
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI application, static file serving
│   │   ├── api/
│   │   │   └── routes/
│   │   │       └── ipsec.py     API route handlers
│   │   ├── models/
│   │   │   └── schemas.py       Pydantic request/response models
│   │   ├── services/
│   │   │   ├── ah_service.py    AH protection and verification
│   │   │   ├── esp_service.py   ESP encryption and verification
│   │   │   ├── packet_service.py  Packet lifecycle
│   │   │   ├── attack_service.py  Packet tampering simulation
│   │   │   └── verification_service.py  Unified verify + recover
│   │   └── utils/
│   │       └── crypto.py        HMAC-SHA256, AES-GCM, key generation
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── index.html               Single-page application
│   ├── css/
│   │   └── styles.css           Cybersecurity lab UI design
│   └── js/
│       ├── api.js               All HTTP fetch calls
│       ├── state.js             Simulation state management
│       ├── ui.js                DOM rendering functions
│       └── app.js               Event controller
│
├── tests/
│   ├── test_ah.py
│   ├── test_esp.py
│   ├── test_attack.py
│   └── test_verification.py
│
├── .gitignore
└── README.md
```

---

## 8. Installation

### Requirements

- Python 3.11 or newer
- pip

### Step 1 — Create virtual environment

```bash
cd ipsec-security-simulator
python -m venv venv
```

### Step 2 — Activate virtual environment

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r backend/requirements.txt
```

---

## 9. Running the Backend

```bash
cd backend
fastapi dev app/main.py
```

The server starts at: **http://127.0.0.1:8000**

---

## 10. Running the Application

Open your browser at:

```
http://127.0.0.1:8000/
```

FastAPI serves both the API and the frontend from the same server. No separate frontend server is needed.

### API Documentation (Swagger UI)

```
http://127.0.0.1:8000/docs
```

---

## 11. API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness check |
| POST | `/api/ipsec/protect` | Apply AH or ESP protection |
| POST | `/api/ipsec/modify` | Simulate packet tampering |
| POST | `/api/ipsec/verify` | Receiver verification |
| POST | `/api/ipsec/recover` | Message recovery |

### GET /api/health

**Response:**
```json
{ "status": "ok", "service": "IPsec Security Simulator" }
```

### POST /api/ipsec/protect

**Request:**
```json
{
  "sender": "Alice",
  "receiver": "Bob",
  "message": "Hello Bob",
  "security_mode": "ESP"
}
```

**Response (ESP):**
```json
{
  "packet_id": "pkt_a1b2c3",
  "sender": "Alice",
  "receiver": "Bob",
  "security_mode": "ESP",
  "original_message": "Hello Bob",
  "protected_packet": {
    "mode": "ESP",
    "ciphertext": "...",
    "nonce": "...",
    "authentication_tag": "..."
  },
  "status": "PROTECTED",
  "protection_steps": [...]
}
```

### POST /api/ipsec/modify

**Request:**
```json
{
  "packet_id": "pkt_a1b2c3",
  "modification_type": "DATA",
  "protected_packet": { ... },
  "new_data": "Hello Eve"
}
```

**Response:**
```json
{
  "packet_id": "pkt_a1b2c3",
  "modification_type": "DATA",
  "modification_detail": {
    "field": "payload",
    "before": "Hello Bob",
    "after": "Hello Eve",
    "explanation": "..."
  },
  "protected_packet": { ... },
  "modified": true,
  "status": "MODIFIED"
}
```

### POST /api/ipsec/verify

**Response (valid):**
```json
{
  "authentication": { "status": "VALID", "detail": "..." },
  "integrity": { "status": "VALID", "detail": "..." },
  "confidentiality": { "status": "PROTECTED", "detail": "..." },
  "packet_status": "ACCEPTED",
  "reason": null
}
```

**Response (tampered):**
```json
{
  "authentication": { "status": "INVALID", "detail": "..." },
  "integrity": { "status": "INVALID", "detail": "..." },
  "packet_status": "REJECTED",
  "reason": "Verification failed..."
}
```

### POST /api/ipsec/recover

**Response (success):**
```json
{
  "packet_id": "pkt_a1b2c3",
  "packet_status": "ACCEPTED",
  "recovered_message": "Hello Bob",
  "verification": { ... },
  "recovery_steps": [ ... ]
}
```

**Response (rejected):**
```json
{
  "packet_id": "pkt_a1b2c3",
  "packet_status": "REJECTED",
  "recovered_message": null,
  "verification": { ... },
  "recovery_steps": [ ... ]
}
```

---

## 12. AH Explanation (Simulator)

1. The sender creates canonical data: `{"message": "...", "receiver": "Bob", "sender": "Alice"}`
2. HMAC-SHA256 is applied using a shared key held server-side.
3. The authentication tag (hex) is attached to the packet.
4. The payload remains **readable** — AH does not encrypt.
5. At the receiver, canonical data is re-derived and HMAC is re-computed.
6. If computed tag equals received tag → **ACCEPTED**.
7. If not equal → **REJECTED**.

---

## 13. ESP Explanation (Simulator)

1. A 96-bit random nonce is generated for each encryption.
2. AES-256-GCM encrypts the message and produces ciphertext + authentication tag.
3. The original message is hidden inside ciphertext.
4. At the receiver, AES-256-GCM decryption inherently verifies the authentication tag.
5. If tag is valid → decryption succeeds → message is recovered.
6. If tag is invalid → decryption fails → **REJECTED** (message not returned).

---

## 14. Packet Modification Explanation

Three types of attacks are simulated:

| Type | What changes | Detection mechanism |
|---|---|---|
| DATA | Payload (AH) or ciphertext bytes (ESP) | HMAC mismatch / GCM tag failure |
| AUTH_TAG | Authentication tag replaced with random bytes | Tag comparison fails |
| HEADER | Sender/receiver metadata changed | Canonical data differs, HMAC fails |

---

## 15. Verification Explanation

The verification service:
1. Dispatches to `ah_service.verify_ah()` or `esp_service.verify_esp()` based on mode.
2. For AH: re-derives canonical data → re-computes HMAC → constant-time comparison.
3. For ESP: attempts AES-GCM decryption → GCM internally verifies the authentication tag.
4. Returns structured result with per-field statuses.
5. Sets packet_status to `ACCEPTED` or `REJECTED`.

---

## 16. Testing

### Run all tests

```bash
cd ipsec-security-simulator
python -m pytest tests/ -v
```

### Test files

| File | What is tested |
|---|---|
| `test_ah.py` | AH protect, verify valid, verify tampered, verify modified tag |
| `test_esp.py` | ESP encrypt, verify valid, recover message, detect tampered ciphertext/tag/nonce |
| `test_attack.py` | DATA / AUTH_TAG / HEADER modifications for AH and ESP |
| `test_verification.py` | Full verify + recover pipeline for valid and tampered packets |

---

## 17. Example Workflow

### Scenario 1 — Secure ESP Delivery

1. Enter: Alice → Bob, "Hello Bob", ESP
2. Click **Protect Packet**
3. See: nonce generated → AES-GCM → ciphertext + tag
4. Click **No Modification — Send Intact**
5. Verification: Authentication VALID, Integrity VALID, Confidentiality PROTECTED
6. Recovery: "Hello Bob" returned

### Scenario 2 — ESP Tamper Detection

1. Enter: Alice → Bob, "Hello Bob", ESP
2. Click **Protect Packet**
3. Click **Modify Payload Data**
4. Verification: Authentication INVALID, Integrity INVALID → REJECTED
5. Recovery: Blocked — null returned

### Scenario 3 — AH Demonstration

1. Enter: Alice → Bob, "Hello Bob", AH
2. Click **Protect Packet**
3. Observe: payload remains readable, authentication tag added
4. Click **Modify Payload Data** → payload changes to "Hello Eve"
5. Verification fails → REJECTED

---

## 18. Viva Questions & Answers

**Q: What is IPsec?**
A: IPsec is a suite of protocols (RFC 4301) that provides security at the IP layer — authentication, integrity, and optional confidentiality. It is used in VPNs and secure tunnels.

**Q: What is the difference between AH and ESP?**
A: AH provides authentication and integrity but no encryption. ESP provides all three: authentication, integrity, and confidentiality through encryption.

**Q: Why does this simulator use HMAC-SHA256 for AH?**
A: HMAC requires a shared secret key, so only authorized parties can compute or verify the tag. Plain SHA-256 has no key and can be re-computed by anyone who modifies the data.

**Q: Why does this simulator use AES-GCM for ESP?**
A: AES-GCM is an authenticated encryption scheme (AEAD) — it provides both encryption and an authentication tag in one operation without a separate MAC step.

**Q: Why is the key never sent to the browser?**
A: The key is the secret that makes authentication and encryption meaningful. Exposing it in the browser would allow anyone to forge packets. The server uses it internally.

**Q: Why does AES-GCM use a nonce?**
A: A unique nonce ensures that encrypting the same message twice produces different ciphertext, preventing pattern analysis. GCM nonces must never be reused with the same key.

**Q: What happens when a packet is tampered?**
A: The receiver recomputes the authentication value. Since the received data no longer matches the original data, the computed value differs from the received tag. The packet is rejected.

**Q: What is the recovery process for ESP?**
A: The receiver first verifies the GCM authentication tag. Only if verification passes does it proceed to decrypt. This prevents decryption of forged packets.

**Q: What is the difference between authentication and integrity?**
A: Authentication verifies the *source* (who sent it). Integrity verifies that the *data* was not modified. Both are provided by HMAC-SHA256 and AES-GCM in this simulator.

---

## 19. Limitations

- This is an educational simulation, not a production VPN or real IPsec implementation.
- AH simulation does not reproduce the complete RFC 4302 wire format (SPI, Sequence Number, Padding, Next Header).
- ESP simulation does not reproduce the complete RFC 4303 wire format.
- Key exchange (IKEv2) is not simulated — keys are generated in-memory on the server at startup.
- Transport mode vs Tunnel mode distinction is not shown.
- Anti-replay protection (sequence numbers) is not simulated.
- No real network traffic is generated or sniffed.

---

## 20. Educational Disclaimer

> This application is an educational simulation of IPsec security concepts. It demonstrates AH/ESP-style protection, authentication, integrity, confidentiality, packet transmission, and tamper detection using HMAC-SHA256 and AES-256-GCM. It does not create real IPsec tunnels, configure real IPsec kernel policies, or transmit real IP packets over any network.
