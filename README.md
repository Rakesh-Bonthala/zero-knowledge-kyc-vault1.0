# Zero-Knowledge KYC Vault 🛡️

A production-grade prototype for fintech applications that enables users to securely encrypt sensitive Know-Your-Customer (KYC) identity documents (passports, national IDs, utility bills, proof of address) locally in their browsers before uploading them to cloud storage.

> **Fundamental Security Guarantee:**
> The backend and cloud storage providers **never** receive, store, or access plaintext documents, the user's passphrase, or derived encryption keys. The server exclusively handles encrypted ciphertext blobs and the non-secret cryptographic metadata required for client-side re-derivation.

---

## Table of Contents
1. [Overview & Core Value](#overview--core-value)
2. [Architecture & Data Flow](#architecture--data-flow)
3. [Cryptographic Specifications](#cryptographic-specifications)
4. [Technology Stack](#technology-stack)
5. [Storage Adapter Pattern (MongoDB GridFS, S3, Firebase, Mock)](#storage-adapter-pattern)
6. [Project Structure](#project-structure)
7. [Prerequisites & Installation](#prerequisites--installation)
8. [Configuration & Environment Setup](#configuration--environment-setup)
9. [Running the Application](#running-the-application)
10. [Automated Test Suite](#automated-test-suite)
11. [Password Breach Verification (HIBP k-Anonymity)](#password-breach-verification-hibp-k-anonymity)
12. [Security Model: What the Server Can & Cannot See](#security-model-what-the-server-can--cannot-see)
13. [Security Limitations & Attack Surface Analysis](#security-limitations--attack-surface-analysis)

---

## Overview & Core Value
In conventional cloud storage architectures, user documents are uploaded in plaintext and encrypted on the server ("encryption at rest"). This leaves sensitive PII vulnerable to insider threats, subpoena orders, backend database leaks, and compromised server infrastructure.

The **Zero-Knowledge KYC Vault** shifts the trust boundary entirely to the client:
- **Zero Key Escrow:** No master keys or server-side backdoors exist.
- **Client-Side PBKDF2 & AES-256-GCM:** Keys are derived directly in browser RAM and never leave the execution stack.
- **k-Anonymity Breach Protection:** Passphrases can be checked against Have I Been Pwned breach records using only a 5-character SHA-1 prefix.
- **Tamper Protection with AAD:** Additional Authenticated Data (AAD) cryptographically binds document metadata (original filename, MIME type, plaintext size, format version) to the ciphertext.

---

## Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER (RAM ONLY)                       │
│                                                                        │
│  [Plaintext Document]                                                  │
│           │                                                            │
│           ▼                                                            │
│  [Generate 16B Salt] + [Generate 12B IV]                               │
│           │                                                            │
│  [User Passphrase] ──► [PBKDF2-SHA256 (600k iter)] ──► [AES-256 Key]   │
│                                                               │        │
│  [File ArrayBuffer] + [AAD Metadata] ─────────────────────────┼──────┐ │
│                                                               ▼      │ │
│                                                      [AES-256-GCM]   │ │
│                                                               │      │ │
│                                                [Ciphertext + 16B Tag]│ │
│                                                               │      │ │
│                          (Passphrase & Key Purged From Memory)│      │ │
└───────────────────────────────────────────────────────────────┼──────┼─┘
                                                                │      │
                                         POST /api/vault/upload │      │
                            (Ciphertext Blob + Non-secret Meta) │      │
                                                                ▼      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    NODE.JS / EXPRESS BACKEND (BLIND)                   │
│                                                                        │
│   • Enforces Authentication & User Ownership Isolation                │
│   • Validates Max Upload Limit (50MB) & Request Headers                │
│   • Stores Metadata Record (Salt, IV, AAD, Iterations, DocID)          │
│                                                                        │
│                       STORAGE ADAPTER FACTORY                          │
│                                   │                                    │
│         ┌─────────────────┬───────┴─────────┬─────────────────┐        │
│         ▼                 ▼                 ▼                 ▼        │
│  [MongoDB GridFS]    [AWS S3]      [Firebase Storage]   [Local Mock]   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Specifications

All client-side operations use exclusively the native W3C **Web Crypto API** (`window.crypto.subtle`):

| Parameter | Value / Algorithm | Specification / Standard |
| :--- | :--- | :--- |
| **Symmetric Cipher** | **AES-256-GCM** | NIST SP 800-38D Authenticated Encryption |
| **Key Length** | **256 bits** (32 bytes) | Cryptographic grade |
| **Key Derivation (KDF)** | **PBKDF2** | RFC 8018 Password-Based Key Derivation |
| **KDF Hash Function** | **HMAC-SHA-256** | FIPS 180-4 standard |
| **PBKDF2 Iterations** | **600,000** (Default) | Exceeds current OWASP recommendations |
| **Salt Length** | **128 bits** (16 bytes) | Generated per document via `crypto.getRandomValues()` |
| **Initialization Vector (IV)** | **96 bits** (12 bytes) | Fresh IV generated for every encryption operation |
| **Authentication Tag** | **128 bits** (16 bytes) | Integrity & authenticity guarantee |
| **AAD Binding** | Canonical JSON | Binds filename, mimeType, size, version to ciphertext |

---

## Technology Stack

- **Frontend:** HTML5, CSS3 (Modern dark fintech aesthetic), Vanilla JavaScript (ES6 Modules), Web Crypto API. No frameworks, zero external crypto libraries.
- **Backend:** Node.js (v18+), Express.js, Helmet (tuned Content Security Policy), CORS, Multer (in-memory streaming).
- **Primary Storage:** MongoDB with GridFS Bucket.
- **Alternative Storage Providers:** AWS S3 (`@aws-sdk/client-s3`), Firebase Storage (`firebase-admin`), and Local Mock Storage.
- **Testing:** Node.js native test runner (`node:test`, `node:assert`), Supertest.

---

## Storage Adapter Pattern

The backend decouples document storage from database vendors using a pluggable adapter pattern:
- **`GridFSStorageAdapter`**: Primary storage engine chunking encrypted files inside MongoDB GridFS.
- **`S3StorageAdapter`**: Plugs into Amazon Web Services S3 buckets.
- **`FirebaseStorageAdapter`**: Integrates with Google Cloud Storage / Firebase buckets.
- **`MockStorageAdapter`**: Saves encrypted files locally in `./.mock_storage/`. **Zero cloud credentials required**.
- **Auto-Fallback Engine:** If MongoDB or cloud credentials are not supplied or fail to connect, the server automatically falls back to `MockStorageAdapter` with visual warnings in the console and UI.

---

## Project Structure

```
zero-knowledge-kyc-vault/
├── backend/
│   ├── config/
│   │   └── config.js                  # Centralized environment configuration
│   ├── controllers/
│   │   ├── crypto-uuid.js             # Cryptographic UUID generator
│   │   └── vault.controller.js        # Request handling (upload, list, download, delete)
│   ├── middleware/
│   │   ├── auth.middleware.js         # User ownership isolation & token validation
│   │   └── error.middleware.js        # Safe error masking
│   ├── models/
│   │   └── document.model.js          # Unified document repository (Mongoose + local store)
│   ├── routes/
│   │   └── vault.routes.js            # Express API router & multer configuration
│   ├── services/
│   │   └── storage/
│   │       ├── storage.interface.js   # Base StorageAdapter interface contract
│   │       ├── gridfs.adapter.js      # MongoDB GridFS adapter
│   │       ├── s3.adapter.js          # AWS S3 adapter
│   │       ├── firebase.adapter.js    # Firebase Cloud Storage adapter
│   │       ├── mock.adapter.js        # Local mock storage adapter
│   │       └── storage.factory.js     # Provider selection & fallback engine
│   └── server.js                      # Express server entry point with Helmet & static hosting
│
├── frontend/
│   ├── index.html                     # Responsive fintech KYC dashboard
│   ├── css/
│   │   └── style.css                  # Modern dark theme with emerald & cyan accents
│   └── js/
│       ├── app.js                     # Core UI controller & lifecycle management
│       ├── crypto.js                  # Web Crypto API engine (AES-GCM, PBKDF2, AAD)
│       ├── breach-check.js            # k-Anonymity HIBP range check
│       ├── api.js                     # Zero-knowledge REST API client
│       ├── storage.js                 # Session preference manager (strict zero-key policy)
│       └── ui.js                      # Rendering, toasts, formatters, progress
│
├── tests/
│   ├── crypto.test.js                 # 8 automated unit tests for Web Crypto engine
│   └── vault.test.js                  # 6 automated integration tests for backend & storage
│
├── .env.example                       # Environment template
├── .gitignore                         # Git exclusion rules
├── package.json                       # Dependencies and npm test scripts
└── README.md                          # Full documentation & security analysis
```

---

## Prerequisites & Installation

### Prerequisites
- **Node.js** v18.0.0 or higher (Tested on Node.js v26)
- **npm** v9.0.0 or higher
- *(Optional)* **MongoDB** (local or MongoDB Atlas connection string)

### Installation
Clone or navigate to the repository directory and install dependencies:
```bash
npm install
```

---

## Configuration & Environment Setup

Copy `.env.example` to create your `.env` file:
```bash
cp .env.example .env
```

### Environment Variables Reference
```env
# Server
PORT=3000
NODE_ENV=development

# Storage Provider: 'gridfs' | 's3' | 'firebase' | 'mock'
STORAGE_PROVIDER=gridfs

# Allow auto-fallback to local mock storage if cloud provider is offline
STORAGE_ALLOW_MOCK_FALLBACK=true

# MongoDB GridFS Configuration (Primary)
MONGODB_URI=mongodb://localhost:27017/zk_kyc_vault

# Optional: AWS S3 Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_S3_BUCKET=zk-kyc-vault-bucket

# Optional: Firebase Storage Configuration
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n..."
FIREBASE_STORAGE_BUCKET=your_app.appspot.com
```

### Running in Zero-Credential Mock Mode
If you do not have MongoDB running, leave `STORAGE_ALLOW_MOCK_FALLBACK=true` (or set `STORAGE_PROVIDER=mock`). The application will store encrypted files under `./.mock_storage/` without requiring any cloud services.

---

## Running the Application

### Start Server
```bash
npm start
```
Or with auto-restart on file change:
```bash
npm run dev
```

### Accessing the Web Application
Open your browser and navigate to:
```
http://localhost:3000
```
- The backend serves both the REST API on `/api/vault` and the frontend interface directly on port 3000.

---

## Automated Test Suite

The test suite validates:
1. Web Crypto API key derivation with PBKDF2 (SHA-256, 256-bit AES-GCM).
2. Fresh random Salt (>=16 bytes) and fresh random IV (12 bytes) on every operation.
3. AES-256-GCM encryption & decryption byte-for-byte fidelity.
4. Tampered ciphertext rejection (128-bit authentication tag failure).
5. Tampered AAD metadata rejection.
6. Incorrect passphrase rejection without leaking corrupted plaintext.
7. Backend REST API endpoints (status, upload, list, download, delete).
8. Multitenant user ownership isolation.
9. Mock storage adapter fallback.

### Run All Tests
```bash
npm test
```

### Run Crypto Unit Tests Only
```bash
npm run test:crypto
```

### Run Vault API Tests Only
```bash
npm run test:vault
```

---

## Password Breach Verification (HIBP k-Anonymity)

To protect users against selecting weak or compromised passphrases:
1. The browser computes the **SHA-1** hash of the user's passphrase locally using Web Crypto API.
2. Only the **first 5 hexadecimal characters** (the prefix) are transmitted to the Have I Been Pwned API:
   `GET https://api.pwnedpasswords.com/range/{prefix}`
3. HIBP returns a list of candidate 35-character hash suffixes.
4. The remaining 35 characters of the user's hash are compared **strictly in the user's browser**.
5. If a match is found, the user is warned that the passphrase has appeared in breached datasets and is advised to change it.
6. **Privacy Guarantee:** The backend server never receives the passphrase or hash. HIBP never receives the full hash.

---

## Security Model: What the Server Can & Cannot See

### 🟢 What the Server CANNOT See:
1. **Original KYC Document Contents:** Plaintext passports, IDs, bank statements are never transmitted over HTTP.
2. **User Passphrase:** Never sent over the wire, never logged, never stored in databases, cookies, or web storage.
3. **Derived AES Encryption Keys:** Generated dynamically in browser RAM via Web Crypto API and destroyed upon task completion.
4. **Decrypted Document Contents:** Decryption takes place exclusively in the user's browser.
5. **No Key Escrow:** The server has no master recovery key; lost passphrases result in permanent cryptographic unrecoverability.

### 🟡 What the Server CAN See:
1. **Encrypted Ciphertext:** High-entropy pseudo-random bytes indistinguishable from random noise.
2. **Cryptographic Metadata:** Salt (16 bytes), IV (12 bytes), Iteration count (600,000), Algorithm (`AES-256-GCM`).
3. **Ciphertext Size:** File size plus 16 bytes for the GCM authentication tag.
4. **Traffic Metadata:** Client IP address, upload/download timestamps, user account ID (`X-User-Id`).
5. **Original Filename & MIME Type:** Included in metadata unless client-side filename obfuscation is toggled.

---

## Security Limitations & Attack Surface Analysis

While client-side zero-knowledge encryption provides robust protection against server-side database breaches and storage inspection, several fundamental web security limitations apply:

1. **Malicious / Compromised Web Server:**
   - Because the frontend JavaScript code (`app.js`, `crypto.js`) is served by the web server, an adversary with root access to the hosting server could theoretically tamper with the served JavaScript to exfiltrate passphrases before encryption occurs.
   - *Mitigation in Production:* Implement strict Subresource Integrity (SRI), Content Security Policy (CSP), DNSSEC, and consider packaging the client as an audited Progressive Web App (PWA) or desktop client.

2. **Client-Side Malware & Browser Extensions:**
   - Keyloggers, compromised browser extensions, or XSS vulnerabilities in the origin can inspect DOM input fields or intercept keystrokes before encryption.
   - *Mitigation:* Zero third-party script tags, strict CSP prohibiting inline scripts (`scriptSrc: ['self']`), and advising users against installing untrusted browser extensions.

3. **Traffic Analysis & Side Channels:**
   - Even without plaintext access, observers monitoring network traffic can infer document types based on ciphertext file size and upload timing (e.g., standard passport scan sizes).
   - *Mitigation in Future Work:* Implement random ciphertext padding (padding files to uniform size buckets such as 1MB, 5MB, 10MB) to disguise actual file sizes.

4. **Passphrase Entropy & Loss:**
   - The security of PBKDF2 relies fundamentally on passphrase entropy. A low-entropy dictionary passphrase remains vulnerable to targeted offline brute-force attacks on the downloaded ciphertext.
   - Furthermore, because there is **no key escrow**, a forgotten passphrase means permanent data loss.

---

## License
MIT License. Developed for Google Antigravity Advanced Agentic Coding.

