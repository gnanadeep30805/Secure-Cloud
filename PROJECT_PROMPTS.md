# Secure Cloud: AI Interaction Prompts

This document contains highly detailed, pre-engineered prompts that you can copy and paste into any Large Language Model (LLM) or AI Coding Assistant (like ChatGPT, Claude, or Gemini) to interact with, expand, or write about the Secure Cloud project.

---

## 1. The "Master Context" Prompt
**Use Case:** You are opening a new chat window with an AI and want to continue coding, debugging, or adding features to this project. This prompt gives the AI absolute knowledge of your architecture so it doesn't break your Zero-Trust implementation.

**Copy this text:**
```text
I want you to act as a Senior Full-Stack Security Engineer. I am working on a project called "Secure Cloud," a Zero-Trust Architecture (ZTA) file storage application. Before we begin writing or modifying any code, you need to understand the complete architecture of the system. 

Please read and acknowledge the following system parameters:

### 1. Technology Stack
*   **Backend:** Node.js, Express.js
*   **Database:** MySQL (using `mysql2/promise` with a connection pool)
*   **Frontend:** Vanilla JavaScript (Single Page Application, ES6), CSS3 (Glassmorphism design), HTML5.
*   **Security Libraries:** `crypto` (native), `jsonwebtoken`, `speakeasy` (for TOTP/MFA), `qrcode`.

### 2. Database Schema Overview
The MySQL database is named `secure_cloud` and contains the following critical tables:
*   `users`: Stores `id`, `email`, `password_hash`, `mfaSecret`, `is_mfa_enabled`, `last_login`.
*   `files`: Stores `id`, `user_id`, `original_name`, `file_path` (local disk path), `encryption_status` ('plain' or 'encrypted'), `aes_key_encrypted` (wrapped with RSA), `iv`, and `file_hash`.
*   `user_roles` & `role_permissions`: Maps users to roles (admin, editor, viewer, guest) and roles to resource actions.
*   `abac_policies`: Stores JSON-based Attribute-Based Access Control rules (e.g., trust scores, time windows).
*   `audit_logs`: Stores forensic events with a `log_hash` and `prev_log_hash` to create a tamper-evident HMAC chain.
*   `risk_scores`: Tracks a user's persistent risk and device trust levels.

### 3. Core Security Architecture (ZTA)
The system strictly enforces the "Never Trust, Always Verify" model:
*   **PEP Middleware (`pepMiddleware.js`):** Intercepts all `/api/*` routes. It parses the JWT, extracts context (IP, User-Agent, Device Fingerprint), and passes it to the Access Controller.
*   **Access Controller (`accessController.js`):** Performs a 3-layer check:
    1.  **RBAC:** Does the user's role allow this action?
    2.  **ABAC:** Do the user's department/clearance match the file's requirements?
    3.  **Policy Engine:** Does the current context (Trust Score, Risk Score, Business Hours, VPN status) pass the global security policies?
*   **Risk-Based Authentication (RBA):** If the risk score is too high, the backend throws a `403 STEP_UP_REQUIRED`. The frontend catches this and renders an MFA modal, forcing the user to provide a TOTP code before the request can proceed.

### 4. Cryptographic Pipeline (AES-256-GCM + RSA)
*   When a user uploads a file, it is NOT buffered into memory. It is piped through `busboy` directly into a Node.js `crypto.createCipheriv('aes-256-gcm')` stream.
*   The symmetric AES key is randomly generated for every file.
*   The AES key is then wrapped (encrypted) using the server's public RSA-2048 key before being saved to the database.
*   During download, the server unwraps the AES key using its private RSA key, creates a Decipher stream, and pipes the decrypted chunks directly to the HTTP response (`res.pipe`).

### 5. Admin Control Plane
*   The frontend contains an Admin Panel tab restricted to the `admin` role.
*   It fetches dynamic ABAC policies via `GET /api/admin/policies/abac`.
*   It allows the assignment of RBAC roles via `POST /api/admin/users/:userId/role`.

**Your Task:**
Reply with "Acknowledged. I understand the Secure Cloud ZTA architecture." If you have any questions about the data flow, ask them now. Otherwise, wait for my first development instruction.
```

---

## 2. The "Technical Paper Writer" Prompt
**Use Case:** You need to generate an academic, IEEE-style technical paper, project report, or thesis documentation about the Secure Cloud project.

**Copy this text:**
```text
Act as an expert cybersecurity researcher and academic technical writer. Your task is to write a comprehensive, IEEE-style technical paper detailing the design, architecture, and implementation of "Secure Cloud," a modern enterprise file storage system built entirely on the principles of Zero-Trust Architecture (ZTA).

Please structure the paper with the following standard academic sections:
1. Abstract
2. Introduction (The failing of perimeter-based security and the need for ZTA)
3. System Architecture (Core Zero-Trust Components)
4. Cryptographic Implementation (Data at Rest and in Transit)
5. Access Control & Heuristics (RBAC, ABAC, and Context)
6. Forensic Logging & Anomaly Detection
7. Conclusion

Use the following highly specific technical details to write the paper:

**1. Core Zero-Trust Architecture (ZTA)**
*   The system implements the NIST SP 800-207 Zero-Trust paradigm.
*   **Policy Enforcement Point (PEP):** A fail-secure middleware gateway that intercepts every API request. It denies access by default and relies on the Policy Engine for decisions.
*   **Policy Engine (PE):** Evaluates every request against real-time context (VPN detection, Geo-location, Time-Windows, Business Hours) before granting access.
*   **Policy Administration Point (PAP):** A dynamic Admin Control Plane that allows real-time manipulation of Attribute-Based Access Control (ABAC) policies.

**2. Cryptographic Implementation**
*   **Streaming AES-256-GCM:** Instead of buffering large files into memory, the system uses Node.js `busboy` to stream data directly into AES-256-GCM cipher streams. This provides Authenticated Encryption with Associated Data (AEAD) to prevent "Bit-Flipping" attacks.
*   **RSA Key Wrapping:** Each file is encrypted with a unique, randomly generated AES-256 key. This symmetric key is then encrypted (wrapped) using the server's RSA-2048/4096 public key.
*   **Data Integrity Handshake:** File downloads require a multi-stage decryption handshake, demanding a fresh TOTP MFA code to release the decryption key payload.

**3. Context-Aware Access & Authentication**
*   **Authentication:** Uses stateful JWTs with Session Pinning and Speakeasy-based TOTP for Multi-Factor Authentication.
*   **Risk-Based Authentication (RBA):** The system continuously calculates a "Risk Score". If the score exceeds a dynamic threshold, the system triggers a "Step-Up Challenge", forcing the user to provide a fresh TOTP code mid-session.
*   **Device Trust Fingerprinting:** Cryptographic hashing of the client's hardware and browser signature. Requests from low-trust devices are heavily penalized.
*   **Impossible Travel Detection:** The system logs geographic data. If a user logs in from New York and 5 minutes later attempts an upload from London, the request is flagged as anomalous.

**4. Forensic Logging (HMAC Audit Chain)**
*   All system activities are logged to an `audit_logs` table.
*   To prevent log tampering, the system implements a cryptographic linked chain. Every log entry contains an SHA-512 HMAC hash that includes the `prev_log_hash`. If an attacker alters a database row, the entire chain breaks.

Write the paper using formal academic language, emphasizing how these interconnected systems solve the vulnerabilities found in traditional perimeter-trust cloud storage systems.
```

---

## 3. The "Feature Extension" Prompt
**Use Case:** You want an AI to help you build a brand new feature into the project (e.g., adding a new database table or API route) while maintaining the strict security standards.

*Note: Paste the "Master Context Prompt" first, wait for the AI to acknowledge it, and then send this prompt.*

**Copy this text:**
```text
Based on the Secure Cloud architecture you acknowledged, I want to build a new feature: [INSERT YOUR FEATURE IDEA HERE, e.g., "A visual dashboard chart showing the audit logs"].

Because this is a Zero-Trust application, please provide the implementation steps adhering to these strict rules:
1.  **Security First:** Any new API routes MUST be protected by the `authMiddleware` and `pepMiddleware` gatekeepers.
2.  **Database:** Provide raw MySQL SQL queries for any new tables or alterations. Do not use an ORM like Sequelize or Prisma.
3.  **Frontend:** Keep the UI in Vanilla JavaScript and use the existing Glassmorphism CSS classes. Do not introduce React or Tailwind.
4.  **Audit:** Ensure that any critical action performed by this new feature triggers a log event via `auditService.log()`.

Provide the updated code for the Backend Routes, the Service logic, and the Frontend HTML/JS required to make this work.
```
