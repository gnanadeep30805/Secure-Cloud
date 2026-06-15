# Secure Cloud: Enterprise Zero-Trust Storage System

Secure Cloud is a state-of-the-art, high-security file storage and sharing platform built on the principles of **Zero-Trust Architecture (ZTA)**. Unlike traditional systems that trust users once they log in, Secure Cloud operates on the "Never Trust, Always Verify" paradigm, evaluating every single request against real-time context, device integrity, and behavioral heuristics.

---

## 🔒 The 10 Pillars of Security

This project implements a comprehensive security framework across all layers of the application:

1.  **Policy Engine (PE):** A centralized decision-making hub that evaluates global security constraints (time-windows, geo-fencing, and trust thresholds) before granting access.
2.  **Policy Enforcement Point (PEP):** A fail-secure middleware gateway that intercepts every request, ensuring no data is served without explicit verification.
3.  **Policy Administration Point (PAP):** A dedicated Admin Control Plane to manage dynamic security policies, roles, and user attributes in real-time.
4.  **Context-Aware Access Control:** Real-time request enrichment tracking VPN usage, IP reputation, session age, and "Impossible Travel" anomalies.
5.  **Device-Trust & Endpoint Security:** Cryptographic device fingerprinting that assigns a "Trust Score" to each hardware client, preventing access from unauthorized or unknown devices.
6.  **Continuous Verification:** Security context is re-evaluated for every chunk of data uploaded or downloaded, ensuring session integrity throughout the transaction.
7.  **Audit Logging & Monitoring:** A tamper-evident audit chain using SHA-512 HMAC-linked logs, providing forensic-grade visibility into all system activities.
8.  **Fine-Grained Access Control (RBAC + ABAC):** Combines hierarchical Role-Based Access Control (Admin, Editor, Viewer, Guest) with flexible Attribute-Based Access Control (Department-level ownership, Clearance levels).
9.  **Risk-Based Authentication (RBA):** Heuristic-based risk engine that triggers "Step-Up" challenges (TOTP/Email MFA) when suspicious behavior is detected.
10. **Data Link Layer Security:** Advanced AES-256-GCM chunked streaming for storage, paired with RSA-2048 key wrapping to protect encryption keys at rest.

---

## 🚀 Technology Stack

*   **Backend:** Node.js, Express.js
*   **Database:** MySQL (Structured Schema for Security Policies)
*   **Cryptography:** 
    *   **AES-256-GCM:** Authenticated Encryption with Associated Data (AEAD).
    *   **RSA-2048/4096:** Asymmetric key wrapping and digital signatures.
    *   **SHA-512:** Secure hashing for integrity and audit chains.
*   **Authentication:** JWT (Stateful with Session Pinning), Speakeasy (TOTP MFA), QRCode generation.
*   **Frontend:** Vanilla JavaScript (SPA Architecture), Modern CSS3 (Glassmorphism design).

---

## 📂 Project Structure

```text
secure-cloud/
├── config/             # Database & Security Configuration
├── controllers/        # Core logic for Files, Auth, and Admin
├── middleware/         # PEP, ThreatGuard, and RBA logic
├── models/             # Database access objects
├── routes/             # API Route definitions
├── services/           # Security Engines (Policy, ABAC, RBAC, Risk)
├── utils/              # Cryptography, Mail, and Activity helpers
├── frontend/           # SPA Frontend
│   └── public/         # HTML, CSS, and App logic
└── server.js           # Main application entry point
```

---

## 🛠️ Installation & Setup

### Prerequisites
*   Node.js (v16+)
*   MySQL Server (v8.0+)

### 1. Database Configuration
Create a database named `secure_cloud` and configure your credentials in the `.env` file.

### 2. Environment Variables (`.env`)
Ensure your `.env` contains the following critical keys:
```env
DB_HOST=127.0.0.1
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=secure_cloud
DB_PORT=3306

JWT_SECRET=your_jwt_secret
HMAC_SECRET=your_hmac_secret
SECRET_KEY=your_aes_32byte_hex_key
```

### 3. Run the Project
```bash
npm install
npm start
```
*The system will automatically run migrations and seed default security policies on the first boot.*

---

## 📖 Usage Guide

### User Flow
1.  **Signup:** Register an account. You will be presented with a **TOTP QR Code**. Scan this into Google Authenticator.
2.  **Login:** Enter credentials and your 6-digit TOTP code.
3.  **Upload:** Choose between "Plain" or "Encrypted" modes. Encrypted files are streamed directly into AES-256-GCM chunks.
4.  **Download:** To download, you must verify the file's integrity using a fresh TOTP code. For encrypted files, the system performs a multi-stage decryption handshake.

### Admin Flow
1.  **Promotion:** Access to the Admin Panel requires the `admin` role (assignable via DB or existing admin).
2.  **Dashboard:** Navigate to "Admin Panel" to view active ABAC policies.
3.  **Management:** Assign roles to other users by their User ID to control system-wide permissions.

---

## 🏗️ Architecture Deep-Dive

### Event-Driven Security
Secure Cloud uses a **Typed Security Event Bus** (`services/eventBus.js`) that acts as the central nervous system. 
*   Every login, file access, and policy violation emits a typed event.
*   The **Anomaly Detector** (`services/anomalyDetector.js`) listens for these events in the background to detect brute-force attacks or suspicious scanning patterns across different IP addresses.

### Database Schema Highlights
The system relies on several specialized security tables:
*   `abac_policies`: Stores fine-grained attribute rules in JSON format.
*   `audit_logs`: The immutable forensic record of every system decision.
*   `user_roles` & `role_permissions`: The hierarchical backbone of the RBAC system.
*   `risk_scores`: Persistent tracking of user and device behavior over time.

---

## 🌐 API Endpoint Reference

| Category | Endpoint | Method | Description |
| :--- | :--- | :--- | :--- |
| **Auth** | `/api/auth/signup` | POST | Register + Generate TOTP Secret |
| **Auth** | `/api/auth/login` | POST | Verify credentials + TOTP |
| **Auth** | `/api/auth/step-up`| POST | Verify RBA Identity Challenges |
| **Files** | `/api/files/list` | GET | List accessible files (ABAC filtered) |
| **Files** | `/api/files/upload` | POST | AES-GCM Chunked Stream Upload |
| **Files** | `/api/files/download`| GET | Integrity Handshake + Stream Download|
| **Admin** | `/api/admin/policies` | GET | List active ABAC policies |
| **Admin** | `/api/admin/users/:id/role`| POST | Update user role (RBAC) |

---

## 🛡️ Security Mechanisms Details

### AES-256-GCM Streaming
Unlike standard encryption, Secure Cloud uses a streaming buffer. This allows files of any size (GBs) to be encrypted/decrypted with minimal RAM usage while providing built-in integrity checking to prevent "Bit-Flipping" attacks.

### Impossible Travel Detection
The system tracks the geo-location of every request. If a user logs in from New York and 5 minutes later attempts an action from London, the system flags "Impossible Travel" and immediately locks the account.

### HMAC Audit Chain
Every log entry contains an HMAC hash that includes the hash of the *previous* log entry. This creates a linked chain; if an attacker modifies a single log in the database, the entire chain breaks, alerting administrators to the tampering.

---

## 🛠️ Developer Tools & Testing

The project includes several utilities for maintenance and verification:

*   **`test-integration.js`**: A full suite of automated integration tests that simulate the entire PEP/RBAC/ABAC pipeline. Run with `node test-integration.js`.
*   **`promote.js`**: A helper script to quickly promote the first user in the database to the `Admin` role for testing.
*   **`test_admin_panel.js`**: A diagnostic script that verifies the Admin API endpoints by forging a valid administrative JWT.
*   **`utils/rsaKeys.js`**: Utility to regenerate the server's RSA key pair (used for secure key wrapping).

---

## 🎨 UI/UX & Aesthetics

Secure Cloud isn't just about security—it's designed to provide a premium, modern experience.
*   **Rich Aesthetics:** The frontend uses a **Glassmorphism** design language with vibrant gradients and subtle micro-animations.
*   **Responsive Logic:** The Single Page Application (SPA) architecture ensures smooth transitions between the Dashboard, Upload, and Admin pages without page reloads.
*   **Dynamic Typography:** Integrated with Google Fonts (DM Sans) for high readability and a professional enterprise feel.

---

## 💡 Project Philosophy
This project was built to demonstrate that high-level security does not have to come at the cost of user experience. By automating complex cryptographic handshakes and context evaluations in the background, we provide an "Invisible Security" layer that protects users without slowing them down.

---

## 📝 License
Proprietary / Enterprise-Grade Security Demo.
Developed as a Comprehensive Zero-Trust Implementation.
