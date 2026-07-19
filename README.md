# ☁️ Secure Cloud – Zero Trust Secure Data Protection System

<div align="center">

![Node.js](https://img.shields.io/badge/Node.js-Backend-339933?style=for-the-badge&logo=node.js)
![Express.js](https://img.shields.io/badge/Express.js-Framework-000000?style=for-the-badge&logo=express)
![MySQL](https://img.shields.io/badge/MySQL-Database-4479A1?style=for-the-badge&logo=mysql)
![AES-256](https://img.shields.io/badge/Encryption-AES--256--GCM-red?style=for-the-badge)
![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust-blue?style=for-the-badge)
![Research](https://img.shields.io/badge/IEEE-Research%20Project-success?style=for-the-badge)

### 🔒 Secure Data Protection for Cloud Computing using Zero Trust Architecture (ZTA)

**Continuous Verification • Adaptive Authorization • End-to-End Encryption**

</div>

---

# 📖 Overview

**Secure Cloud** is a research-oriented cloud security system designed to provide secure file storage and access using the principles of **Zero Trust Architecture (ZTA)**.

Unlike traditional cloud systems that trust users after login, Secure Cloud continuously verifies every access request based on user identity, device trust, roles, attributes, and risk level before allowing access to protected resources.

The system integrates modern security mechanisms including:

- Zero Trust Architecture (NIST SP 800-207)
- AES-256-GCM Encryption
- JWT Authentication
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- Risk-Based Authentication (RBA)
- Device Fingerprinting
- Secure Audit Logging

This project was developed as part of a research paper on cloud security.

---

# 🎯 Problem Statement

Traditional cloud systems generally authenticate users only once during login. Once authenticated, users often gain broad access to cloud resources, making systems vulnerable to:

- Unauthorized Access
- Insider Threats
- Credential Theft
- Session Hijacking
- Data Leakage
- Privilege Escalation
- Lateral Movement Attacks

Secure Cloud addresses these challenges by implementing a **Zero Trust security model**, where **every request is verified before access is granted**.

---

# ✨ Key Features

## 🔐 Zero Trust Authentication

Every request is validated through:

- Identity Verification
- Role Validation
- Device Verification
- Context Evaluation
- Risk Assessment
- Continuous Authorization

---

## 🛡 Role-Based Access Control (RBAC)

Supports multiple user roles:

- 👑 Admin
- ✏️ Editor
- 👀 Viewer
- 👤 Guest

Each role has predefined permissions for accessing cloud resources.

---

## 📋 Attribute-Based Access Control (ABAC)

Access decisions are made using:

- User Role
- Department
- Time
- Device
- IP Address
- Request Context
- Resource Sensitivity

---

## ⚠️ Risk-Based Authentication (RBA)

The system dynamically evaluates login risks based on:

- Unknown Devices
- Suspicious Login Patterns
- Device Fingerprints
- User Context
- Session Information

High-risk requests require additional verification.

---

## 🔒 AES-256-GCM File Encryption

Files are encrypted before storage using:

- AES-256-GCM
- Random IV Generation
- Authentication Tags
- Streaming Encryption
- Secure Key Management

Benefits:

- Confidentiality
- Integrity
- Authentication

---

## 📂 Secure File Management

Users can:

- Upload Files
- Download Files
- Delete Files
- View File Metadata
- Encrypt Files Automatically
- Verify File Integrity

---

## 📱 Device Fingerprinting

Each login device is identified using:

- Browser Information
- Screen Resolution
- Timezone
- User Agent
- Canvas Fingerprint

This helps detect suspicious device changes.

---

## 📊 Secure Audit Logs

Every important activity is logged, including:

- Login Attempts
- File Uploads
- Downloads
- Access Requests
- Authorization Decisions
- Security Events

---

# 🏗 System Architecture

```
                     Client
                        │
                        ▼
              Authentication Layer
                        │
                        ▼
             Policy Enforcement Point
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
      RBAC Engine   ABAC Engine   Risk Engine
          │             │             │
          └─────────────┼─────────────┘
                        ▼
               Policy Decision Point
                        │
                        ▼
             AES-256-GCM Encryption
                        │
                        ▼
                  Cloud Storage
                        │
                        ▼
                  MySQL Database
```

---

# 🔐 Security Components

## Policy Enforcement Point (PEP)

- Intercepts every API request
- Validates authentication
- Enforces security policies

---

## Policy Decision Point (PDP)

Determines whether access should be:

- Allow
- Deny
- Require Additional Verification

---

## Role-Based Access Control

Assigns permissions based on user roles.

Example:

| Role | Upload | Download | Delete |
|------|----------|------------|-----------|
| Admin | ✅ | ✅ | ✅ |
| Editor | ✅ | ✅ | ❌ |
| Viewer | ❌ | ✅ | ❌ |
| Guest | ❌ | ❌ | ❌ |

---

## Attribute-Based Access Control

Evaluates multiple attributes:

- User Role
- Device
- Login Time
- Department
- Resource Type
- Access Context

---

## Risk Engine

Calculates authentication risk before granting access.

Factors considered:

- New Device
- Multiple Failed Logins
- Suspicious Activity
- Session Behavior

---

# 🛠 Technology Stack

## Frontend

- HTML5
- CSS3
- JavaScript

---

## Backend

- Node.js
- Express.js

---

## Database

- MySQL

---

## Authentication

- JWT
- bcrypt
- Session Management

---

## Security

- AES-256-GCM
- SHA-256
- Zero Trust Policies
- Device Fingerprinting

---

# 📂 Project Structure

```
Secure-Cloud/

│
├── client/
│   ├── css/
│   ├── js/
│   ├── images/
│   └── pages/
│
├── server/
│   ├── config/
│   ├── middleware/
│   ├── routes/
│   ├── controllers/
│   ├── models/
│   ├── services/
│   ├── encryption/
│   └── utils/
│
├── uploads/
├── database/
├── docs/
├── screenshots/
└── README.md
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/gnanadeep30805/Secure-Cloud.git
```

---

## Navigate

```bash
cd Secure-Cloud
```

---

## Install Dependencies

```bash
npm install
```

---

## Configure Environment Variables

Create a `.env` file.

```env
PORT=5000

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=secure_cloud

JWT_SECRET=your_secret_key

AES_SECRET_KEY=your_aes_secret_key
```

---

## Start the Server

```bash
npm start
```

or

```bash
npm run dev
```

---

# 📸 Screenshots

Include screenshots of:

- Login Page
- Dashboard
- File Upload
- File Encryption
- Access Control
- User Management
- Audit Logs

---

# 📊 Research Highlights

- Implements **Zero Trust Architecture (NIST SP 800-207)**
- Continuous Authentication & Authorization
- Hybrid Access Control (RBAC + ABAC + RBA)
- Secure File Encryption using AES-256-GCM
- Device Fingerprinting
- Secure Audit Trail
- Protection against Insider Threats
- Improved Cloud Security Model

---

# 🔬 Future Enhancements

- Multi-Factor Authentication (MFA)
- Behavioral Biometrics
- AI-Based Threat Detection
- Blockchain-Based Audit Logs
- Post-Quantum Cryptography (Kyber & Dilithium)
- Fully Homomorphic Encryption (FHE)
- Machine Learning Risk Engine
- Continuous Behavioral Authentication

---

# 📚 Research Reference

This project is based on the concepts presented in:

**Secure Data Protection for Cloud Computing with Zero Trust Architecture**

The implementation follows the security principles defined in **NIST SP 800-207 (Zero Trust Architecture)** while extending the model with adaptive access control and secure encryption mechanisms.

---

# 🤝 Contributing

Contributions are welcome!

1. Fork the repository

2. Create a new feature branch

```bash
git checkout -b feature-name
```

3. Commit your changes

```bash
git commit -m "Added new feature"
```

4. Push to GitHub

```bash
git push origin feature-name
```

5. Create a Pull Request

---

# ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub.

It helps others discover the project and motivates further development.

---

# 👨‍💻 Author

**Gnana Deep**

🎓 Computer Science Student  
☁️ Cloud Security Researcher  
🔒 Cybersecurity Enthusiast  
💻 Full Stack Developer

---

<div align="center">

## 🔐 Trust Nothing. Verify Everything.

**Secure Cloud demonstrates how Zero Trust Architecture can significantly enhance cloud security through continuous verification, adaptive authorization, and end-to-end encryption.**

Made with ❤️ using Node.js, Express.js, MySQL & Zero Trust Architecture

</div>
