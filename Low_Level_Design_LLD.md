# Low-Level Design (LLD) - Identity Security Framework for EdTech

## 1. Introduction
### 1.1. Scope of the document
This document provides a comprehensive technical breakdown of the Identity Security Framework. it covers the internal logic, data structures, security protocols, and interface specifications required to maintain a high-security environment for EdTech users (Students, Teachers, and Admins).

### 1.2. Intended Audience
- Developers and System Architects
- Security Auditors
- EdTech Platform Administrators

### 1.3. System Overview
The framework is a Flask-based identity management system featuring multi-layered authentication:
1.  **Primary**: Email/Password or Google OAuth (SSO).
2.  **Secondary**: Time-based One-Time Passwords (TOTP) and Hardware-bound "Sentinel" challenges.
3.  **Recovery**: Decentralized Shamir Secret Sharing (SSS) for account restoration.

---

## 2. System Design
### 2.1. Application Design
The application follows a modular **Blueprint** architecture:
-   `auth_bp`: Handles Login, Registration, 2FA setup, and Hardware Sentinel binding.
-   `admin_bp`: Manages user whitelists and security overrides.
-   `profile_bp`: Handles user-specific security settings and dashboards.

### 2.2. Process Flow
#### A. Registration Flow
1.  User enters Email/Password and Role.
2.  System validates against `AllowedStudentId` or `AllowedTeacherEmail`.
3.  Upon success, user is forced to `/setup-2fa` to generate a TOTP secret and backup codes.
4.  IP tracking captures registration attempts to prevent brute-force (max 5 attempts before lockout).

#### B. Authentication Flow
1.  **Phase 1**: Credential validation (Password/hash or Google JWT).
2.  **Phase 2**: If 2FA enabled, redirect to `/verify-2fa`.
3.  **Phase 3**: If Sentinel enabled, redirect to `/verify-sentinel` for hardware signature verification.
4.  **Final**: Session establishment via `flask_login`.

### 2.3. Information Flow
1.  **Frontend**: Collects credentials/signatures and sends via POST.
2.  **Controller**: Sanitizes input, queries the SQLite DB using SQLAlchemy ORM.
3.  **Utility Layer**: Performs heavy lifting (Bcrypt comparison, TOTP verification, RSA signature checking).
4.  **Database**: Persists audit logs and updated authentication state (last login, failed attempts).

### 2.4. Components Design
-   **Auth Engine**: Core logic for credential verification.
-   **Sentinel Module**: Manages RSA-based hardware binding (browser TPM simulation).
-   **Quantum Guard**: Implements Lattice-based signatures for audit logs to ensure non-repudiation.
-   **Recovery Agent**: Manages Shamir shards for decentralized secret reconstruction.

### 2.5. Key Design Considerations
-   **Graceful Degradation**: If 2FA app is lost, backup codes are checked. If codes lost, Shamir shards are invoked.
-   **Role-Based Access Control (RBAC)**: Enforced via Flask-Login and custom decorators.

### 2.6. API Catalogue
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/register` | Initial user onboarding and whitelist verification. |
| `POST` | `/verify-2fa` | Validates 6-digit TOTP or 8-digit backup codes. |
| `POST` | `/verify-sentinel` | Validates hardware RSA signatures. |
| `POST` | `/recover-account` | Reconstructs TOTP secret from user-provided shards. |

---

## 3. Data Design
### 3.1. Data Model
| Entity | Key Fields | Purpose |
| :--- | :--- | :--- |
| `User` | `email, password_hash, totp_secret, role` | Primary user identity and security state. |
| `BackupCode` | `user_id, code_hash, used` | One-time recovery values. |
| `IPBlacklist` | `ip_address, blocked_until, attempts` | Brute-force protection metadata. |
| `AuditLog` | `action, user_id, details, pqc_signature` | High-fidelity security event tracking. |

### 3.2. Data Access Mechanism
-   **ORM**: SQLAlchemy for abstracted SQLite queries.
-   **Constraints**: Cascading deletes on backup codes to prevent dangling references.

### 3.3. Data Retention Policies
-   **Audit Logs**: Retained indefinitely (append-only).
-   **Temporary Lockouts**: Expires automatically after 15 minutes.

### 3.4. Data Migration
Uses `db.create_all()` for schema synchronization, with manual pre-seeding scripts for administrative entities.

---

## 4. Interfaces
-   **User Interface**: Responsive HTML5/CSS3 templates using Semantic HTML tags for accessibility.
-   **Sentinel Interface**: JSON-based communication for hardware nonces and signatures.
-   **Admin Interface**: Protected dashboard for managing whitelists and IP lockout overrides.

---

## 5. State and Session Management
-   **Flask-Login**: Manages persistent authenticated sessions via secure cookies.
-   **Transient State**: `pending_2fa_user_id` and `pending_sentinel_user_id` stored in Flask session to bridge multi-step auth without premature login.

---

## 6. Caching
-   **Short-term store**: Flask sessions (server-side signed cookies).
-   **Client-side**: Browser `localStorage` for Sentinel Node IDs and hardware fingerprints.

---

## 7. Non-Functional Requirements
### 7.1. Security Aspects
-   **Password Hashing**: Bcrypt with `rounds=12`.
-   **IP Protection**: Automatic temporal lockout based on adaptive failure thresholds.
-   **PQC Simulation**: Lattice-based signatures on audit logs for future-proofing against quantum threats.

### 7.2. Performance Aspects
-   **Database**: SQLite for development efficiency; minimal latency for local identity checks.
-   **Cryptography**: Optimized RSA and SSS implementations to ensure handshake under 500ms.

---

## 8. References
-   **Flask Documentation**: Web framework standards.
-   **Authlib**: OAuth 2.0 and Google SSO integration.
-   **PyOTP/Bcrypt**: Industry standard authentication libraries.
-   **PyCryptodome**: Low-level cryptographic primitives.

