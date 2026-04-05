# Detailed Project Plan: Identity Security Framework for EdTech

## Project Overview

| Field | Details |
|-------|---------|
| **Project ID** | PRJN26-175 |
| **Title** | Design and Development of Identity Security Framework for EdTech |
| **Duration** | 45 Days |
| **Target Audience** | BCA/BSc Students (Cyber Security specialization) |
| **Core Technology Stack** | Python, Flask, Flask-Login, SQLite |
| **Authentication Methods** | Traditional (email/password) + Google OAuth |
| **Second Factor** | TOTP (Google Authenticator) – mandatory initially, optional after 5 logins |
| **Domain** | Cyber Security, Ethical Hacking and Digital Forensics |
| **Context** | EdTech (Educational Technology) |

---

## Executive Summary

This project builds a production‑ready identity security framework for an EdTech platform. Students will learn:

- **Authentication** (verifying identity) vs **Authorization** (granting permissions)
- **Password security** using bcrypt hashing
- **Two‑Factor Authentication (2FA)** with Google Authenticator (TOTP)
- **OAuth 2.0 integration** (Google Login)
- **Role‑Based Access Control** (Student, Teacher, Admin)
- **Brute force protection** (account lockout, IP blacklisting)
- **Admin‑managed whitelists** for student campus IDs and teacher emails
- **Session management** with Flask-Login

The framework aligns with **FERPA** and **COPPA** principles for protecting student data in online learning environments.

---

## 1. Requirements Specification

### 1.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR01 | User registration with email, password, role selection (student/teacher) | High |
| FR02 | Student registration requires a valid **Campus ID** (pre‑approved by admin) | High |
| FR03 | Teacher registration requires an **email** pre‑approved by admin | High |
| FR04 | Admin (pre‑seeded) can manage whitelists: add/remove student Campus IDs and teacher emails | High |
| FR05 | Admin can view all users, change roles, reset 2FA, force password reset | Medium |
| FR06 | All passwords stored using **bcrypt** (salt rounds = 12) | High |
| FR07 | Traditional login with email + password | High |
| FR08 | **Google OAuth login/register** – user can sign in with Google account | High |
| FR09 | After any primary authentication (password or Google), **mandatory 2FA** (TOTP) for new users | High |
| FR10 | **2FA setup** during registration: generate TOTP secret, show QR code, verify one code, generate backup codes | High |
| FR11 | **2FA verification** during login: user enters 6‑digit TOTP code or backup code | High |
| FR12 | **Login counter** – track total successful logins per user | High |
| FR13 | **2FA policy**: After 5 successful logins, user can optionally disable 2FA from settings | High |
| FR14 | If 2FA is disabled, user can re‑enable anytime | Medium |
| FR15 | Backup codes (10 per user) – one‑time use, hashed with bcrypt | High |
| FR16 | Session management: login, logout, session timeout (15 min), secure cookies | High |
| FR17 | Role‑based authorization: Student, Teacher, Admin (see matrix below) | High |
| FR18 | Password change option (available to all logged‑in users) | Medium |
| FR19 | Brute force protection: 5 failed login attempts → account locked for 15 min | High |
| FR20 | Brute force protection for Campus ID registration attempts: 5 failures from same IP → IP blacklisted for 15 min | High |
| FR21 | Brute force protection for TOTP verification: 5 failures → 2FA lockout for 15 min | High |
| FR22 | Admin can view IP blacklist and manually unblock | Low |

### 1.2 Non‑Functional Requirements

| Requirement | Specification |
|-------------|---------------|
| Security | HTTPS in production; cookies `HttpOnly`, `Secure`, `SameSite=Lax` |
| Performance | QR code generation < 500ms; TOTP verification < 100ms |
| Usability | Responsive UI (Tailwind CSS), clear error messages |
| Availability | SQLite for development (can migrate to PostgreSQL for production) |
| Compliance | Aligns with FERPA (role‑based access to student records) |

### 1.3 Role‑Based Access Matrix

| Action | Student | Teacher | Admin |
|--------|---------|---------|-------|
| View own profile | ✅ | ✅ | ✅ |
| View enrolled courses | ✅ | ✅ | ✅ |
| Submit assignments | ✅ | ✅ (as student) | ❌ |
| Grade assignments | ❌ | ✅ (own class) | ✅ |
| Manage course content | ❌ | ✅ | ✅ |
| Manage user whitelists (campus IDs, teacher emails) | ❌ | ❌ | ✅ |
| View all users | ❌ | ❌ | ✅ |
| Reset user 2FA | ❌ | ❌ | ✅ |
| Change user roles | ❌ | ❌ | ✅ |
| Access admin panel | ❌ | ❌ | ✅ |

---

## 2. System Architecture (High‑Level Design)

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Client Browser                       │
└─────────────────────────────┬───────────────────────────────┘
                              │ HTTP/HTTPS
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Flask Application                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Routes    │  │   Session   │  │   OAuth Client      │  │
│  │ (auth, 2FA, │  │ Management  │  │   (Google)          │  │
│  │  admin)     │  │(Flask-Login)│  └─────────────────────┘  │
│  └─────────────┘  └─────────────┘  ┌─────────────────────┐  │
│  ┌─────────────┐  ┌─────────────┐  │   TOTP Engine       │  │
│  │   Forms &   │  │   Utils     │  │   (pyotp)           │  │
│  │  Validation │  │ (QR, backup)│  └─────────────────────┘  │
│  └─────────────┘  └─────────────┘                           │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        Database (SQLite)                     │
│  users | allowed_student_ids | allowed_teacher_emails       │
│  backup_codes | ip_blacklist                                │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Authentication Flow (Traditional + 2FA)

```
User → /login (POST)
         │
         ▼
    [Validate email/password]
         │
         ├── Failure → increment failed_attempts → lock if >=5 → show error
         │
         ▼ Success
    [Check if account locked?] → if locked → show remaining time
         │
         ▼
    [Check is_2fa_required flag?]
         │
         ├── False (2FA disabled) → call login_user() → dashboard
         │
         ▼ True (2FA required)
    [Store user_id in session variable pending_2fa_user_id]
         │
         ▼
    Redirect to /2fa-verify (GET)
         │
         ▼
    User enters TOTP or backup code → POST to /2fa-verify
         │
         ├── Backup code → verify against backup_codes table → mark used
         │
         └── TOTP code → verify with pyotp.TOTP(secret).verify()
         │
         ▼ Success
    [Clear pending_2fa_user_id]
    [Increment login_count]
    [If login_count >= 5 and user wants to disable 2FA later – flag remains True until user manually disables]
    call login_user()
         │
         ▼
    Dashboard
```

### 2.3 Google OAuth Flow with Mandatory 2FA

```
User clicks "Sign in with Google"
         │
         ▼
Redirect to Google consent screen
         │
         ▼
Google returns authorization code → Flask exchanges for access token → gets user info (email, name, google_id)
         │
         ▼
[Check if email exists in users table]
         │
         ├── Yes → user exists → proceed to 2FA verification (if is_2fa_required = True)
         │
         └── No → create new user (role = 'student' by default, login_count=0, is_2fa_required=True)
                    → redirect to /setup-2fa (mandatory setup before dashboard)
         │
         ▼
After 2FA verification (or setup), complete login, increment login_count
```

### 2.4 Registration Flow (Student)

```
Student accesses /register
         │
         ▼
Submits: email, password, campus_id
         │
         ▼
[Check IP blacklist] → if IP blocked → reject with time remaining
         │
         ▼
[Check campus_id exists in allowed_student_ids table]
         │
         ├── No → increment failed_attempts for IP
         │         if failed_attempts >=5 → blacklist IP for 15 min
         │         reject registration
         │
         ▼ Yes
[Check if email already exists] → if yes → reject
         │
         ▼
Hash password with bcrypt
Create user (role='student', login_count=0, is_2fa_required=True)
         │
         ▼
Redirect to /setup-2fa (mandatory)
```

### 2.5 Registration Flow (Teacher)

Similar to student, but checks `allowed_teacher_emails` table instead of campus IDs. Role set to `'teacher'`.

### 2.6 Admin Panel – Whitelist Management

Admin (`28467@yenepoya.edu.in`) can access `/admin/whitelist`:

- **Student Campus IDs**: Add new ID, remove existing, view all.
- **Teacher Emails**: Add new email, remove existing, view all.
- Each addition is validated (no duplicates, format checks).

### 2.7 2FA Optional After 5 Logins – User Control

- After each successful login, `login_count` increments.
- Once `login_count >= 5`, the user sees a **"Disable 2FA"** button in Security Settings.
- Clicking it sets `is_2fa_required = False`. User can now log in without TOTP.
- If user wants to re‑enable, they click **"Enable 2FA"**, which redirects to `/setup-2fa` again (new secret, new backup codes).
- The 5‑login threshold is **not reset** when re‑enabling; it's a permanent achievement.

---

## 3. Database Schema (Low‑Level Design)

### 3.1 Table: `users`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT | |
| email | VARCHAR(100) | UNIQUE NOT NULL | User email (login) |
| password_hash | VARCHAR(255) | NOT NULL | bcrypt hash (for traditional login) |
| google_id | VARCHAR(255) | NULL | Google OAuth unique ID |
| role | VARCHAR(20) | NOT NULL DEFAULT 'student' | student, teacher, admin |
| totp_secret | VARCHAR(32) | NULL | Base32 TOTP secret (for 2FA) |
| is_2fa_required | BOOLEAN | DEFAULT 1 | Whether 2FA is enforced for this user |
| login_count | INTEGER | DEFAULT 0 | Total successful logins (to track 5‑login threshold) |
| failed_attempts | INTEGER | DEFAULT 0 | Consecutive failed login attempts |
| locked_until | DATETIME | NULL | Account lock expiry (after 5 failures) |
| failed_2fa_attempts | INTEGER | DEFAULT 0 | Consecutive failed TOTP attempts |
| locked_2fa_until | DATETIME | NULL | 2FA lock expiry |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | |
| last_login | DATETIME | NULL | |

### 3.2 Table: `backup_codes`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY |
| user_id | INTEGER | FOREIGN KEY REFERENCES users(id) ON DELETE CASCADE |
| code_hash | VARCHAR(255) | NOT NULL (bcrypt hash of 8‑digit code) |
| used | BOOLEAN | DEFAULT 0 |

### 3.3 Table: `allowed_student_ids`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY |
| campus_id | VARCHAR(50) | UNIQUE NOT NULL |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

### 3.4 Table: `allowed_teacher_emails`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY |
| email | VARCHAR(100) | UNIQUE NOT NULL |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

### 3.5 Table: `ip_blacklist`

| Column | Type | Constraints |
|--------|------|-------------|
| id | INTEGER | PRIMARY KEY |
| ip_address | VARCHAR(45) | NOT NULL (supports IPv4 and IPv6) |
| blocked_until | DATETIME | NOT NULL |
| failed_attempts | INTEGER | DEFAULT 0 (count of registration failures) |

---

## 4. Module‑wise Detailed Design (No Code)

### 4.1 Authentication Module (`auth_routes.py`)

| Function | Description |
|----------|-------------|
| `login()` | GET: show login form; POST: validate email/password, handle account lock, increment failed attempts, redirect to 2FA if required, else login. |
| `google_login()` | Redirect to Google OAuth endpoint. |
| `google_callback()` | Handle OAuth callback, create or fetch user, redirect to 2FA verification or setup. |
| `logout()` | End session, clear cookies. |
| `register_student()` | Student registration with campus ID validation, IP blacklist check. |
| `register_teacher()` | Teacher registration with email whitelist validation, IP blacklist check. |
| `setup_2fa()` | GET: generate TOTP secret, create QR code (Base64), show form. POST: verify TOTP, generate backup codes, save to DB, set `is_2fa_required=True`. |
| `verify_2fa()` | GET: show TOTP entry form. POST: verify TOTP or backup code, increment login_count, login user. |
| `disable_2fa()` | POST only, requires `login_count >= 5`, sets `is_2fa_required=False`. |
| `enable_2fa()` | Redirect to `setup_2fa` (regenerates secret and backup codes). |

### 4.2 Admin Module (`admin_routes.py`)

| Function | Description |
|----------|-------------|
| `admin_dashboard()` | Overview of users, whitelist counts, IP blacklist. |
| `manage_student_ids()` | List, add, delete allowed campus IDs. |
| `manage_teacher_emails()` | List, add, delete allowed teacher emails. |
| `manage_users()` | List all users, edit role, reset 2FA (clear totp_secret, set is_2fa_required=True, delete backup codes), force password reset. |
| `view_ip_blacklist()` | List blocked IPs with expiry, manual unblock option. |
| `reset_user_2fa(user_id)` | Admin can reset any user's 2FA (useful if user loses authenticator). |

### 4.3 Profile & Security Module (`profile_routes.py`)

| Function | Description |
|----------|-------------|
| `profile()` | View user info, email, role. |
| `change_password()` | POST: verify old password, hash new password, update. |
| `security_settings()` | Show 2FA status, option to disable/enable (if login_count >=5). |

### 4.4 Utilities (`utils.py`)

| Function | Description |
|----------|-------------|
| `generate_totp_secret()` | Returns random Base32 string (16 chars) using `secrets` module. |
| `get_totp_uri(username, secret, issuer="EdTechApp")` | Returns provisioning URI for QR code. |
| `generate_qr_base64(uri)` | Creates QR code PNG in memory, returns Base64 string for `<img src="data:image/png;base64,...">`. |
| `verify_totp(secret, user_code)` | Uses `pyotp.TOTP(secret).verify(user_code, valid_window=1)`. |
| `generate_backup_codes(count=10, digits=8)` | Returns list of plain codes (strings). |
| `hash_backup_codes(codes)` | Returns list of bcrypt hashes. |
| `check_ip_blacklist(ip)` | Returns `(blocked, remaining_seconds)` based on `ip_blacklist` table. |
| `record_ip_failure(ip)` | Increments failed_attempts for IP; if reaches 5, inserts/updates blacklist with 15 min expiry. |
| `clear_ip_failures(ip)` | Removes IP from blacklist and resets failed attempts. |

### 4.5 Rate Limiting & Brute Force Logic

**Login brute force:**
- On failed password: increment `failed_attempts` for user.
- If `failed_attempts >= 5`, set `locked_until = now + 15 min`.
- On success: reset `failed_attempts = 0`, `locked_until = NULL`.

**2FA brute force:**
- On failed TOTP/backup code: increment `failed_2fa_attempts`.
- If `>=5`, set `locked_2fa_until = now + 15 min`.
- On success: reset to 0.

**Registration IP blacklist:**
- On invalid campus ID or teacher email, call `record_ip_failure(ip)`.
- After 5 failures, IP blacklisted for 15 min.
- All registration attempts from blacklisted IP are rejected until expiry.

---

## 5. Testing Strategy

### 5.1 Unit Tests (Conceptual)

| Test Case | Expected |
|-----------|----------|
| TOTP secret generation → verify correct code | True |
| TOTP verify wrong code | False |
| Backup code generation (10 unique, 8‑digit) | All unique, correct length |
| bcrypt password hash verify | Match |
| Campus ID whitelist lookup | Exists / not exists |
| IP blacklist after 5 failures | IP blocked |

### 5.2 Integration Tests

- **Full traditional registration + 2FA setup + login + TOTP verification** → dashboard.
- **Google OAuth new user** → redirect to 2FA setup → complete → dashboard.
- **Google OAuth existing user** → redirect to 2FA verification → dashboard.
- **After 5 logins, disable 2FA** → next login without TOTP → success.
- **Re‑enable 2FA** → requires new setup.
- **Admin adds campus ID** → student registers with that ID → success.
- **Admin removes campus ID** → student cannot register with that ID.
- **Brute force: 5 wrong passwords** → account locked for 15 min.
- **Brute force: 5 wrong campus IDs from same IP** → IP blacklisted.

### 5.3 Security Tests

| Attack Vector | Mitigation Test |
|---------------|----------------|
| SQL injection | Parameterized queries (SQLAlchemy) → input like `' OR '1'='1` fails |
| XSS | Template auto‑escaping; try `<script>alert(1)</script>` in name field → escaped |
| CSRF | Flask-WTF protects forms |
| Session fixation | Login regenerates session ID |
| Replay attack | TOTP expires after 30 seconds; same code cannot be reused |
| Credential stuffing | 2FA + account lockout |

---

## 6. Documentation Deliverables

| Document | Contents |
|----------|----------|
| **Proposal** | Problem statement, solution overview, EdTech relevance, 2FA & OAuth strategy, timeline. |
| **High‑Level Design (HLD)** | Architecture diagram, component descriptions, database schema overview, authentication/authorization flows, role matrix, state diagrams. |
| **Low‑Level Design (LLD)** | Detailed function specifications (pseudocode), table schemas with indexes, security configurations (bcrypt rounds, cookie settings, rate limits), error handling patterns, logging format. |
| **Final Report** | Introduction, implementation summary (no code), testing results (table of test cases with outcomes), security analysis (threat model and mitigations), future enhancements (e.g., SMS 2FA, WebAuthn). |
| **Presentation Outline** | 15‑slide deck covering problem → architecture → flows → 2FA policy → OAuth → admin panel → demo → security → Q&A. |

---

## 7. Project Timeline (45 Days)

| Phase | Activities | Days |
|-------|------------|------|
| **Phase 1: Initiation & Requirements** | Domain research, requirement finalization, environment setup | 1‑5 |
| **Phase 2: High‑Level Design** | Architecture, database schema, component design, flow diagrams | 6‑10 |
| **Phase 3: Low‑Level Design** | Detailed function specs, security rules, rate limiting logic | 11‑20 |
| **Phase 4: Implementation** | Coding (not included in this plan – but in actual project) | 21‑30 |
| **Phase 5: Testing** | Unit, integration, security tests | 31‑35 |
| **Phase 6: Documentation** | Proposal, HLD, LLD, Final Report, Presentation Outline | 36‑42 |
| **Phase 7: Deployment & Presentation** | Demo environment, rehearsal, final submission | 43‑45 |

*Note: This is the planning phase. Actual coding would follow after this plan is approved.*

---

## 8. Risk Management

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-------------|
| Google OAuth configuration errors | Medium | High | Use environment variables for client ID/secret; test with test OAuth client first |
| User loses Google Authenticator device | Medium | High | Backup codes + admin reset 2FA |
| Time drift causing TOTP failure | Low | Medium | NTP on server + `valid_window=1` |
| IP blacklist blocks legitimate users | Low | Medium | Admin can manually unblock; blacklist expires automatically after 15 min |
| Student uses another student's campus ID | Medium | Medium | Campus IDs are unique and pre‑approved; no two accounts can use same ID |
| Session hijacking | Low | Medium | HttpOnly, Secure, SameSite cookies; HTTPS in production |

---

## 9. Learning Outcomes

Upon completion, students will be able to:

1. **Explain** the difference between authentication and authorization using real EdTech scenarios.
2. **Implement** secure password storage with bcrypt.
3. **Integrate** TOTP‑based two‑factor authentication (Google Authenticator).
4. **Add** OAuth 2.0 login (Google) with mandatory 2FA overlay.
5. **Design** role‑based access control (Student, Teacher, Admin).
6. **Build** admin interfaces for whitelist management and user administration.
7. **Apply** brute force protection (account lockout, IP blacklisting).
8. **Align** security controls with educational privacy laws (FERPA, COPPA).

---

## 10. Next Steps

This detailed plan is now complete and ready for your review. Once you approve, we can:

1. Generate the **full implementation code** (Python, Flask, templates, OAuth config) matching every requirement.
2. Produce the **final documentation** (Proposal, HLD, LLD, Final Report, Presentation Outline) with EdTech context.
3. Create a **demo walkthrough script** and test cases.

**Please confirm that this plan meets all your expectations. If any modifications are needed, let me know before we proceed to code generation.**
