# High-Level Design (HLD)

## 1. System Architecture
The application runs as a modular Flask web server leveraging a local SQLite database designed to conform strictly to EdTech paradigms and FERPA principles. 

### 1.1 Core Components
*   **Web Framework:** Flask / Flask-Login (Routing and HTTP cookie management).
*   **Database Interface:** Flask-SQLAlchemy interfacing with `edtech.db`.
*   **OAuth Engine:** Authlib interacting with Google OpenID connectors.
*   **TOTP Engine:** PyOTP validating 6-digit Time-Based codes.
*   **Frontend Representation:** Tailwind CSS injection across HTML Jinja2 templates.

### 1.2 Authentication & Authorization Pathing
*   **Authentication:** Users identify themselves either via email/password or Google OAuth. Both paths terminate into a mandatory 2-Factor check for all users below a 5-login threshold.
*   **Authorization:** The `@admin_required` decorators ensure students physically cannot access whitelisting routes, preventing privilege escalation.

## 2. Security Defense Mechanics
*   **Brute-Force (Login):** Intercepted via `failed_attempts` integers. Locks the account after 5 misses for 15 minutes.
*   **Brute-Force (Registration Spam):** Intercepted via `request.remote_addr`. Invalid identifiers bounce the payload and strike the IP address on the `ip_blacklist` table, completely dropping connections after 5 strikes.
*   **Cross-Site Request Forgery (CSRF):** Overlain across all HTML forms via Flask-WTF `{{ csrf_token() }}`.

## 3. Database Schema Overview
### 3.1 Primary Users Table
*   `id` (PK)
*   `email` (VARCHAR(100), UNIQUE)
*   `password_hash` (VARCHAR(256))
*   `google_id` (VARCHAR(256), NULL)
*   `role` (VARCHAR(20), default: 'student')
*   `is_2fa_required` (BOOLEAN, default: True)
*   `login_count` (INTEGER, locks out voluntary 2FA disable until 5)
*   `failed_attempts`, `locked_until` (Used for brute-force tracking)

### 3.2 Auxiliary Protection Tables
*   `ip_blacklist`: Logs failed remote IP hits for 15-minute global timeouts.
*   `allowed_student_ids`: Whitelist registry required for Student Roles to sign up.
*   `allowed_teacher_emails`: Whitelist registry required for Teacher Roles to sign up.
*   `backup_codes`: Single-use bcrypt hashed emergency fallback strings.
