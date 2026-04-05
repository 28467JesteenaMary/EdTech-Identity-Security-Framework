# Final Report: Identity Security Framework for EdTech

## 1. Introduction
*   Context on Educational Technology (EdTech) scale breaches.
*   The necessity for identity management complying with FERPA parameters, specifically separating Student footprints from Teacher administrative rights.

## 2. Technology Stack & Framework
*   **Backend & DB:** Python, Flask, SQLite.
*   **Core Security Libraries:** Flask-Login, PyOTP, bcrypt, Authlib, Flask-WTF.
*   **Frontend Representation:** Tailwind CSS implementation for responsive layouts.

## 3. Implementation of Security Algorithms
### 3.1 OAuth & Brute-Force Monitoring
*   Implemented strict 5-lock iterations across multiple vectors: 
*   **Global Login**: Triggers 15-minute global timeouts.
*   **2FA Verification**: Isolated component dropping TOTP requests rapidly.
*   **IP Monitoring**: Records spam `request.remote_addr` connections protecting against automated creation scripts attempting to guess valid `Campus IDs`.

### 3.2 Two-Factor Authentication Lifecycle
*   Employed standard RFC 6238 via Google Authenticator.
*   **Optional Override Rule**: Initially mandatory for all users to ensure safe environments, the platform eventually introduces an option to drop 2FA protection only after a user proves their integrity by clearing 5 successive login sessions.

## 4. Conclusion & Future Enhancements
*   Successfully demonstrated complex web deployment strategies wrapping Google SSO across traditional TOTP architectures targeting school campuses.
*   *Future Integration*: Integrating standard WebAuthn parameter hardware keys to augment standard app-based TOTP.
