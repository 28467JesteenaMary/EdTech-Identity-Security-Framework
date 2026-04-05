# Presentation Outline: EdTech Identity Security Pipeline

## Slide 1: Title Slide
*   Title: Design and Development of Identity Security Framework for EdTech
*   Presenter Details & Project ID (PRJN26-175)

## Slide 2: The Problem
*   Credential theft targeting online learning (Canvas, Blackboard analogies).
*   Compliance necessities corresponding to FERPA regulations.

## Slide 3: The Holistic Solution
*   Role-Based Authorization Architecture (Student, Teacher, Admin).
*   Dual-Authentication (OAuth + TOTP overlay).

## Slide 4: Registration Gatekeeping
*   Protecting registrations using pre-seeded Admin Whitelists.
*   Only valid `Campus IDs` and `Email Signatures` permitted.
*   Tracking malicious IP vectors targeting the `register` endpoint.

## Slide 5: The 5-Threshold Logic
*   Diagram tracking the login_count sequence.
*   Why the logic permits users to voluntarily disable 2FA only after hitting thresholds.

## Slide 6: Google OAuth Mapping
*   How Authlib intercepts OpenID connects to extract user details.
*   Handling native 2FA intersections inside standard 3rd party loops.

## Slide 7: Demo Walkthrough Screenshots
*   *(Screenshot: Google Oauth Portal)*
*   *(Screenshot: Admin Dashboard showing IP tables and Whitelists)*
*   *(Screenshot: 2FA Locking error screen)*

## Slide 8: Security Measures Checkup
*   Defending against CSRF, Brute-Force credentials, and Rate Limiting.

## Slide 9: Conclusion & Q&A
*   Summary of protections.
*   Addressing anticipated questions (e.g. SQLite -> PostgreSQL migration, OAuth limitations).
