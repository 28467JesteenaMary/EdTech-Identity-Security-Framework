# Project Proposal: Identity Security Framework for EdTech

## 1. Project Overview
* **Project ID:** PRJN26-175
* **Project Title:** Design and Development of Identity Security Framework for EdTech

## 2. Problem Statement
* EdTech platforms frequently suffer data breaches primarily stemming from compromised student credentials and untracked API access.
* Single-factor authentication is insufficient to protect sensitive FERPA-protected Educational Records and fails to meet strict privacy compliance standards.

## 3. Proposed Solution
This project aims to design a comprehensive Identity Security Framework tailored specifically to the Educational domain. It incorporates secure authentication via Google OAuth alongside traditional means, tightly coupled with role-based authorization (Student, Teacher, Admin) to protect student data.

## 4. Security Enhancements
* **Two-Factor Authentication (2FA) Strategy:** Employs TOTP utilizing Google Authenticator. Mandatory setting, with unlocking flexibility after 5 consecutive successful logins.
* **Brute-force Lockdown:** Limits failed log ins to 5 attempts, enforcing a strict 15-minute cool-down period against brute-fore threats.
* **Pre-Approved Whitelists:** Students and Teachers must cross reference assigned parameters like `Campus IDs` overseen by Admins to reduce unpermissioned external spam accounts.
* **IP Threat Blacklisting:** Detects concurrent registration failures and blacklists bad actor IP addresses entirely from the server.
