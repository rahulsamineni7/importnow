# ImportNow Enterprise Cybersecurity & Hardening Specification

This document details the cybersecurity architecture, defense-in-depth measures, and operational security controls implemented in the ImportNow web platform.

---

## 1. Threat Model & Mitigations

| Threat | OWASP Category | Mitigation Implemented |
|---|---|---|
| **Cross-Site Scripting (XSS)** | A03:2021 Injection | Strict Content-Security-Policy (CSP) restricting script execution; automated HTML entity encoding for dynamic query parameters and blog rendering. |
| **Clickjacking / UI Redress** | A05:2021 Security Misconfiguration | `X-Frame-Options: DENY` and `frame-ancestors 'none'` in CSP, plus client-side framebusting defense. |
| **MIME Sniffing** | A05:2021 Security Misconfiguration | `X-Content-Type-Options: nosniff` on all static and dynamic responses. |
| **Man-In-The-Middle (MITM)** | A02:2021 Cryptographic Failures | HTTP Strict Transport Security (`HSTS`) with `max-age=63072000`, `includeSubDomains`, and `preload`. |
| **Denial of Service (DoS / DDoS)** | A04:2021 Insecure Design | Sliding-window IP rate limiting (300 req/min per IP in `server.js`, 30 req/s burst 50 in Nginx). |
| **Directory Traversal / LFI** | A01:2021 Broken Access Control | Strict path normalization and path containment verification against `ROOT_DIR`. |
| **Form Flooding & Bot Spam** | A04:2021 Insecure Design | Client-side rate-limiting and anti-bot validation on WhatsApp redirection forms. |
| **Information Disclosure** | A05:2021 Security Misconfiguration | Hiding server tokens (`server_tokens off;`), obfuscated server identification (`WebSecure`). |
| **Supply Chain Tampering** | A06:2021 Vulnerable & Outdated Components | Zero external npm dependencies required for runtime (`server.js`); local vendor mirrors provided for 3D graphics libraries and textures. |

---

## 2. HTTP Security Headers Overview

The following security headers are enforced across Vercel (`vercel.json`), Netlify (`netlify.toml` / `_headers`), Nginx (`nginx.conf`), and Node.js (`server.js`):

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https: blob:; connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self' https://wa.me; frame-ancestors 'none'; upgrade-insecure-requests;
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-XSS-Protection: 0
```

---

## 3. Vulnerability Disclosure & RFC 9116

The application publishes a machine-readable security contact policy at `/.well-known/security.txt` conforming to RFC 9116:

- Contact: `mailto:security@importnow.in`
- Policy: `https://importnow.in/security`
- Preferred Languages: `en, hi, te`

---

## 4. Operational Hardening Guidelines

1. **Static Hosting:**
   - Deploy to Vercel with `vercel.json` or Netlify with `netlify.toml` to automatically enable edge caching and global DDoS absorption.
2. **Containerized Deployment:**
   - Use the included unprivileged Docker container (`docker-compose up -d`) which runs with all Linux capabilities dropped (`cap_drop: ALL`) and read-only container rootfs where applicable.
3. **Zero-Dependency Native Server:**
   - Run `node server.js` for lightweight self-hosted setups with zero external dependencies to eliminate third-party supply-chain compromise vectors.
