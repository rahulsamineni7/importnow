# ImportNow — 1:1 Production Replica & Security Hardened Platform

A 1:1 reproduction of the [ImportNow](https://importnow-concept.vercel.app/#home) web application, reverse-engineered with exact visual fidelity, animations, 3D WebGL scenes (Three.js Earth globe & voyage), blog system, quote workflows, and full enterprise-grade cybersecurity protections.

---

## ⚡ Quick Start

### Option 1: Zero-Dependency Node.js Server (Recommended for local testing)
No `npm install` needed! Uses native Node.js:

```bash
cd importnow
node server.js
```
Open **http://localhost:3000** in your browser.

---

### Option 2: Docker Container (Production Hardened)
Runs on an unprivileged, capability-dropped Nginx Alpine container:

```bash
cd importnow
docker-compose up -d --build
```
Open **http://localhost:8080** in your browser.

---

### Option 3: Deploy to Vercel (1:1 with Original)
Simply link the repository or push to Vercel. The included `vercel.json` automatically activates:
- Clean URLs
- Exact caching headers (`Cache-Control: public, max-age=31536000, immutable` on assets)
- Full OWASP Security Headers (CSP, HSTS, X-Frame-Options, etc.)

---

### Option 4: Deploy to Netlify
The included `netlify.toml` and `_headers` configure all security headers and routing automatically.

---

## 🛡️ Cybersecurity Protections Included

1. **Strict Content-Security-Policy (CSP)**:
   - Eliminates unauthorized script injections while enabling legitimate 3D WebGL canvas shaders and Google Fonts.
2. **Anti-Clickjacking (UI Redress Defense)**:
   - `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
3. **MIME Sniffing Prevention**:
   - `X-Content-Type-Options: nosniff`.
4. **Transport Layer Security**:
   - `Strict-Transport-Security` (HSTS) with 2-year lifetime and preload.
5. **DDoS & Flooding Mitigation**:
   - Sliding-window IP rate limiter limiting aggressive scrapers or brute-force requests.
6. **Path Traversal / LFI Protection**:
   - Strict normalization and containment checks preventing directory traversal.
7. **RFC 9116 Compliant Security Directory**:
   - `/.well-known/security.txt` configured with security contact and disclosure policies.
8. **Anti-Fingerprinting**:
   - Obfuscated server identification and disabled banner disclosure.

---

## 📁 File Structure

```
importnow/
├── index.html            # Main one-page experience (#home, #services, #journey, #products, #shanghai, etc.)
├── blog.html             # Blog directory with category pills & search
├── post.html             # Dynamic article reader with table of contents & related posts
├── favicon.svg           # High-resolution brand SVG favicon
├── robots.txt            # Search engine & crawler directives
├── .well-known/
│   └── security.txt      # RFC 9116 vulnerability disclosure policy
├── assets/
│   ├── site.css          # Full design system, typography, responsive styles, animations
│   ├── site.js           # Navigation, dynamic SVGs, mobile menu, tilt effects, quote form
│   ├── globe.js          # Three.js 3D Earth globe with custom shaders, atmosphere & trade routes
│   ├── voyage.js         # Three.js 3D ocean voyage with container ship, port cranes & scroll tracking
│   ├── posts.js          # Complete article database with full text & metadata
│   ├── textures/         # Local mirror of 3D Earth & ocean shader textures
│   └── vendor/           # Local mirror of Three.js ES modules
├── server.js             # Hardened zero-dependency Node.js production server
├── package.json          # Package manifest & npm scripts
├── vercel.json           # Vercel deployment & security configuration
├── netlify.toml          # Netlify configuration
├── _headers              # Netlify/Cloudflare static headers
├── nginx.conf            # Hardened Nginx configuration
├── Dockerfile            # Multi-stage secure Docker container definition
├── docker-compose.yml    # Docker Compose orchestration
└── SECURITY.md           # Enterprise cybersecurity specification
```
