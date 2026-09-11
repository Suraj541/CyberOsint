# Security & Operational Ethics Policy

## 1. Vulnerability Reporting

If you discover a potential security vulnerability in the **Cybersecurity OSINT Intelligence Platform**, please report it responsibly:
- **Email**: `security@cyber-osint.local` (or file a private security advisory via repository tools).
- Please include detailed steps to reproduce, impact assessment, and any proof-of-concept material.
- We commit to acknowledging receipt within 48 hours and providing regular remediation status updates.

---

## 2. Strict OSINT Scope & Legal Compliance

The platform is strictly an **Open-Source Intelligence (OSINT)** platform. It collects only information that is legally and technically public on the internet.

### Prohibited Actions
The system and all its connectors must **never**:
1. Bypass or attempt to bypass authentication mechanisms or access controls.
2. Circumvent paywalls, subscription requirements, or access restrictions.
3. Defeat or solve CAPTCHAs, bot detections, or challenge-response protections.
4. Exploit target websites or systems to obtain data.
5. Harvest credentials, tokens, cookies, or private session identifiers.
6. Access private accounts or scrape private communications.
7. Collect illegally obtained, leaked, or stolen data archives.
8. Evade platform security controls or perform adversarial evasion.

### Compliance Rules
The system must at all times respect:
- Website Terms of Service and `robots.txt` directives where applicable.
- Official API restrictions, quotas, and licensing contracts.
- Intellectual property and copyright guidelines (preserving canonical URLs and metadata instead of duplicating full protected texts).
- Privacy regulations and applicable local/international laws.

---

## 3. Technical Safeguards & Hardening

### SSRF Protection
All outgoing network requests initiated by connectors and fetchers must pass through an SSRF (Server-Side Request Forgery) validation layer:
- **Disallowed IP ranges**: Loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), cloud metadata endpoints (`169.254.169.254`), and multicast ranges.
- **DNS Resolution Pre-check**: Hostnames must be resolved before connection establishment to verify target IP validity.
- **Redirect Boundaries**: HTTP redirects must be inspected at every hop, capped at a maximum of 3 hops, and forbidden from traversing to internal addresses.

### Untrusted Content Sandboxing
Content fetched from external feeds or sources is treated as untrusted:
- Strict content-type verification and maximum payload size limits (default: 10 MB).
- HTML and XML parsing with entity expansion disabled (XXE defense).
- Markdown and text sanitization to prevent script injection in visualization dashboards.

### Secret Management
- Zero hardcoded secrets, API keys, or database credentials.
- All secrets loaded exclusively via environment variables (`.env`).
- Secrets and credential files strictly excluded via `.gitignore`.
