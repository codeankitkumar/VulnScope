# VulnScope

**AI-Assisted Vulnerability Assessment Platform**

VulnScope is a professional web application that helps security engineers assess
**authorized** web applications and infrastructure, identify security weaknesses,
prioritize vulnerabilities by business risk, and generate remediation reports.

It combines automated scanning (Nmap, OWASP ZAP), NVD CVE intelligence, a
CVSS-based risk engine, a rule-based/LLM-capable security assistant, and PDF
reporting into a single, self-hosted, Docker-deployable platform.

> **Authorized use only.** VulnScope only scans targets that have been explicitly
> added and flagged as *ownership verified* by their registered owner. Destructive
> testing and uncontrolled exploitation are explicitly out of scope.

---

## Highlights

- 🔐 **Target management** – registration, ownership verification, project scoping,
  scan scheduling, scan history.
- 🌐 **Vulnerability scanning** – Nmap port/service discovery, OWASP ZAP passive &
  safe-active web tests, technology fingerprinting, HTTP security-header checks,
  TLS configuration checks, and a basic OWASP Top 10 assessment.
- 🧠 **Vulnerability intelligence** – NVD (National Vulnerability Database) CVE
  retrieval, CWE mapping, CVSS scores, affected-version matching, references and
  remediation advice. Version matches are clearly **not** treated as proof of
  exploitability.
- ⚖️ **Risk prioritization** – a transparent risk engine weighing CVSS, asset
  importance, exposure, exploit availability, vuln age, and business impact to
  classify findings Critical / High / Medium / Low.
- 🤖 **AI Security Assistant** – explains findings, gives remediation steps,
  suggests secure configuration, groups related findings, generates executive
  summaries, and recommends priority order. Output always cites real evidence and
  marks confirmed vs. possible findings.
- 📊 **Dashboard** – asset counts, scan completion, open vulnerabilities, critical
  findings, severity distribution, risk trends, and remediation progress.
- 📄 **PDF reporting** – scope, methodology, findings, evidence, risk ratings,
  remediation, and executive summary.
- 🛡️ **Security & deployment** – JWT auth, role-based access control, API rate
  limiting, bcrypt credential storage, per-target scan isolation (allowlist),
  audit logging, and Docker Compose deployment.

---

## Technology Stack

| Layer      | Technology                                                              |
|------------|-------------------------------------------------------------------------|
| Backend    | Node.js, TypeScript, Express, Knex, JWT, bcrypt, node-cron, pdfkit       |
| Database   | SQLite (dev/test) or PostgreSQL (production)                             |
| Frontend   | React 18, TypeScript, Vite, react-router-dom, plain CSS                  |
| Scanners   | Nmap, OWASP ZAP (headless), Node-based HTTP/TLS/fingerprint checks       |
| CVE data   | NVD API v2 (https://nvd.nist.gov/developers)                             |
| AI         | Built-in rule-based assistant + optional OpenAI-compatible LLM adapter   |
| Deploy     | Docker & Docker Compose                                                  |

---

## Repository Layout

```
VulnScope/
├── backend/           # Express API, DB schema, scanners, services, tests
│   └── src/
│       ├── routes/    # HTTP API routes
│       ├── services/  # business logic (auth, scan, cve, risk, ai, report)
│       ├── middleware/# jwt, rbac, rate-limit, errors, validation
│       ├── db/        # knex + migrations
│       ├── config/    # environment loading
│       └── types/     # shared TypeScript types
├── frontend/          # React SPA (dashboard, targets, scans, findings, etc.)
├── scanner/           # Docker image with Nmap + ZAP worker scripts
├── docs/              # API documentation
└── docker-compose.yml
```

---

## Getting Started (Quick Start with Docker)

```bash
cp .env.example .env        # edit secrets
docker compose up --build
# Frontend:  http://localhost:5173
# Backend:   http://localhost:4000   (Swagger at /api/docs)
```

---

## Local Development

### Backend

```bash
cd backend
cp .env.example .env
npm install
npx knex migrate:latest      # create schema (SQLite by default)
npm run dev
```

### Frontend

```bash
cd frontend
npm install
npm run dev                  # http://localhost:5173
```

### Tests

```bash
cd backend
npm test                     # Vitest unit & integration tests
```

---

## Environment Variables

See [.env.example](./.env.example). All secrets are documented there. A real
`.env` is never committed.

---

## API Documentation

Interactive Swagger docs are served at `/api/docs` when the backend runs. See
[docs/API.md](./docs/API.md) for a written reference.

---

## Security & Deployment Notes

- Scans run in an isolated Docker service with Nmap/ZAP and cannot reach the
  control-plane database directly.
- Only allowlisted, ownership-verified targets are scheduled.
- Every mutating action is written to the audit log.
- Secrets are injected via environment variables; `.env` is gitignored.

---

## Roadmap

- [x] Target management & ownership verification
- [x] Scanner adapters (Nmap, ZAP, headers, TLS, fingerprint, Top 10)
- [x] NVD CVE intelligence
- [x] Risk engine & prioritization
- [x] AI security assistant (rule-based + optional LLM)
- [x] Dashboard analytics
- [x] PDF reporting
- [x] JWT + RBAC + rate limiting + audit logs
- [x] Docker Compose deployment
- [ ] Webhooks & Slack notifications
- [ ] Custom scan policies
- [ ] Retest / regression workflow
- [ ] Expanded CWE mapping and MITRE ATT&CK alignment

---

## License

[MIT](./LICENSE)

## Disclaimer

VulnScope is a security assessment tool intended for use only against systems
you own or are explicitly authorized to test. The maintainers are not
responsible for misuse. Always verify scope and authorization before scanning.