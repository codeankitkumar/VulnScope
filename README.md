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
- 🌐 **Vulnerability scanning** – Nmap port/service discovery, safe-active OWASP ZAP
  web testing, technology fingerprinting, HTTP security-header checks, TLS
  configuration checks, and a basic OWASP Top 10 assessment.
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
| Backend    | Node.js 20, TypeScript, Express, Knex, JWT, bcrypt, node-cron, pdfkit    |
| Database   | PostgreSQL 16 (production, dev, and test)                               |
| Frontend   | React 18, TypeScript, Vite, react-router-dom, nginx                      |
| Scanners   | Nmap, OWASP ZAP (headless REST daemon), Node-based HTTP/TLS/fingerprint  |
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
│       ├── db/        # knex + migrations + seeds
│       ├── config/    # environment loading
│       └── types/     # shared TypeScript types
├── frontend/          # React SPA (dashboard, projects, targets, scans, ...)
├── scanner/           # optional isolated Nmap/zap-cli worker image
├── docs/              # API documentation
└── docker-compose.yml
```

---

## Quick Start (Docker)

```bash
cp .env.example .env       # edit secrets (JWT_SECRET, DB password, etc.)
docker compose up --build
# Frontend:  http://localhost:8080
# Backend:   http://localhost:4000   (health /api/health, Swagger /api/docs)
```

`docker compose up` starts PostgreSQL, OWASP ZAP, the backend (with Nmap), and
the nginx-served frontend. Tables are migrated automatically on backend boot.
Create your first account at `/register`.

## Local Development

### Infrastructure

```bash
docker run -d --name vulnscope-pg \
  -e POSTGRES_USER=vulnscope -e POSTGRES_PASSWORD=vulnscope -e POSTGRES_DB=vulnscope \
  -p 5432:5432 postgres:16-alpine
# create a test database:
docker exec vulnscope-pg psql -U vulnscope -d vulnscope -c "CREATE DATABASE vulnscope_test;"
```

### Backend

```bash
cd backend
cp .env.example .env        # set PGHOST=127.0.0.1 etc.
npm install
npm run migrate             # apply schema
npm run seed                # seed an admin (optional)
npm run dev                 # http://localhost:4000
```

### Frontend

```bash
cd frontend
npm install
npm run dev                 # http://localhost:5173 (proxies /api -> :4000)
```

### Tests

```bash
cd backend
npm test                    # Vitest unit + integration tests (needs the Postgres test DB)
```

---

## Environment Variables

See [.env.example](./.env.example). All secrets are documented there; a real
`.env` is never committed.

---

## API Documentation

Interactive Swagger docs are served at `/api/docs`. A written reference is in
[docs/API.md](./docs/API.md).

---

## How Scanning Safety Works

1. **Registration** – a target is added to a project.
2. **Ownership verification** – a one-time token is generated and delivered
   out-of-band; the target owner must present it plus their contact to verify.
3. **Allowlisting** – only allowlisted, verified targets may be scheduled.
4. **Isolation** – Nmap runs inside the backend container; OWASP ZAP runs in its
   own container. No destructive testing.
5. **Evidence & confidence** – every finding carries evidence and is tagged
   `confirmed` or `possible`; NVD version matches are advisory, never proof.

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