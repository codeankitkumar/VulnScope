# VulnScope API Reference

Base URL: `/api` (Swagger UI served at `/api/docs`).

Authentication is via a `Bearer` JWT: `Authorization: Bearer <token>`.
Roles: `admin`, `analyst`, `viewer` (analyst is the default for new accounts).

Most endpoints enforce **project access**: a user (non-admin) may only access
projects they created.

---

## Health & Docs

| Method | Path          | Description                          |
|--------|---------------|--------------------------------------|
| GET    | `/health`     | Liveness probe                       |
| GET    | `/docs`       | Swagger UI                           |

## Authentication

| Method | Path              | Body                                          | Description      |
|--------|-------------------|-----------------------------------------------|------------------|
| POST   | `/auth/register`  | `{email, name, password(min 8)}`              | Create account   |
| POST   | `/auth/login`     | `{email, password}`                           | Get JWT          |

Rate-limited (20 requests / 15 min) to resist brute force.

## Users (admin)

| Method | Path          | Description            |
|--------|---------------|------------------------|
| GET    | `/users`      | List all users (admin) |
| GET    | `/users/me`   | Own profile            |

## Projects

| Method | Path                       | Description                    |
|--------|----------------------------|--------------------------------|
| POST   | `/projects`                | Create project                 |
| GET    | `/projects`                | List projects for user         |
| GET    | `/projects/:id`            | Project detail                 |
| GET    | `/projects/:id/targets`    | Targets in project             |
| GET    | `/projects/:id/scans`      | Scan history                   |
| GET    | `/projects/:id/findings`   | Findings in project            |
| DELETE | `/projects/:id`            | Delete project (owner/admin)   |

## Targets

| Method | Path | Description |
|--------|------|-------------|
| POST | `/targets` | Register a target: `{projectId, name, kind("web"\|"infrastructure"), host, port?, importance?}` |
| POST | `/targets/:targetId/ownership-token` | Generate a one-time ownership token |
| POST | `/targets/:targetId/verify` | Verify ownership: `{ownershipToken, ownershipOwner}` |
| PUT | `/targets/:targetId/allowlist` | Allowlist for scanning: `{allowlisted}` |
| GET | `/targets/:targetId` | Target detail |

**Scan gate:** a target must be ownership-verified **and** allowlisted before
scans are permitted.

## Scans

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scans` | Run a scan: `{targetId, type("quick"\|"full"), mode("passive"\|"active")}` |
| GET | `/scans/:scanId` | Scan detail |
| GET | `/scans/:scanId/findings` | Findings for a scan |
| GET | `/scans/:scanId/artifacts` | Raw detector artifacts |
| PATCH | `/scans/findings/:findingId/status` | Update status: `{status}` (open \| in_progress \| remediated \| false_positive) |

## CVE Intelligence (NVD)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/cve/:cveId` | Fetch a CVE record (cached) |
| POST | `/cve/search` | Search NVD: `{keyword}` |

## AI Assistant

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ai/analyze` | Explain/summarize findings or answer a question: `{projectId, question?}` |
| POST | `/ai/group` | Group related findings: `{projectId}` |
| POST | `/ai/cve-enrich` | Enrich findings with CVE data: `{projectId}` |

Responses always reference scan evidence and mark `confirmed` vs `possible`.

## Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Analytics (assets, scans, severity distribution, risk trend, remediation progress) |

## Reports

| Method | Path | Description |
|--------|------|-------------|
| GET | `/reports/scan/:scanId` | Download PDF report for a scan |
| GET | `/reports/project/:projectId` | Report listing convenience |

## Audit (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/audit` | Recent audit log entries |

---

## Example: end-to-end authorized scan

```bash
# 1) register & login
TOKEN=$(curl -s -X POST localhost:4000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","name":"A","password":"Password123!"}' \
  | jq -r .token)

# 2) create project
PROJECT=$(curl -s -X POST localhost:4000/api/projects -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Eng"}' | jq -r .project.id)

# 3) register target
TARGET=$(curl -s -X POST localhost:4000/api/targets -H "Authorization: Bearer $TOKEN" \
  -d "{\"projectId\":\"$PROJECT\",\"name\":\"App\",\"kind\":\"web\",\"host\":\"https://example.com\"}" \
  | jq -r .target.id)

# 4) ownership verification
TOK=$(curl -s -X POST localhost:4000/api/targets/$TARGET/ownership-token -H "Authorization: Bearer $TOKEN" | jq -r .ownershipToken)
curl -s -X POST localhost:4000/api/targets/$TARGET/verify -H "Authorization: Bearer $TOKEN" \
  -d "{\"ownershipToken\":\"$TOK\",\"ownershipOwner\":\"sec@owner.com\"}" > /dev/null

# 5) allowlist
curl -s -X PUT localhost:4000/api/targets/$TARGET/allowlist -H "Authorization: Bearer $TOKEN" \
  -d '{"allowlisted":true}' > /dev/null

# 6) run scan
SCAN=$(curl -s -X POST localhost:4000/api/scans -H "Authorization: Bearer $TOKEN" \
  -d "{\"targetId\":\"$TARGET\",\"type\":\"quick\",\"mode\":\"passive\"}" | jq -r .scan.id)

# 7) findings + PDF report
curl -s localhost:4000/api/scans/$SCAN/findings -H "Authorization: Bearer $TOKEN"
curl -s localhost:4000/api/reports/scan/$SCAN -H "Authorization: Bearer $TOKEN" -o report.pdf
```