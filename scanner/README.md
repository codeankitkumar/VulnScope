# VulnScope Scanner

An optional, isolated scanner image that bundles:

- **Nmap** – authorized port & service discovery for infrastructure targets.
- **zap-cli** – command-line wrapper for OWASP ZAP.

The primary deployment runs Nmap inside the `backend` container and drives
OWASP ZAP through its REST API (see docker-compose). This image is provided for
teams that want to run scanners in a separate, network-isolated worker.

## Build & run

```bash
docker build -t vulnscope/scanner ./scanner

# Run a safe scan (non-destructive)
docker run --rm vulnscope/scanner '{"host":"203.0.113.10","port":443}'
```