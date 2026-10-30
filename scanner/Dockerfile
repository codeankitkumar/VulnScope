# ---- VulnScope scanner (optional standalone) ----
# Bundles Nmap and OWASP zap-cli for isolated scanning workloads.
# The primary pipeline uses the backend (with Nmap) + the ZAP REST service.
FROM node:20-alpine
RUN apk add --no-cache nmap py3-pip tzdata bind-tools \
    && pip3 install --no-cache-dir zapcli==0.6.2
WORKDIR /worker
COPY worker.js ./worker.js
COPY package.json ./package.json
RUN npm ci --omit=dev 2>/dev/null || true
ENTRYPOINT ["node", "worker.js"]