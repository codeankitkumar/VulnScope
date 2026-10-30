import type { ScannerAdapter, ScannerContext, ScanRunResult, ScannerFinding } from '../types.js';
import { request } from '../helpers/http.js';

export const tlsAdapter: ScannerAdapter = {
  name: 'tls-config',
  description: 'Inspects TLS/SSL configuration including protocol, certificate and authorization.',
  isAvailable(target) {
    if (target.kind !== 'web') return { available: false, reason: 'Not a web target' };
    return { available: true };
  },

  async scan(context: ScannerContext): Promise<ScanRunResult> {
    const { target } = context;
    const findings: ScannerFinding[] = [];
    const artifacts: Record<string, unknown> = {};

    let resp;
    try {
      resp = await request(target.host);
    } catch (err) {
      return {
        findings: [
          {
            title: 'TLS negotiation failed',
            description: `Could not establish a secure connection to ${target.host}: ${String(err)}`,
            cweId: 'CWE-295',
            severity: 'high',
            confidence: 'confirmed',
            evidence: String(err),
            remediation:
              'Ensure the host serves a valid certificate over TLS 1.2+ and is reachable.',
          },
        ],
        artifacts: { error: String(err) },
      };
    }

    if (!resp.tls) {
      return {
        findings: [
          {
            title: 'No TLS detected',
            description: 'The endpoint did not present a TLS certificate.',
            cweId: 'CWE-319',
            severity: 'info',
            confidence: 'possible',
            evidence: `Plain HTTP response (status ${resp.status}) from ${target.host}.`,
            remediation: 'Serve the application over HTTPS with a valid certificate.',
          },
        ],
        artifacts: { response: { status: resp.status, headers: resp.headers } },
      };
    }

    artifacts.tls = resp.tls;

    // Certificate expiry.
    if (resp.tls.validTo) {
      const validTo = new Date(resp.tls.validTo);
      const daysLeft = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
      if (daysLeft < 0) {
        findings.push({
          title: 'TLS certificate has expired',
          description: `The server certificate expired ${Math.abs(daysLeft)} day(s) ago.`,
          cweId: 'CWE-295',
          severity: 'high',
          confidence: 'confirmed',
          evidence: `valid_to: ${resp.tls.validTo}`,
          remediation: 'Renew and deploy the certificate immediately.',
        });
      } else if (daysLeft < 30) {
        findings.push({
          title: 'TLS certificate expiring soon',
          description: `The server certificate expires in ${daysLeft} day(s).`,
          cweId: 'CWE-398',
          severity: 'low',
          confidence: 'confirmed',
          evidence: `valid_to: ${resp.tls.validTo}`,
          remediation: 'Schedule a certificate renewal before expiry.',
        });
      }
    }

    // Authorization.
    if (!resp.tls.authorized) {
      const reason = resp.tls.selfSigned ? 'The certificate appears self-signed.' : 'The certificate chain is not trusted.';
      findings.push({
        title: 'Untrusted TLS certificate',
        description: reason,
        cweId: 'CWE-295',
        severity: 'high',
        confidence: 'confirmed',
        evidence: `Subject CN: ${resp.tls.subject ?? 'n/a'}; Issuer CN: ${resp.tls.issuer ?? 'n/a'}`,
        remediation:
          'Use a certificate from a public CA (or a properly trusted private CA) and ensure the chain is served.',
      });
    }

    // Protocol level.
    if (resp.tls.protocol === 'TLSv1' || resp.tls.protocol === 'TLSv1.1') {
      findings.push({
        title: 'Deprecated TLS protocol in use',
        description:
          `${resp.tls.protocol} is deprecated and vulnerable to known attacks. Only TLS 1.2 and 1.3 are recommended.`,
        cweId: 'CWE-327',
        severity: 'high',
        confidence: 'confirmed',
        evidence: `negotiated protocol: ${resp.tls.protocol}`,
        remediation: 'Disable TLS 1.0/1.1 and enforce TLS 1.2+ on the server and load balancer.',
      });
    }

    findings.unshift({
      title: 'TLS configuration inspected',
      description:
        `Service negotiates ${resp.tls.protocol ?? 'unknown'} with cipher ${resp.tls.cipherName ?? 'unknown'}. Certificate ${resp.tls.authorized ? 'is trusted' : 'is NOT trusted'}.`,
      cweId: null,
      severity: 'info',
      confidence: 'confirmed',
      evidence: `protocol=${resp.tls.protocol ?? 'n/a'} cipher=${resp.tls.cipherName ?? 'n/a'}`,
    });

    return { findings, artifacts };
  },
};