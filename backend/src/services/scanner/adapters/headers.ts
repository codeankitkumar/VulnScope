import type { ScannerAdapter, ScannerContext, ScanRunResult, ScannerFinding } from '../types.js';
import { request } from '../helpers/http.js';

const REQUIRED_HEADERS: Array<{ name: string; why: string; cwe: string; remediation?: string }> = [
  {
    name: 'strict-transport-security',
    why: 'Missing HSTS header allows downgrade attacks and cookie exposure over plain HTTP.',
    cwe: 'CWE-319',
    remediation:
      'Send `Strict-Transport-Security` (e.g. `max-age=31536000; includeSubDomains`) on all HTTPS responses.',
  },
  {
    name: 'content-security-policy',
    why: 'Missing Content-Security-Policy allows the browser to load scripts from untrusted sources (XSS risk).',
    cwe: 'CWE-693',
    remediation:
      'Define a restrictive `Content-Security-Policy` header. Start with `default-src \'self\'` and tighten iteratively.',
  },
  {
    name: 'x-content-type-options',
    why: 'Missing X-Content-Type-Options permits MIME type sniffing that can lead to reflected XSS.',
    cwe: 'CWE-693',
    remediation: 'Send `X-Content-Type-Options: nosniff` on responses that carry user content.',
  },
  {
    name: 'x-frame-options',
    why: 'Missing X-Frame-Options allows the page to be embedded in a clickjacking frame.',
    cwe: 'CWE-1021',
    remediation: 'Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) or use CSP `frame-ancestors`.',
  },
  {
    name: 'referrer-policy',
    why: 'Missing Referrer-Policy may leak sensitive URL parameters to third parties.',
    cwe: 'CWE-200',
    remediation: 'Send `Referrer-Policy: strict-origin-when-cross-origin`.',
  },
];

export const headersAdapter: ScannerAdapter = {
  name: 'http-headers',
  description: 'Checks for common HTTP security headers and cookie flags.',
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
            title: 'Web endpoint unreachable',
            description: `The web target could not be reached for header inspection: ${String(err)}`,
            cweId: null,
            severity: 'info',
            confidence: 'confirmed',
          },
        ],
        artifacts: { error: String(err) },
      };
    }

    artifacts.response = {
      status: resp.status,
      headers: resp.headers,
      redirects: resp.redirects,
      finalUrl: resp.finalUrl,
    };

    for (const h of REQUIRED_HEADERS) {
      if (!resp.headers[h.name]) {
        findings.push({
          title: `${h.name.toUpperCase()} header is missing`,
          description: h.why,
          cweId: h.cwe,
          severity: 'medium',
          confidence: 'confirmed',
          evidence: `HTTP ${resp.status} for ${target.host}; header "${h.name}" absent from response.`,
          remediation: h.remediation,
          references: ['https://owasp.org/www-project-secure-headers/'],
        });
      } else {
        findings.push({
          title: `${h.name.toUpperCase()} header present`,
          description: `The ${h.name} header was returned.`,
          cweId: null,
          severity: 'info',
          confidence: 'confirmed',
          evidence: `${h.name}: ${resp.headers[h.name]}`,
        });
      }
    }

    // Cookie security check.
    const setCookie = resp.headers['set-cookie'];
    if (setCookie) {
      const insecure = /;\s*[^;]*\bSecure\b/i.test(setCookie) === false;
      const noHttpOnly = /;\s*HttpOnly/i.test(setCookie) === false;
      if (insecure || noHttpOnly) {
        findings.push({
          title: 'Cookies set without required security flags',
          description:
            'Session cookies should be set with the Secure, HttpOnly and SameSite attributes to reduce hijacking and CSRF risk.',
          cweId: 'CWE-614',
          severity: 'medium',
          confidence: 'confirmed',
          evidence: `Set-Cookie: ${setCookie}`,
          remediation:
            'Set cookies with `Secure; HttpOnly; SameSite=Lax (or Strict)` attributes.',
          references: ['https://owasp.org/www-community/controls/SecureFlag'],
        });
      }
    }

    return { findings, artifacts };
  },
};