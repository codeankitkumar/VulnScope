import type { ScannerAdapter, ScannerContext, ScanRunResult, ScannerFinding } from '../types.js';
import { request } from '../helpers/http.js';

/**
 * A *safe* basic OWASP Top 10 assessment. Only performs non-destructive
 * checks (response inspection, feature probing). No exploitation.
 */
export const owaspAdapter: ScannerAdapter = {
  name: 'owasp-top10',
  description: 'Basic, non-destructive OWASP Top 10 web checks.',
  isAvailable(target) {
    if (target.kind !== 'web') return { available: false, reason: 'Not a web target' };
    return { available: true };
  },

  async scan(context: ScannerContext): Promise<ScanRunResult> {
    const { target } = context;
    const findings: ScannerFinding[] = [];
    const artifacts: Record<string, unknown> = {};
    const base = /^https?:\/\//i.test(target.host) ? target.host.replace(/\/+$/, '') : `https://${target.host}`;

    let home: Awaited<ReturnType<typeof request>>;
    try {
      home = await request(base);
    } catch (err) {
      return {
        findings: [
          {
            title: 'OWASP assessment could not reach target',
            description: String(err),
            cweId: null,
            severity: 'info',
            confidence: 'possible',
            evidence: base,
          },
        ],
        artifacts: { error: String(err) },
      };
    }
    artifacts.home = { status: home.status, headers: home.headers, url: home.finalUrl };

    const httpOnly = home.finalUrl.startsWith('https://');
    // Passive probes (non-destructive).
    const probes = ['/.git/HEAD', '/.env', '/server-status', '/actuator', '/phpinfo.php', '/wp-config.php.bak'];
    const endpoints: Record<string, number> = {};
    for (const path of probes) {
      try {
        const pr = await request(`${base}${path}`, { timeoutMs: 6000, maxRedirects: 0 });
        endpoints[path] = pr.status;
        if (pr.status === 200 && pr.body) {
          findings.push({
            title: `Potentially exposed file or endpoint: ${path}`,
            description:
              `The path ${path} returned HTTP 200. This may indicate an information disclosure or sensitive file exposure. Non-destructive probe only.`,
            cweId: 'CWE-538',
            severity: 'medium',
            confidence: 'possible',
            evidence: `GET ${base}${path} -> ${pr.status}`,
            remediation:
              'Remove or deny public access to sensitive files and informational endpoints; ensure web server configuration blocks them.',
            references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
          });
        }
      } catch {
        // timeout/connection error — treat as not exposed, no finding
      }
    }

    // HSTS: redirecting HTTP->HTTPS is weak without HSTS (covered by headers adapter).
    if (!httpOnly) {
      findings.push({
        title: 'HTTPS not enforced at application root',
        description:
          'The application did not enforce HTTPS for the root URL. Sensitive traffic could be transmitted in cleartext.',
        cweId: 'CWE-319',
        severity: 'medium',
        confidence: 'possible',
        evidence: `final URL: ${home.finalUrl}`,
        remediation: 'Redirect all HTTP traffic to HTTPS and enable HSTS.',
      });
    }

    // Check for exposed error markers that could leak stack traces.
    const errorMarkers = [
      /stack trace/i,
      /SQLSTATE|PDOException|mysqli_|ORA-\d{5}/i,
      /at [A-Za-z_$]+ \(/,
    ];
    const leakPath = endpoints['/.env'] === 200 ? '/.env' : '/.git/HEAD';
    if (endpoints[leakPath] === 200) {
      // already reported as exposure
    }
    if (home.body && errorMarkers.filter((re) => re.test(home.body)).length > 0) {
      findings.push({
        title: 'Possible error-page information disclosure',
        description:
          'The application response contains markers that may indicate stack traces or database errors are disclosed to users.',
        cweId: 'CWE-209',
        severity: 'low',
        confidence: 'possible',
        remediation:
          'Configure the application and web server to return generic error pages and never expose stack traces, SQL errors, or internal paths.',
      });
    }

    return { findings, artifacts };
  },
};