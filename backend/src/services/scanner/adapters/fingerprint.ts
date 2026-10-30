import type { ScannerAdapter, ScannerContext, ScanRunResult, ScannerFinding } from '../types.js';
import { request, fingerprintFromHttp } from '../helpers/http.js';

/** Infer likely technologies from response headers and HTML markers. */
function inferTechnologies(body: string, respHeaders: Record<string, string>): string[] {
  const hits = new Set<string>();
  const server = respHeaders['server'];
  if (server) {
    if (/(nginx)/i.test(server)) hits.add('Nginx');
    if (/(apache)/i.test(server)) hits.add('Apache');
    if (/(IIS)/i.test(server)) hits.add('Microsoft IIS');
    if (/(cloudflare)/i.test(server)) hits.add('Cloudflare');
  }
  const poweredBy = respHeaders['x-powered-by'];
  if (poweredBy) {
    if (/php/i.test(poweredBy)) hits.add('PHP');
    if (/express/i.test(poweredBy)) hits.add('Express (Node.js)');
    if (/asp\.net/i.test(poweredBy)) hits.add('ASP.NET');
  }
  const markers: Array<[RegExp, string]> = [
    [/<meta[^>]+name="generator"[^>]+content="wordpress"/i, 'WordPress'],
    [/wp-content|wp-includes/i, 'WordPress'],
    [/__NEXT_DATA__/i, 'Next.js'],
    [/<div id="root">|__NUXT__/i, 'React/JS SPA'],
    [/drupal/i, 'Drupal'],
    [/joomla/i, 'Joomla'],
    [/jquery/i, 'jQuery'],
    [/bootstrap/i, 'Bootstrap'],
  ];
  for (const [re, label] of markers) {
    if (re.test(body)) hits.add(label);
  }
  return Array.from(hits).slice(0, 20);
}

export const fingerprintAdapter: ScannerAdapter = {
  name: 'fingerprint',
  description: 'Identifies web server, frameworks and other technologies.',
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
            title: 'Fingerprinting failed',
            description: `Could not retrieve the target for fingerprinting: ${String(err)}`,
            cweId: null,
            severity: 'info',
            confidence: 'possible',
            evidence: String(err),
          },
        ],
        artifacts: { error: String(err) },
      };
    }

    const headerTech = fingerprintFromHttp(resp);
    const technologies = inferTechnologies(resp.body, resp.headers);
    artifacts.headers = headerTech;
    artifacts.technologies = technologies;

    if (technologies.length) {
      findings.push({
        title: 'Identified technologies',
        description: `Detected ${technologies.join(', ')} from response headers and page markers.`,
        cweId: null,
        severity: 'info',
        confidence: 'possible',
        evidence: `technologies: ${technologies.join(', ')}`,
        references: ['https://nvd.nist.gov/'],
      });
    } else {
      findings.push({
        title: 'No technologies fingerprinted',
        description: 'No well-known technology markers were identified from the response.',
        cweId: null,
        severity: 'info',
        confidence: 'possible',
      });
    }

    return { findings, artifacts };
  },
};