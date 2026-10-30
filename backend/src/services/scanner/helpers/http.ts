import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  url: string;
  finalUrl: string;
  redirects: number;
  tls?: {
    protocol: string | null;
    cipherName: string | null;
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    selfSigned: boolean | null;
    authorized: boolean;
  };
  timingMs: number;
}

export interface HttpOptions {
  method?: string;
  timeoutMs?: number;
  maxRedirects?: number;
  headers?: Record<string, string>;
}

function normalizeUrl(raw: string): string {
  if (/^https?:\/\//i.test(raw)) return raw;
  return `https://${raw}`;
}

/**
 * Perform an HTTP(S) GET with redirect following and TLS inspection.
 * Returns structured response including security-relevant metadata.
 */
export function request(rawUrl: string, options: HttpOptions = {}): Promise<HttpResponse> {
  const timeoutMs = options.timeoutMs ?? 10000;
  const maxRedirects = options.maxRedirects ?? 3;
  const method = options.method ?? 'GET';
  const start = Date.now();

  return new Promise((resolve, reject) => {
    let redirects = 0;

    function go(urlString: string): void {
      let url: URL;
      try {
        url = new URL(normalizeUrl(urlString));
      } catch (err) {
        reject(new Error(`Invalid URL ${urlString}`));
        return;
      }
      const isHttps = url.protocol === 'https:';
      const lib = isHttps ? https : http;

      const req = lib.request(
        url,
        {
          method,
          headers: {
            'User-Agent': 'VulnScope-Scanner/0.1 (+authorized-assessment)',
            Accept: '*/*',
            ...options.headers,
          },
          timeout: timeoutMs,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
          }

          if (status >= 300 && status < 400 && headers.location && redirects < maxRedirects) {
            res.resume();
            redirects += 1;
            try {
              go(new URL(headers.location, url).toString());
            } catch (err) {
              reject(err);
            }
            return;
          }

          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf8');
            const socket = res.socket as unknown as {
              getPeerCertificate?: (detailed?: boolean) => Record<string, unknown> & {
                subject?: Record<string, string>;
                issuer?: Record<string, string>;
                valid_from?: string;
                valid_to?: string;
              };
              authorized?: boolean;
            };
            let tls: HttpResponse['tls'];
            if (isHttps && socket.getPeerCertificate) {
              const cert = socket.getPeerCertificate(true);
              tls = {
                protocol: res.socket ? (res.socket as unknown as { getProtocol?: () => string | null }).getProtocol?.() ?? null : null,
                cipherName: res.socket ? (res.socket as unknown as { getCipher?: () => { name: string } | null })?.getCipher?.()?.name ?? null : null,
                subject: cert.subject ? cert.subject.CN ?? null : null,
                issuer: cert.issuer ? cert.issuer.CN ?? null : null,
                validFrom: cert.valid_from ?? null,
                validTo: cert.valid_to ?? null,
                selfSigned:
                  cert.subject && cert.issuer
                    ? cert.subject.CN === cert.issuer.CN
                    : null,
                authorized: socket.authorized ?? false,
              };
            }
            resolve({
              status,
              headers,
              body,
              url: urlString,
              finalUrl: url.toString(),
              redirects,
              tls,
              timingMs: Date.now() - start,
            });
          });
          res.on('error', reject);
        },
      );
      req.on('timeout', () => {
        req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
      });
      req.on('error', reject);
      req.end();
    }

    go(rawUrl);
  });
}

/** Extract software fingerprints from common server/technology headers. */
export function fingerprintFromHttp(resp: HttpResponse): Record<string, string[]> {
  const found: Record<string, string[]> = {};
  const server = resp.headers['server'];
  if (server) found.server = [server];
  const poweredBy = resp.headers['x-powered-by'];
  if (poweredBy) found.poweredBy = [poweredBy];
  for (const key of Object.keys(resp.headers)) {
    if (key.startsWith('x-') && !['x-powered-by'].includes(key)) {
      found[key] = [resp.headers[key]];
    }
  }
  return found;
}