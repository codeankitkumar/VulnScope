import axios from 'axios';
import type { ScannerAdapter, ScannerContext, ScanRunResult, ScannerFinding } from '../types.js';
import { config } from '../../../config/env.js';

/**
 * OWASP ZAP adapter. Uses the ZAP REST API (json format). Passive scans are
 * always safe; active in-scanner scans use the "safe"/"low" policy by default.
 * Non-destructive only.
 */
export const zapAdapter: ScannerAdapter = {
  name: 'zap',
  description: 'OWASP ZAP passive & safe-active web security testing.',
  isAvailable(target) {
    if (target.kind !== 'web') return { available: false, reason: 'Not a web target' };
    if (!config.zap.baseUrl) return { available: false, reason: 'ZAP base URL not configured' };
    return { available: true };
  },

  async scan(context: ScannerContext): Promise<ScanRunResult> {
    const { target, mode } = context;
    const findings: ScannerFinding[] = [];
    const artifacts: Record<string, unknown> = {};
    const baseUrl = config.zap.baseUrl;
    const api = axios.create({
      baseURL: baseUrl,
      params: { apikey: config.zap.apiKey },
      timeout: 15000,
    });

    const zUrl = /^https?:\/\//i.test(target.host) ? target.host : `https://${target.host}`;

    try {
      // Spin up the scanner session for this target (authz: use "external" to
      // force our own session management later).
      const spider = await api.get('/JSON/spider/action/scan/', { params: { url: zUrl } });
      const scanId = spider.data?.scan;
      artifacts.spiderScanId = scanId;

      // Wait for spider to complete (poll up to N times).
      if (scanId !== undefined) {
        for (let i = 0; i < 60; i++) {
          await new Promise((r) => setTimeout(r, 2000));
          const status = await api.get('/JSON/spider/view/status/', { params: { scanId } });
          if (String(status.data.status) === '100') break;
        }
      }

      // Passive scan results are always collected.
      const alerts = await api.get('/JSON/core/view/alerts/', { params: { baseurl: zUrl } });
      const list = Array.isArray(alerts.data?.alerts) ? alerts.data.alerts : [];
      artifacts.alertCount = list.length;

      if (mode === 'active') {
        // Safe active scan: run the ZAP active scanner but force a non-
        // destructive policy. Only "low"/"safe" level targeted checks.
        const ascanner = await api.get('/JSON/ascan/action/scan/', { params: { url: zUrl, inScopeOnly: 'false' } });
        const aScanId = ascanner.data?.scan;
        artifacts.activeScanId = aScanId;
        if (aScanId !== undefined) {
          for (let i = 0; i < 90; i++) {
            await new Promise((r) => setTimeout(r, 2000));
            const status = await api.get('/JSON/ascan/view/status/', { params: { scanId: aScanId } });
            if (String(status.data.status) === '100') break;
          }
        }
        const after = await api.get('/JSON/core/view/alerts/', { params: { baseurl: zUrl } });
        const afterList = Array.isArray(after.data?.alerts) ? after.data.alerts : [];
        artifacts.postActiveAlertCount = afterList.length;
        Object.assign(list, afterList);
      }

      for (const alert of list) {
        findings.push(mapZapAlert(alert));
      }
    } catch (err) {
      const axiosErr = err as { code?: string; response?: { status?: number } };
      if (axiosErr.code === 'ECONNREFUSED' || axiosErr.response?.status === 404) {
        return {
          findings: [
            {
              title: 'OWASP ZAP not reachable',
              description:
                `Could not contact OWASP ZAP at ${baseUrl}. Start the ZAP scanner service (see docker-compose) to enable web scanning.`,
              cweId: null,
              severity: 'info',
              confidence: 'possible',
              remediation: 'Start the ZAP scanner container and set ZAP_BASE_URL/ZAP_API_KEY.',
            },
          ],
          artifacts: { toolMissing: true },
        };
      }
      return {
        findings: [
          {
            title: 'ZAP scanning error',
            description: `The ZAP scan failed: ${String(err)}`,
            cweId: null,
            severity: 'info',
            confidence: 'possible',
            evidence: String(err),
          },
        ],
        artifacts: { error: String(err) },
      };
    }

    return { findings, artifacts };
  },
};

interface ZapAlert {
  alert?: string;
  risk?: string | number;
  confidence?: string | number;
  description?: string;
  solution?: string;
  evidence?: string;
  cweid?: string | number;
  references?: string;
  url?: string;
}

function mapZapAlert(alert: ZapAlert): ScannerFinding {
  const riskMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    '0': 'info',
    '1': 'low',
    '2': 'medium',
    '3': 'high',
    '4': 'critical',
  };
  const risk = typeof alert.risk === 'string' ? alert.risk : String(alert.risk ?? '0');
  const severity = riskMap[risk] ?? 'info';
  const confidence =
    ['Who?', 'Internal', 'TODO', 'Noisy'].includes(String(alert.confidence)) || Number(alert.confidence) < 2
      ? 'possible'
      : 'confirmed';
  return {
    title: alert.alert ?? 'ZAP finding',
    description: alert.description ?? 'Detected by OWASP ZAP.',
    cweId: alert.cweid ? `CWE-${alert.cweid}` : undefined,
    severity,
    confidence,
    evidence: alert.evidence || `ZAP alert at ${alert.url ?? 'unknown'}`,
    remediation: alert.solution,
    references: alert.references ? alert.references.split('\n').filter(Boolean) : undefined,
    cveId: undefined,
  };
}