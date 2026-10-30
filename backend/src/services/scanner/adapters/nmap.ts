import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ScannerAdapter, ScannerContext, ScanRunResult, ScannerFinding } from '../types.js';

const execFileAsync = promisify(execFile);

/**
 * Nmap adapter for infrastructure targets (port & service discovery).
 * Runs only the safe, non-destructive default scan (SYN/connect scan, version
 * and OS detection are conservative). Tools that are not installed are
 * reported, not faked.
 */
export const nmapAdapter: ScannerAdapter = {
  name: 'nmap',
  description: 'Nmap port and service discovery for infrastructure targets.',
  isAvailable(_target) {
    // We do a lazily-cached availability check at scan time.
    return { available: true };
  },

  async scan(context: ScannerContext): Promise<ScanRunResult> {
    const { target } = context;
    const findings: ScannerFinding[] = [];
    const artifacts: Record<string, unknown> = {};
    const host = target.host;
    const args = ['-Pn', '-sV', '--open', '-oX', '-', host];
    if (target.port) {
      args.splice(-1, 0, `-p${target.port}`);
    }

    let xml: string;
    try {
      const { stdout } = await execFileAsync('nmap', args, {
        timeout: 120000,
        maxBuffer: 4 * 1024 * 1024,
      });
      xml = stdout;
    } catch (err) {
      const code = (err as { code?: string | number })?.code;
      if (code === 'ENOENT') {
        return {
          findings: [
            {
              title: 'Nmap not available',
              description:
                'The Nmap binary is not installed in the scanner environment. Install Nmap (or run the scanner Docker image which bundles it) to enable port/service discovery.',
              cweId: null,
              severity: 'info',
              confidence: 'possible',
              remediation: 'Install nmap. `docker compose up --build scanner` provides a bundled image.',
            },
          ],
          artifacts: { toolMissing: true },
        };
      }
      return {
        findings: [
          {
            title: 'Nmap scan failed',
            description: `The Nmap scan could not complete: ${String(err)}`,
            cweId: null,
            severity: 'info',
            confidence: 'possible',
            evidence: String(err),
          },
        ],
        artifacts: { error: String(err) },
      };
    }

    artifacts.rawXmlPreview = xml.slice(0, 4000);
    const openPorts = parseNmapOpenPorts(xml);
    artifacts.openPorts = openPorts;

    if (openPorts.length === 0) {
      findings.push({
        title: 'No open ports detected',
        description: `Nmap reported no open ports on ${host}.`,
        cweId: null,
        severity: 'info',
        confidence: 'confirmed',
      });
    } else {
      for (const port of openPorts) {
        const serviceRisk = serviceRiskLevel(port);
        if (serviceRisk) {
          findings.push({
            title: `Potentially risky service exposed: ${port.service || port.port}`,
            description: serviceRisk.description,
            cweId: 'CWE-1035',
            severity: serviceRisk.severity,
            confidence: 'possible',
            evidence: `${port.protocol}/${port.port} ${port.state} ${port.service ?? ''} ${port.version ?? ''}`,
            remediation: serviceRisk.remediation,
          });
        } else {
          findings.push({
            title: `Open port: ${port.port}/${port.protocol}`,
            description: `Service ${port.service ?? 'unknown'} detected.`,
            cweId: null,
            severity: 'info',
            confidence: 'confirmed',
            evidence: `${port.protocol}/${port.port} ${port.service ?? ''} ${port.version ?? ''}`,
          });
        }
      }
    }

    return { findings, artifacts };
  },
};

interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
}

/** Minimal XML parser for nmap -oX output (open ports). */
function parseNmapOpenPorts(xml: string): NmapPort[] {
  const ports: NmapPort[] = [];
  const regex = /<port protocol="([^"]+)" portid="(\d+)">[\s\S]*?<state state="(\w+)"[^>]*\/>[\s\S]*?(?:<service name="([^"]*)"[^>]*?(?:version="([^"]*)")?[^>]*\/>)?/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(xml)) !== null) {
    const state = m[3];
    if (!['open', 'open|filtered'].includes(state)) continue;
    ports.push({
      protocol: m[1],
      port: Number(m[2]),
      state,
      service: m[4] || undefined,
      version: m[5] || undefined,
    });
  }
  // Dedupe by port/protocol
  const seen = new Set<string>();
  return ports.filter((p) => {
    const k = `${p.protocol}/${p.port}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function serviceRiskLevel(port: NmapPort): {
  severity: 'high' | 'medium';
  description: string;
  remediation: string;
} | null {
  const svc = (port.service ?? '').toLowerCase();
  if (['telnet', 'ftp'].includes(svc)) {
    return {
      severity: 'high',
      description: `${svc.toUpperCase()} transmits credentials in cleartext and is commonly targeted.`,
      remediation: 'Disable telnet/FTP; use SSH/SFTP and enforce MFA.',
    };
  }
  if (['snmp', 'rpcbind', 'netbios-ssn', 'microsoft-ds'].includes(svc) || svc.includes('samba')) {
    return {
      severity: 'medium',
      description: `The ${svc || port.port} service is often exposed to attack surfaces and version-based exploitation.`,
      remediation: 'Restrict exposure to these services via firewall allowlists.',
    };
  }
  if (['http', 'https', 'ssl/http', 'ssl/https'].some((s) => svc.includes(s))) {
    return {
      severity: 'medium',
      description: 'A web service is exposed; ensure it is patched and behind the web scan pipeline.',
      remediation: 'Apply patches; run the web scanner adapters against this service.',
    };
  }
  return null;
}