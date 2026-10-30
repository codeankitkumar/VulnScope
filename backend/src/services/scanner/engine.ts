import type { Target } from '../../types/index.js';
import type { ScannerAdapter, ScannerContext, ScanRunResult } from './types.js';
import { headersAdapter } from './adapters/headers.js';
import { tlsAdapter } from './adapters/tls.js';
import { fingerprintAdapter } from './adapters/fingerprint.js';
import { owaspAdapter } from './adapters/owasp.js';
import { nmapAdapter } from './adapters/nmap.js';
import { zapAdapter } from './adapters/zap.js';

type ScanType = 'quick' | 'full';
type ScanMode = 'passive' | 'active';

export interface EngineResult {
  findings: ScanRunResult['findings'];
  artifacts: Record<string, unknown>;
  executed: string[];
  skipped: Array<{ name: string; reason: string }>;
}

const allAdapters: ScannerAdapter[] = [
  headersAdapter,
  tlsAdapter,
  fingerprintAdapter,
  owaspAdapter,
  nmapAdapter,
  zapAdapter,
];

/**
 * Run the appropriate safe adapters for a target. Quick scans run web-only
 * passive checks; full scans add ZAP active-safe checks and Nmap discovery.
 */
export async function runScanEngine(
  target: Target,
  scanId: string,
  type: ScanType,
  mode: ScanMode,
): Promise<EngineResult> {
  const results: EngineResult = { findings: [], artifacts: {}, executed: [], skipped: [] };
  const context: ScannerContext = { id: scanId, target, mode, type };

  // Select adapters by target kind and scan type.
  let adapters: ScannerAdapter[];
  if (target.kind === 'web') {
    adapters = [headersAdapter, tlsAdapter, fingerprintAdapter, owaspAdapter];
    if (type === 'full') adapters.push(zapAdapter);
  } else {
    adapters = [nmapAdapter];
    if (type === 'full') adapters.push(zapAdapter);
  }

  for (const adapter of adapters) {
    const availability = await adapter.isAvailable(target);
    if (!availability.available) {
      results.skipped.push({ name: adapter.name, reason: availability.reason ?? 'not available' });
      results.artifacts[adapter.name] = { skipped: availability.reason };
      continue;
    }
    try {
      const run = await adapter.scan(context);
      results.executed.push(adapter.name);
      results.findings.push(...run.findings);
      results.artifacts[adapter.name] = run.artifacts;
    } catch (err) {
      results.skipped.push({ name: adapter.name, reason: String(err) });
      results.artifacts[adapter.name] = { error: String(err) };
    }
  }

  return results;
}