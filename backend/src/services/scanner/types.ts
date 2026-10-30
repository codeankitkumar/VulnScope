import type {
  FindingConfidence,
  FindingSeverity,
  ScanMode,
  Target,
} from '../../types/index.js';

export interface ScannerFinding {
  title: string;
  description: string;
  cweId?: string | null;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  evidence?: string | null;
  remediation?: string | null;
  references?: string[] | null;
  cveId?: string | null;
  cvssScore?: number | null;
  detector?: string;
}

export interface ScannerContext {
  id: string; // scan id
  target: Target;
  mode: ScanMode;
  type: 'quick' | 'full';
}

export interface ScanRunResult {
  findings: ScannerFinding[];
  artifacts: Record<string, unknown>;
}

export interface ScannerAdapter {
  readonly name: string;
  readonly description: string;
  isAvailable(_target: Target): Promise<{ available: boolean; reason?: string }> | { available: boolean; reason?: string };
  scan(context: ScannerContext): Promise<ScanRunResult>;
}

export const toReferences = (items?: string[] | null): string | null =>
  items && items.length ? JSON.stringify(items) : null;

export const parseReferences = (value: string | null): string[] => {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
};
