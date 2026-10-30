import type { FindingSeverity } from '../types/index.js';

export interface RiskInput {
  cvssScore: number | null;
  assetImportance: number; // 1..5
  exposure: number; // 0..1 (how exposed the asset is)
  exploitAvailability: number; // 0..1 (0 none, 1 public known exploit)
  vulnerabilityAgeDays: number | null;
  businessImpact: number; // 1..5
  confidence: 'confirmed' | 'possible';
}

export interface RiskOutput {
  score: number; // 0..10 final numeric risk
  severity: FindingSeverity;
  factors: Record<string, number>;
  explanation: string;
}

const clamp = (v: number, lo = 0, hi = 10): number => Math.min(hi, Math.max(lo, v));

/**
 * Transparent, deterministic risk model. Computes a weighted aggregate of
 * CVSS and organizational factors, then maps to a severity band.
 */
export function computeRisk(input: RiskInput): RiskOutput {
  const { cvssScore, assetImportance, exposure, exploitAvailability, vulnerabilityAgeDays, businessImpact, confidence } = input;

  // Normalize CVSS to 0..1 scale (assume base 10).
  const cvss = cvssScore == null ? 0 : clamp(cvssScore, 0, 10) / 10;
  const importNorm = (assetImportance - 1) / 4; // 1..5 -> 0..1
  const impactNorm = (businessImpact - 1) / 4;
  const exposureNorm = clamp(exposure, 0, 1);

  // Vulnerability age: score increases with age (older vulns more likely targeted),
  // capping at ~365 days.
  const age = vulnerabilityAgeDays == null ? 0 : clamp(vulnerabilityAgeDays, 0, 365) / 365;

  const weights = {
    cvss: 0.35,
    importance: 0.15,
    exposure: 0.15,
    exploit: 0.15,
    age: 0.05,
    businessImpact: 0.15,
  };

  const factorScores = {
    cvss: cvss,
    importance: importNorm,
    exposure: exposureNorm,
    exploit: exploitAvailability,
    age,
    businessImpact: impactNorm,
  };

  let score =
    weights.cvss * factorScores.cvss +
    weights.importance * factorScores.importance +
    weights.exposure * factorScores.exposure +
    weights.exploit * factorScores.exploit +
    weights.age * factorScores.age +
    weights.businessImpact * factorScores.businessImpact;

  // Confidence penalty: possible findings are de-rated.
  if (confidence === 'possible') score *= 0.7;

  score = clamp(score * 10, 0, 10);

  let severity: FindingSeverity;
  if (score >= 9) severity = 'critical';
  else if (score >= 7) severity = 'high';
  else if (score >= 4) severity = 'medium';
  else if (score >= 0.5) severity = 'low';
  else severity = 'info';

  const drivers: string[] = [];
  if (cvss >= 0.7) drivers.push(`High CVSS (${cvssScore})`);
  if (exploitAvailability >= 0.7) drivers.push('Public exploit available');
  if (exposureNorm >= 0.7) drivers.push('Internet-exposed');
  if (importNorm >= 0.7) drivers.push('High-importance asset');
  if (impactNorm >= 0.7) drivers.push('High business impact');

  const explanation =
    drivers.length > 0
      ? `Final risk ${severity.toUpperCase()} (${score.toFixed(1)}/10). Drivers: ${drivers.join('; ')}. Confidence: ${confidence}.`
      : `Final risk ${severity.toUpperCase()} (${score.toFixed(1)}/10). Confidence: ${confidence}.`;

  return { score: Number(score.toFixed(2)), severity, factors: { ...factorScores, rawScore: score }, explanation };
}