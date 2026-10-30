import { describe, it, expect } from 'vitest';
import { computeRisk } from '../src/services/risk.service.js';

describe('Risk engine', () => {
  it('classifies a confirmed critical finding as critical', () => {
    const out = computeRisk({
      cvssScore: 9.8,
      assetImportance: 5,
      exposure: 1,
      exploitAvailability: 0.9,
      vulnerabilityAgeDays: 60,
      businessImpact: 5,
      confidence: 'confirmed',
    });
    expect(out.severity).toBe('critical');
    expect(out.score).toBeGreaterThanOrEqual(9);
    expect(out.explanation).toMatch(/critical/i);
  });

  it('downgrades possible findings via confidence penalty', () => {
    const confirmed = computeRisk({
      cvssScore: 6.5, assetImportance: 3, exposure: 1, exploitAvailability: 0.5, vulnerabilityAgeDays: 30, businessImpact: 3, confidence: 'confirmed',
    });
    const possible = computeRisk({
      cvssScore: 6.5, assetImportance: 3, exposure: 1, exploitAvailability: 0.5, vulnerabilityAgeDays: 30, businessImpact: 3, confidence: 'possible',
    });
    expect(possible.score).toBeLessThan(confirmed.score);
  });

  it('yields low/info for benign inputs', () => {
    const out = computeRisk({
      cvssScore: 0, assetImportance: 1, exposure: 0, exploitAvailability: 0, vulnerabilityAgeDays: null, businessImpact: 1, confidence: 'confirmed',
    });
    expect(out.severity).toBe('info');
    expect(out.score).toBeLessThan(0.5);
  });

  it('weights CVSS heavily', () => {
    const high = computeRisk({
      cvssScore: 10, assetImportance: 3, exposure: 1, exploitAvailability: 0, vulnerabilityAgeDays: null, businessImpact: 3, confidence: 'confirmed',
    });
    expect(['high','critical']).toContain(high.severity);
    expect(high.score).toBeGreaterThanOrEqual(6);
  });
});


