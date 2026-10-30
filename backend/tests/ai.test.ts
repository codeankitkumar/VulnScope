import { describe, it, expect } from 'vitest';
import { assistant } from '../src/services/ai.service.js';
import type { Finding } from '../src/types/index.js';

const now = new Date().toISOString();
const findings: Finding[] = [
  {
    id: 'f1', scanId: 's1', targetId: 't1', projectId: 'p1',
    title: 'HSTS header missing', description: 'The strict-transport-security header was absent.',
    cweId: 'CWE-319', cvssScore: 5.3, severity: 'medium', confidence: 'confirmed',
    evidence: 'GET https://x -> 200; header absent', remediation: 'Send HSTS header.', status: 'open', detector: 'http-headers', createdAt: now,
  },
  {
    id: 'f2', scanId: 's1', targetId: 't1', projectId: 'p1',
    title: 'Potential SQL injection indicator', description: 'Error markers suggest possible injection.',
    cweId: 'CWE-89', severity: 'high', confidence: 'possible', evidence: 'error page shows SQLSTATE', status: 'open', detector: 'owasp-top10', createdAt: now,
  },
];

describe('AI assistant (rule-based)', () => {
  it('produces an executive summary with counts and confidence split', () => {
    const res = assistant.explain(findings, {});
    expect(res.generatedBy).toBe('rules');
    expect(res.sections.some((s) => s.heading === 'Executive summary')).toBe(true);
    const exec = res.sections.find((s) => s.heading === 'Executive summary')!.body;
    expect(exec).toContain('2 finding(s)');
    expect(exec).toContain('confirmed');
    expect(exec).toContain('possible');
  });

  it('references actual evidence in explanations', () => {
    const res = assistant.explain(findings, { findingIds: ['f1'] });
    const body = res.sections.map((s) => s.body).join('\n');
    expect(body).toContain('Send HSTS header.');
    expect(body).toContain('CWE-319');
  });

  it('distinguishes confirmed from possible findings in references', () => {
    const res = assistant.explain(findings, { findingIds: ['f1', 'f2'] });
    const f2ref = res.referencedFindings.find((r) => r.id === 'f2')!;
    expect(f2ref.confidence).toBe('possible');
  });

  it('answers remediation questions', async () => {
    const res = await assistant.ask(findings, 'How do I remediate these?');
    expect(res.answer).toContain('HSTS');
  });

  it('groups related findings by CWE', () => {
    const groups = assistant.groupRelated(findings);
    expect(groups.length).toBeGreaterThanOrEqual(2);
    const cwe319 = groups.find((g) => g.group.startsWith('CWE-319'));
    expect(cwe319).toBeTruthy();
    expect(cwe319!.findings[0].id).toBe('f1');
  });
});
