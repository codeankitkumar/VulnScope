import PDFDocument from 'pdfkit';
import type { Finding, Project, Scan, Target, User } from '../types/index.js';
import { parseReferences } from './scanner/types.js';

export interface ReportData {
  project: Project;
  target: Target;
  scan: Scan;
  author: Pick<User, 'name' | 'email'>;
  findings: Finding[];
  generatedAt: string;
  methodology: string;
}

const severityColor: Record<string, string> = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#7b7b7b',
  info: '#0288d1',
};

const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function escapePdf(text: string): string {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Generate an A4 PDF report: executive summary, scope, methodology,
 * findings with evidence / severity / remediation, and distribution.
 */
export function buildPdfReport(data: ReportData): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 48, size: 'A4', bufferPages: true });
  const chunks: Buffer[] = [];
  const finished = new Promise<Buffer>((resolve) => {
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
  });

  const heading = (text: string, size = 18): void => {
    doc.font('Helvetica-Bold').fontSize(size).fillColor('#1a1a2e').text(text);
    doc.moveDown(0.25);
  };
  const body = (text: string): void => {
    doc.font('Helvetica').fontSize(10).fillColor('#333333').text(text);
    doc.moveDown(0.4);
  };
  const kv = (label: string, value: string): void => {
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#1a1a2e').text(`${label}: `, { continued: true });
    doc.font('Helvetica').fillColor('#333333').text(String(value ?? '-'));
  };
  const maybePage = (needed: number): void => {
    if (doc.y > doc.page.height - needed) doc.addPage();
  };

  // Header band
  doc.fillColor('#1a1a2e').rect(0, 0, doc.page.width, 90).fill();
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(24).text('VulnScope', 48, 24);
  doc.font('Helvetica').fontSize(12).text('Vulnerability Assessment Report', 48, 56);
  doc.fillColor('#000000').moveDown(2);

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of data.findings) counts[f.severity as keyof typeof counts] += 1;
  const confirmed = data.findings.filter((f) => f.confidence === 'confirmed').length;
  const ordered = [...data.findings].sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));

  heading('Executive Summary');
  body(
    `This report documents the security assessment of ${data.target.host} (${data.target.name}). ` +
    `A total of ${data.findings.length} finding(s) were identified: ${counts.critical} critical, ` +
    `${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} informational. ` +
    `Of these, ${confirmed} are confirmed against scan evidence; the remainder are possible issues requiring manual verification.`,
  );
  doc.moveDown(0.6);

  heading('Assessment Scope');
  kv('Target', data.target.host);
  kv('Target name', data.target.name);
  kv('Kind', data.target.kind);
  kv('Ownership', data.target.ownershipVerified ? 'Verified' : 'Not verified');
  kv('Allowlisted', data.target.allowlisted ? 'Yes' : 'No');
  kv('Asset importance', String(data.target.importance));
  doc.moveDown(0.6);

  heading('Scan Methodology');
  body(data.methodology);
  kv('Scan id', data.scan.id);
  kv('Scan type', data.scan.type);
  kv('Scan mode', data.scan.mode);
  kv('Trigger', data.scan.trigger);
  kv('Started', data.scan.startedAt ?? '-');
  kv('Finished', data.scan.finishedAt ?? '-');
  doc.moveDown(0.6);

  heading(`Identified Vulnerabilities (${data.findings.length})`);
  if (ordered.length === 0) body('No findings were recorded for this scan.');
  for (const [idx, f] of ordered.entries()) {
    maybePage(140);
    doc.fillColor('#eceff1').rect(48, doc.y, doc.page.width - 96, 4).fill();
    doc.moveDown(0.5);
    heading(`${idx + 1}. ${escapePdf(f.title)}`, 13);
    kv('Severity', f.severity.toUpperCase());
    kv('Confidence', f.confidence.toUpperCase());
    if (f.cvssScore != null) kv('CVSS', String(f.cvssScore));
    if (f.cweId) kv('CWE', f.cweId);
    if (f.cveId) kv('CVE', f.cveId);
    kv('Detector', f.detector);
    doc.moveDown(0.3);
    body(f.description ?? 'No description.');
    if (f.evidence) {
      heading('Evidence', 11);
      body(f.evidence);
    }
    if (f.remediation) {
      heading('Remediation', 11);
      body(f.remediation);
    }
    const refs = parseReferences(f.references);
    if (refs.length) {
      heading('References', 11);
      body(refs.join('\n'));
    }
    doc.moveDown(0.8);
  }

  maybePage(300);
  heading('Vulnerability Distribution');
  const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;
  const keys = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const maxN = Math.max(1, ...keys.map((k) => counts[k]));
  doc.moveDown(0.5);
  for (let i = 0; i < keys.length; i++) {
    doc.font('Helvetica').fontSize(10).fillColor('#333333').text(labels[i], 48);
    doc.fillColor('#eceff1').rect(140, doc.y - 10, 220, 10).fill();
    doc.fillColor(severityColor[keys[i]]).rect(140, doc.y - 10, (220 * counts[keys[i]]) / maxN, 10).fill();
    doc.fillColor('#333333').text(` ${counts[keys[i]]}`, 355, doc.y - 8);
    doc.moveDown(0.4);
  }

  doc.moveDown(1);
  const author = `${data.author.name} <${data.author.email}>`;
  kv('Generated by', author);
  kv('Generated at', data.generatedAt);
  doc.fillColor('#666666').font('Helvetica-Oblique').fontSize(8).text(
    'Generated by VulnScope from authorized, non-destructive scans and NVD intelligence. Software version matches are advisory, not proof of exploitability.',
    48,
    doc.page.height - 60,
    { width: doc.page.width - 96 },
  );

  doc.end();
  return finished;
}