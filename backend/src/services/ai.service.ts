import axios from 'axios';
import { config } from '../config/env.js';
import type { Finding } from '../types/index.js';
import { parseReferences } from './scanner/types.js';

export interface ExplainRequest {
  findingIds?: string[];
  question?: string;
}

export interface AssistantResponse {
  answer: string;
  sections: AssistantSection[];
  referencedFindings: Array<{ id: string; title: string; severity: string; confidence: string }>;
  generatedBy: 'rules' | 'llm';
}

export interface AssistantSection {
  heading: string;
  body: string;
}

const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * AI Security Assistant. By default uses a deterministic rule-based engine
 * that always cites real evidence. Optionally calls an LLM provider
 * (USE_EXTERNAL_LLM=true) to enrich explanations.
 */
export class AssistantService {
  explain(findings: Finding[], request: ExplainRequest): AssistantResponse {
    const selected = request.findingIds?.length
      ? findings.filter((f) => request.findingIds!.includes(f.id))
      : findings;

    const sorted = [...selected].sort(
      (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0),
    );

    const sections: AssistantSection[] = [];
    for (const f of sorted) {
      sections.push({
        heading: `${f.title} (${f.severity.toUpperCase()}, ${f.confidence})`,
        body: this.describeFinding(f),
      });
    }

    sections.unshift({ heading: 'Executive summary', body: this.executiveSummary(sorted) });
    sections.push({ heading: 'Recommended remediation priorities', body: this.priorityRecommendation(sorted) });

    const referenced = sorted.map((f) => ({ id: f.id, title: f.title, severity: f.severity, confidence: f.confidence }));
    const answer = `Analyzed ${referenced.length} finding(s). ${this.executiveSummary(sorted)}`;

    return { answer, sections, referencedFindings: referenced, generatedBy: 'rules' };
  }
async ask(findings: Finding[], question: string): Promise<AssistantResponse> {
    const context = findings
      .slice(0, 20)
      .map((f) => `- [${f.severity}] ${f.title} (confidence: ${f.confidence})`)
      .join('\n');

    if (config.ai.useExternalLLM && config.ai.openaiApiKey) {
      const text = await this.callLlm(question, context);
      return {
        answer: text,
        sections: [{ heading: 'Assistant', body: text }],
        referencedFindings: findings.slice(0, 20).map((f) => ({ id: f.id, title: f.title, severity: f.severity, confidence: f.confidence })),
        generatedBy: 'llm',
      };
    }

    const lower = question.toLowerCase();
    let reply: string;
    if (/remedi|fix|how to/.test(lower)) {
      const remediations = findings
        .filter((f) => f.remediation)
        .map((f) => `- ${f.title}: ${f.remediation}`)
        .join('\n');
      reply =
        remediations ||
        'No explicit remediation guidance is stored for the current findings. Consult vendor advisories referenced on each finding.';
    } else if (/priority|which first/.test(lower)) {
      reply = this.priorityRecommendation(findings);
    } else if (/critical/i.test(lower)) {
      const crit = findings.filter((f) => f.severity === 'critical');
      reply =
        crit.length === 0
          ? 'No critical findings are present in the current set.'
          : `Critical findings:\n${crit.map((f) => `- ${f.title}`).join('\n')}`;
    } else {
      reply =
        `I analyzed ${findings.length} finding(s) from the scanned evidence:\n${context}\n\n` +
        'Ask me about remediation, priorities, or specific findings. My answers always reference the actual scan evidence and I mark possible findings as such.';
    }

    return {
      answer: reply,
      sections: [{ heading: 'Assistant', body: reply }],
      referencedFindings: findings.slice(0, 20).map((f) => ({ id: f.id, title: f.title, severity: f.severity, confidence: f.confidence })),
      generatedBy: 'rules',
    };
  }

  groupRelated(findings: Finding[]): Array<{ group: string; findings: Finding[]; rationale: string }> {
    const byCwe = new Map<string, Finding[]>();
    for (const f of findings) {
      const key = f.cweId || 'uncategorized';
      byCwe.set(key, [...(byCwe.get(key) ?? []), f]);
    }
    return Array.from(byCwe.entries()).map(([group, groupFindings]) => ({
      group: group === 'uncategorized' ? 'Uncategorized' : `${group} (${groupFindings[0].title})`,
      findings: groupFindings,
      rationale:
        group === 'uncategorized'
          ? 'Findings without an associated CWE mapped together.'
          : `Grouped by shared weakness identifier ${group}.`,
    }));
  }

  private describeFinding(f: Finding): string {
    const lines: string[] = [];
    lines.push(f.description || 'No description provided.');
    if (f.cveId) lines.push(`Related CVE: ${f.cveId}`);
    if (f.cweId) lines.push(`Weakness: ${f.cweId}`);
    if (f.cvssScore != null) lines.push(`CVSS: ${f.cvssScore}`);
    lines.push(`Confidence: ${f.confidence.toUpperCase()} (${f.confidence === 'confirmed' ? 'verified against scan evidence' : 'possible — requires manual verification'}).`);
    if (f.evidence) lines.push(`Evidence: ${f.evidence}`);
    if (f.remediation) lines.push(`Remediation: ${f.remediation}`);
    const refs = parseReferences(f.references);
    if (refs.length) lines.push(`References: ${refs.join(', ')}`);
    return lines.join('\n');
  }

  private executiveSummary(findings: Finding[]): string {
    if (findings.length === 0) return 'No findings were provided for analysis.';
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) counts[f.severity as keyof typeof counts] += 1;
    const confirmed = findings.filter((f) => f.confidence === 'confirmed').length;
    const possible = findings.length - confirmed;
    return (
      `This assessment identified ${findings.length} finding(s): ${counts.critical} critical, ` +
      `${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} informational. ` +
      `${confirmed} are confirmed against scan evidence and ${possible} are possible issues that require manual verification. ` +
      `Prioritize confirmed critical and high findings first.`
    );
  }

  private priorityRecommendation(findings: Finding[]): string {
    const sorted = [...findings].sort(
      (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0),
    );
    return sorted.length === 0
      ? 'No findings to prioritize.'
      : sorted
          .map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title} — ${f.confidence === 'confirmed' ? 'confirmed' : 'verify before remediation effort'}`)
          .join('\n');
  }

  private async callLlm(question: string, context: string): Promise<string> {
    try {
      const resp = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        {
          model: config.ai.openaiModel,
          messages: [
            {
              role: 'system',
              content:
                'You are VulnScope, a security assistant. Answer using ONLY the provided scan evidence. Distinguish confirmed findings from possible ones. Do not fabricate CVEs.',
            },
            { role: 'user', content: `Evidence:\n${context}\n\nQuestion: ${question}` },
          ],
          temperature: 0.2,
        },
        { headers: { Authorization: `Bearer ${config.ai.openaiApiKey}` }, timeout: 30000 },
      );
      return resp.data?.choices?.[0]?.message?.content ?? 'No response from model.';
    } catch (err) {
      return `The LLM provider could not be reached: ${String(err)}. Falling back to rule-based guidance.`;
    }
  }
}

export const assistant = new AssistantService();