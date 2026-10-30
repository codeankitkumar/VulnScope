import { getDb } from '../db/index.js';
import { newId } from '../utils/ids.js';
import { AppError } from '../utils/http.js';
import type { Finding, PublicUser, Scan } from '../types/index.js';
import { assertProjectAccess } from './project.service.js';
import { getTargetById, assertScanAllowed } from './target.service.js';
import { runScanEngine } from './scanner/engine.js';
import { toReferences } from './scanner/types.js';
import { computeRisk } from './risk.service.js';
import { nvd } from './nvd.service.js';
import { assistant } from './ai.service.js';
import { recordAudit } from './audit.service.js';

export async function getScanById(id: string): Promise<Scan | undefined> {
  const rows = await getDb()('scans').where({ id }).limit(1);
  return rows[0] as Scan | undefined;
}

export async function listScansForProject(user: PublicUser, projectId: string): Promise<Scan[]> {
  await assertProjectAccess(user, projectId);
  return (await getDb()('scans').where({ projectId }).orderBy('createdAt', 'desc')) as Scan[];
}

export interface CreateScanInput {
  targetId: string;
  type: 'quick' | 'full';
  mode: 'passive' | 'active';
}

/**
 * Schedule a scan. The scan is validated (own project, ownership + allowlist),
 * queued, then executed. Safety gates are enforced before execution.
 */
export async function createScan(user: PublicUser, input: CreateScanInput): Promise<Scan> {
  const target = await getTargetById(input.targetId);
  if (!target) throw new AppError(404, 'Target not found');
  const project = await assertProjectAccess(user, target.projectId);
  await assertScanAllowed(target);

  const scan: Scan = {
    id: newId(),
    targetId: target.id,
    projectId: target.projectId,
    type: input.type,
    mode: input.mode,
    status: 'queued',
    startedAt: null,
    finishedAt: null,
    summary: null,
    error: null,
    createdById: user.id,
    trigger: 'manual',
    createdAt: new Date().toISOString(),
  };
  await getDb()('scans').insert({ ...scan, createdAt: new Date() });
  await recordAudit({
    actorId: user.id,
    action: 'scan.create',
    entity: 'scan',
    entityId: scan.id,
    metadata: { targetId: target.id, type: scan.type, mode: scan.mode, project: project.name },
  });

  return executeScan(scan, user);
}

export async function executeScan(scan: Scan, byUser?: PublicUser): Promise<Scan> {
  const target = (await getTargetById(scan.targetId))!;
  await getDb()('scans').where({ id: scan.id }).update({ status: 'running', startedAt: new Date() });
  const running: Scan = { ...scan, status: 'running', startedAt: new Date().toISOString() };
  try {
    const result = await runScanEngine(target, scan.id, scan.type, scan.mode);
    const findings: Finding[] = [];
    for (const sf of result.findings) {
      const risk = computeRisk({
        cvssScore: sf.cvssScore ?? null,
        assetImportance: target.importance,
        exposure: target.kind === 'web' ? 1 : 0.5,
        exploitAvailability: 0,
        vulnerabilityAgeDays: null,
        businessImpact: target.importance,
        confidence: sf.confidence,
      });
      const baseSev = sf.severity !== 'info' ? sf.severity : risk.severity;
      const severity = baseSev === 'info' ? (risk.score > 0 ? 'low' : 'info') : baseSev;
      findings.push({
        id: newId(),
        scanId: scan.id,
        targetId: target.id,
        projectId: target.projectId,
        title: sf.title,
        description: sf.description,
        cweId: sf.cweId ?? null,
        cveId: sf.cveId ?? null,
        cvssScore: sf.cvssScore ?? null,
        severity,
        confidence: sf.confidence,
        evidence: sf.evidence ?? null,
        remediation: sf.remediation ?? null,
        references: toReferences(sf.references),
        detector: sf.detector ?? 'engine',
        status: 'open',
        createdAt: new Date().toISOString(),
      });
    }
    for (const f of findings) {
      await getDb()('findings').insert({ ...f, createdAt: new Date() });
    }
    for (const [detector, raw] of Object.entries(result.artifacts)) {
      try {
        await getDb()('scan_artifacts').insert({
          id: newId(),
          scanId: scan.id,
          detector,
          raw: typeof raw === 'string' ? raw : JSON.stringify(raw),
          createdAt: new Date(),
        });
      } catch {
        // artifact persistence must never fail a scan
      }
    }
    const summary = `Scan completed. Detectors: ${result.executed.join(', ') || 'none'}. Findings: ${findings.length}.`;
    await getDb()('scans').where({ id: scan.id }).update({ status: 'completed', finishedAt: new Date(), summary, error: null });
    await recordAudit({
      actorId: byUser?.id ?? null,
      action: 'scan.completed',
      entity: 'scan',
      entityId: scan.id,
      metadata: { findings: findings.length, detectors: result.executed },
    });
    return { ...running, status: 'completed', finishedAt: new Date().toISOString(), summary };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await getDb()('scans').where({ id: scan.id }).update({ status: 'failed', finishedAt: new Date(), error: message });
    await recordAudit({ actorId: byUser?.id ?? null, action: 'scan.failed', entity: 'scan', entityId: scan.id, metadata: { error: message } });
    return { ...running, status: 'failed', finishedAt: new Date().toISOString(), error: message };
  }
}

export async function listFindingsForProject(user: PublicUser, projectId: string): Promise<Finding[]> {
  await assertProjectAccess(user, projectId);
  return (await getDb()('findings').where({ projectId }).orderBy('createdAt', 'desc')) as Finding[];
}

export async function listFindingsForScan(user: PublicUser, scanId: string): Promise<Finding[]> {
  const scan = await getScanById(scanId);
  if (!scan) throw new AppError(404, 'Scan not found');
  await assertProjectAccess(user, scan.projectId);
  return (await getDb()('findings').where({ scanId }).orderBy('createdAt', 'asc')) as Finding[];
}

export async function updateFindingStatus(user: PublicUser, findingId: string, status: Finding['status']): Promise<Finding> {
  const finding = (await getDb()('findings').where({ id: findingId }).first()) as Finding | undefined;
  if (!finding) throw new AppError(404, 'Finding not found');
  await assertProjectAccess(user, finding.projectId);
  await getDb()('findings').where({ id: findingId }).update({ status });
  await recordAudit({ actorId: user.id, action: 'finding.status_update', entity: 'finding', entityId: findingId, metadata: { status } });
  return { ...finding, status };
}

/** Enrich a set of findings with NVD CVE details (best-effort, bounded). */
export async function enrichFindingsWithCve(findings: Finding[]): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const f of findings.slice(0, 10)) {
    let record: Awaited<ReturnType<typeof nvd.getCve>> = null;
    try {
      record = f.cveId ? await nvd.getCve(f.cveId) : (await nvd.lookupProduct(f.title, ''))[0] ?? null;
    } catch {
      record = null;
    }
    if (record) {
      out.push({
        ...f,
        cvssScore: f.cvssScore ?? record.cvssV3 ?? record.cvssV2,
        cveId: f.cveId ?? record.id,
        cweId: f.cweId ?? record.cwes[0] ?? null,
        description: f.description ? `${f.description}\n\nNVD: ${record.description}` : record.description,
        references: f.references
          ? JSON.stringify([...JSON.parse(f.references), ...record.references])
          : JSON.stringify(record.references),
      });
    } else {
      out.push(f);
    }
  }
  return out;
}

/** Compute an AI analysis over findings for a project/scan context. */
export async function analyzeFindings(user: PublicUser, projectId: string, question?: string) {
  await assertProjectAccess(user, projectId);
  const findings = await listFindingsForProject(user, projectId);
  const enriched = await enrichFindingsWithCve(findings);
  if (question) return assistant.ask(enriched, question);
  return assistant.explain(enriched, {});
}
