import { getDb } from '../db/index.js';
import type { PublicUser } from '../types/index.js';
import { listProjectsForUser } from './project.service.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

interface Row {
  n?: number | string;
  severity?: string;
  status?: string;
}

function num(v: number | string | undefined | null): number {
  return Number(v ?? 0);
}

export interface DashboardStats {
  projects: number;
  assets: number;
  completedScans: number;
  totalScans: number;
  openVulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  severityDistribution: Array<{ severity: string; count: number }>;
  riskTrend: Array<{ date: string; count: number }>;
  remediationProgress: { open: number; inProgress: number; remediated: number; falsePositive: number };
}

export async function getDashboardStats(user: PublicUser): Promise<DashboardStats> {
  const projects = await listProjectsForUser(user);
  const projectIds = projects.map((p) => p.id);

  const stats: DashboardStats = {
    projects: projects.length,
    assets: 0,
    completedScans: 0,
    totalScans: 0,
    openVulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    severityDistribution: [],
    riskTrend: [],
    remediationProgress: { open: 0, inProgress: 0, remediated: 0, falsePositive: 0 },
  };

  if (projectIds.length === 0) return stats;

  const targetRow = (await getDb()('targets').whereIn('projectId', projectIds).count<Row[]>('* as n').first()) as Row | undefined;
  stats.assets = num(targetRow?.n);

  const scanStatus = (await getDb()('scans').whereIn('projectId', projectIds).select('status').count<Row[]>('* as n').groupBy('status')) as Row[];
  stats.totalScans = scanStatus.reduce((a, r) => a + num(r.n), 0);
  stats.completedScans = scanStatus.filter((r) => r.status === 'completed').reduce((a, r) => a + num(r.n), 0);

  const findingBySeverity = (await getDb()('findings').whereIn('projectId', projectIds).select('severity').count<Row[]>('* as n').groupBy('severity')) as Row[];
  const sevMap = new Map<string, number>();
  for (const r of findingBySeverity) sevMap.set(r.severity ?? '', num(r.n));
  const counters = stats as unknown as Record<string, number>;
  for (const s of SEVERITIES) counters[s] = sevMap.get(s) ?? 0;
  stats.openVulnerabilities = SEVERITIES.reduce((a, s) => a + (sevMap.get(s) ?? 0), 0);
  stats.severityDistribution = SEVERITIES.map((s) => ({ severity: s, count: sevMap.get(s) ?? 0 }));

  const byStatus = (await getDb()('findings').whereIn('projectId', projectIds).select('status').count<Row[]>('* as n').groupBy('status')) as Row[];
  for (const r of byStatus) {
    const key = r.status as keyof DashboardStats['remediationProgress'];
    if (key in stats.remediationProgress) (stats.remediationProgress as Record<string, number>)[key] = num(r.n);
  }

  stats.riskTrend = await computeRiskTrend(projectIds);
  return stats;
}

/** Risk trend: count of high+critical findings per day (last 14 days). */
async function computeRiskTrend(projectIds: string[]): Promise<Array<{ date: string; count: number }>> {
  const rows = (await getDb()('findings')
    .whereIn('projectId', projectIds)
    .whereIn('severity', ['high', 'critical'])
    .select('createdAt')) as Array<{ createdAt: Date | string }>;

  const byDay = new Map<string, number>();
  for (const r of rows) {
    const key = new Date(r.createdAt).toISOString().slice(0, 10);
    byDay.set(key, (byDay.get(key) ?? 0) + 1);
  }
  const out: Array<{ date: string; count: number }> = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(now.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    out.push({ date: key, count: byDay.get(key) ?? 0 });
  }
  return out;
}
