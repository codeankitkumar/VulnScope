import crypto from 'node:crypto';
import cron from 'node-cron';
import { getDb } from '../db/index.js';
import { executeScan } from './scan.service.js';
import { getTargetById } from './target.service.js';

interface ScheduleRow {
  id: string;
  targetId: string;
  projectId: string;
  cron: string;
  type: 'quick' | 'full';
  mode: 'passive' | 'active';
  enabled: boolean;
  createdById: string | null;
}

interface ScanLike {
  id: string;
  targetId: string;
  projectId: string;
  type: 'quick' | 'full';
  mode: 'passive' | 'active';
}

/** Evaluate a 5-field cron expression against the current time (minute granularity). */
export function cronMatches(expr: string, now: Date): boolean {
  const parts = expr.trim().split(/\s+/);
  const [minField, hourField] = parts;
  if (!minField || !hourField) return false;
  const minutes = expandField(minField, 0, 59);
  if (!minutes.includes(now.getMinutes())) return false;
  if (hourField === '*') return true;
  const hours = expandField(hourField, 0, 23);
  return hours.includes(now.getHours());
}

function expandField(field: string, lo: number, hi: number): number[] {
  if (field === '*') {
    const out: number[] = [];
    for (let i = lo; i <= hi; i++) out.push(i);
    return out;
  }
  const stepMatch = field.match(/^([\d*]+)\/(\d+)$/);
  if (stepMatch) {
    const start = stepMatch[1] === '*' ? lo : Number(stepMatch[1]);
    const step = Number(stepMatch[2]) || 1;
    const out: number[] = [];
    for (let i = start; i <= hi; i += step) out.push(i);
    return out;
  }
  return field.split(',').map((v) => Number(v)).filter((n) => Number.isInteger(n) && n >= lo && n <= hi);
}

/**
 * Scheduled scan runner. Every minute, evaluate enabled schedules and execute
 * any that are due, using the schedule author (or an admin) as the acting user.
 */
export function startScheduler(): void {
  cron.schedule('* * * * *', async () => {
    try {
      const schedules = (await getDb()('scan_schedules').select('*')) as ScheduleRow[];
      if (schedules.length === 0) return;
      const now = new Date();
      for (const sched of schedules) {
        if (!sched.enabled) continue;
        if (!cronMatches(sched.cron, now)) continue;

        const target = await getTargetById(sched.targetId);
        if (!target || !target.ownershipVerified || !target.allowlisted) continue;

        const creator = sched.createdById
          ? await getDb()('users').where({ id: sched.createdById }).first().catch(() => undefined)
          : undefined;
        const actor = creator ?? (await getDb()('users').where({ role: 'admin' }).first());

        const scan: ScanLike = {
          id: crypto.randomUUID(),
          targetId: target.id,
          projectId: target.projectId,
          type: sched.type,
          mode: sched.mode,
        };
        await getDb()('scans').insert({
          ...scan,
          status: 'queued',
          startedAt: null,
          finishedAt: null,
          summary: null,
          error: null,
          createdById: actor?.id ?? null,
          trigger: 'scheduled',
          createdAt: new Date(),
        });
        if (actor) {
          void executeScan({ ...scan, status: 'queued', createdAt: new Date().toISOString(), startedAt: null, finishedAt: null, summary: null, error: null, trigger: 'scheduled', createdById: actor.id } as never, actor);
        }
        await getDb()('scan_schedules').where({ id: sched.id }).update({ lastRunAt: new Date() });
      }
    } catch {
      // Scheduler must never crash the process.
    }
  });
}

/** Register a schedule for a target. Assumes caller has already validated access. */
export async function createSchedule(input: {
  targetId: string;
  projectId: string;
  cron: string;
  type: 'quick' | 'full';
  mode: 'passive' | 'active';
  createdById: string;
}): Promise<ScheduleRow> {
  const id = crypto.randomUUID();
  await getDb()('scan_schedules').insert({ ...input, id, enabled: true, createdAt: new Date(), lastRunAt: null });
  return { ...input, id, enabled: true };
}
