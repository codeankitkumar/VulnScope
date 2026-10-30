import { getDb } from '../db/index.js';
import { newId } from '../utils/ids.js';
import type { AuditLog } from '../types/index.js';

export interface AuditInput {
  actorId: string | null;
  action: string;
  entity: string;
  entityId?: string | null;
  metadata?: unknown;
  ip?: string | null;
}

export async function recordAudit(input: AuditInput): Promise<AuditLog> {
  const row = await getDb()('audit_logs')
    .insert({
      id: newId(),
      actorId: input.actorId,
      action: input.action,
      entity: input.entity,
      entityId: input.entityId ?? null,
      metadata: input.metadata !== undefined ? JSON.stringify(input.metadata) : null,
      ip: input.ip ?? null,
    })
    .returning('*');
  return row[0] as AuditLog;
}

export async function listAudit(limit = 200): Promise<AuditLog[]> {
  return (await getDb()('audit_logs').orderBy('createdAt', 'desc').limit(limit)) as AuditLog[];
}