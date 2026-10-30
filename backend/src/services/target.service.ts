import { getDb } from '../db/index.js';
import { newId, createToken } from '../utils/ids.js';
import { AppError } from '../utils/http.js';
import type { PublicUser, Target, TargetKind } from '../types/index.js';
import { assertProjectAccess } from './project.service.js';
import { recordAudit } from './audit.service.js';

const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9\-._]*[a-zA-Z0-9])?$/;

export function validateHost(host: string, kind: TargetKind): void {
  const trimmed = host.trim();
  if (!trimmed || trimmed.length > 500) {
    throw new AppError(400, 'A valid host or URL is required');
  }
  if (kind === 'web') {
    if (!/^https?:\/\//i.test(trimmed) && !HOSTNAME_RE.test(trimmed)) {
      throw new AppError(400, 'Web target must be a valid URL or hostname');
    }
  } else if (!HOSTNAME_RE.test(trimmed) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    throw new AppError(400, 'Infrastructure target must be a valid hostname or IP address');
  }
}

export async function getTargetById(id: string): Promise<Target | undefined> {
  const rows = await getDb()('targets').where({ id }).limit(1);
  return rows[0] as Target | undefined;
}

export async function createTarget(
  user: PublicUser,
  input: {
    projectId: string;
    name: string;
    kind: TargetKind;
    host: string;
    port?: number | null;
    ownershipOwner?: string;
    importance?: number;
  },
): Promise<Target> {
  await assertProjectAccess(user, input.projectId);
  validateHost(input.host, input.kind);

  const port = input.kind === 'infrastructure' ? input.port ?? null : null;
  if (input.kind === 'infrastructure' && port != null && (port < 1 || port > 65535)) {
    throw new AppError(400, 'Port must be between 1 and 65535');
  }
  const importance = Math.min(5, Math.max(1, input.importance ?? 3));

  const now = new Date().toISOString();
  const target: Target = {
    id: newId(),
    projectId: input.projectId,
    name: input.name.trim(),
    kind: input.kind,
    host: input.host.trim(),
    port,
    ownershipOwner: input.ownershipOwner?.trim() || null,
    ownershipToken: null,
    ownershipVerified: false,
    status: 'pending',
    allowlisted: false,
    importance,
    createdById: user.id,
    createdAt: now,
    updatedAt: now,
  };
  await getDb()('targets').insert({ ...target, createdAt: new Date(), updatedAt: new Date() });
  await recordAudit({
    actorId: user.id,
    action: 'target.create',
    entity: 'target',
    entityId: target.id,
    metadata: { host: target.host, projectId: target.projectId },
  });
  return target;
}

export async function listTargetsForProject(
  user: PublicUser,
  projectId: string,
): Promise<Target[]> {
  await assertProjectAccess(user, projectId);
  return (await getDb()('targets').where({ projectId }).orderBy('createdAt', 'desc')) as Target[];
}

export async function generateOwnershipToken(
  user: PublicUser,
  targetId: string,
): Promise<{ ownershipToken: string }> {
  const target = await getTargetById(targetId);
  if (!target) throw new AppError(404, 'Target not found');
  await assertProjectAccess(user, target.projectId);
  const token = createToken(32);
  await getDb()('targets').where({ id: targetId }).update({ ownershipToken: token, updatedAt: new Date() });
  await recordAudit({ actorId: user.id, action: 'target.ownership_token_generated', entity: 'target', entityId: targetId });
  return { ownershipToken: token };
}

export async function verifyOwnership(
  user: PublicUser,
  targetId: string,
  input: { ownershipToken: string; ownershipOwner: string },
): Promise<Target> {
  const target = await getTargetById(targetId);
  if (!target) throw new AppError(404, 'Target not found');
  await assertProjectAccess(user, target.projectId);
  if (!target.ownershipToken) {
    throw new AppError(400, 'No ownership token has been generated for this target');
  }
  const a = Buffer.from(String(input.ownershipToken));
  const b = Buffer.from(String(target.ownershipToken));
  if (a.length !== b.length || !a.equals(b)) {
    throw new AppError(403, 'Ownership verification failed: invalid token');
  }
  await getDb()('targets').where({ id: targetId }).update({
    ownershipOwner: input.ownershipOwner.trim(),
    ownershipVerified: true,
    status: 'verified',
    updatedAt: new Date(),
  });
  await recordAudit({ actorId: user.id, action: 'target.ownership_verified', entity: 'target', entityId: targetId });
  return { ...target, ownershipOwner: input.ownershipOwner.trim(), ownershipVerified: true, status: 'verified' };
}

export async function setAllowlisted(
  user: PublicUser,
  targetId: string,
  allowlisted: boolean,
): Promise<Target> {
  const target = await getTargetById(targetId);
  if (!target) throw new AppError(404, 'Target not found');
  await assertProjectAccess(user, target.projectId);
  await getDb()('targets').where({ id: targetId }).update({ allowlisted, updatedAt: new Date() });
  await recordAudit({ actorId: user.id, action: allowlisted ? 'target.allowlisted' : 'target.de_allowlisted', entity: 'target', entityId: targetId });
  return { ...target, allowlisted, updatedAt: new Date().toISOString() };
}

export async function assertScanAllowed(target: Target): Promise<void> {
  if (!target.ownershipVerified || target.status !== 'verified') {
    throw new AppError(403, 'Target is not ownership-verified');
  }
  if (!target.allowlisted) {
    throw new AppError(403, 'Target is not allowlisted for scanning');
  }
}
