// Shared domain types used across services, routes, and tests.

export type Role = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  email: string;
  name: string;
  passwordHash: string;
  role: Role;
  createdAt: string;
  updatedAt: string;
}

export type PublicUser = Omit<User, 'passwordHash'>;

export interface Project {
  id: string;
  name: string;
  description: string | null;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

export type TargetStatus = 'pending' | 'verified' | 'rejected';
export type TargetKind = 'web' | 'infrastructure';

export interface Target {
  id: string;
  projectId: string;
  name: string;
  kind: TargetKind;
  host: string; // hostname, IP, or URL
  port: number | null;
  ownershipOwner: string | null; // contact of the party that owns the target
  ownershipToken: string | null; // one-time verification token delivered out-of-band
  ownershipVerified: boolean;
  status: TargetStatus;
  allowlisted: boolean;
  importance: number; // 1..5 asset importance
  createdById: string;
  createdAt: string;
  updatedAt: string;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'canceled';
export type ScanMode = 'passive' | 'active';
export type ScanType = 'quick' | 'full';

export interface Scan {
  id: string;
  targetId: string;
  projectId: string;
  type: ScanType;
  mode: ScanMode;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  summary: string | null;
  error: string | null;
  createdById: string;
  trigger: 'manual' | 'scheduled';
  createdAt: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'confirmed' | 'possible';

export interface Finding {
  id: string;
  scanId: string;
  targetId: string;
  projectId: string;
  title: string;
  description: string;
  cweId: string | null;
  cveId: string | null;
  cvssScore: number | null;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  evidence: string | null;
  remediation: string | null;
  references: string | null; // JSON array string
  detector: string; // which adapter produced the finding
  status: 'open' | 'in_progress' | 'remediated' | 'false_positive';
  createdAt: string;
}

// Scan `artifacts` store raw adapter output per scan run.
export interface ScanArtifact {
  id: string;
  scanId: string;
  detector: string;
  raw: string; // JSON-encoded
  createdAt: string;
}

export interface AuditLog {
  id: string;
  actorId: string | null;
  action: string;
  entity: string;
  entityId: string | null;
  metadata: string | null; // JSON string
  ip: string | null;
  createdAt: string;
}

export interface PromptOptions {
  includeEvidence: boolean;
}

export interface ApiError extends Error {
  status?: number;
  details?: unknown;
}