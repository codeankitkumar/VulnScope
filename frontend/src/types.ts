export interface PublicUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  createdAt: string;
  updatedAt: string;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

export interface Target {
  id: string;
  projectId: string;
  name: string;
  kind: 'web' | 'infrastructure';
  host: string;
  port: number | null;
  ownershipVerified: boolean;
  status: 'pending' | 'verified' | 'rejected';
  allowlisted: boolean;
  importance: number;
  createdAt: string;
}

export interface Scan {
  id: string;
  targetId: string;
  projectId: string;
  type: 'quick' | 'full';
  mode: 'passive' | 'active';
  status: 'queued' | 'running' | 'completed' | 'failed' | 'canceled';
  startedAt: string | null;
  finishedAt: string | null;
  summary: string | null;
  error: string | null;
  trigger: 'manual' | 'scheduled';
  createdAt: string;
}

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
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'possible';
  evidence: string | null;
  remediation: string | null;
  references: string | null;
  detector: string;
  status: 'open' | 'in_progress' | 'remediated' | 'false_positive';
  createdAt: string;
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
