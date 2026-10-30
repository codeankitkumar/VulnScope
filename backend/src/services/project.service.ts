import { getDb } from '../db/index.js';
import { newId } from '../utils/ids.js';
import { AppError } from '../utils/http.js';
import type { Project, PublicUser } from '../types/index.js';
import { recordAudit } from './audit.service.js';

export async function getProjectById(id: string): Promise<Project | undefined> {
  const rows = await getDb()('projects').where({ id }).limit(1);
  return rows[0] as Project | undefined;
}

/**
 * Enforce that a user can access a project. Admins access everything;
 * otherwise only the project owner may access it.
 */
export async function assertProjectAccess(
  user: PublicUser,
  projectId: string,
): Promise<Project> {
  const project = await getProjectById(projectId);
  if (!project) throw new AppError(404, 'Project not found');
  if (user.role === 'admin' || project.ownerId === user.id) return project;
  throw new AppError(403, 'You do not have access to this project');
}

export async function createProject(
  user: PublicUser,
  input: { name: string; description?: string },
): Promise<Project> {
  const project: Project = {
    id: newId(),
    name: input.name.trim(),
    description: input.description?.trim() || null,
    ownerId: user.id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await getDb()('projects').insert({
    ...project,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  return { ...project, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
}

export async function listProjectsForUser(user: PublicUser): Promise<Project[]> {
  if (user.role === 'admin') {
    return (await getDb()('projects').orderBy('createdAt', 'desc')) as Project[];
  }
  return (await getDb()('projects').where({ ownerId: user.id }).orderBy('createdAt', 'desc')) as Project[];
}

export async function countProjectsForUser(user: PublicUser): Promise<number> {
  if (user.role === 'admin') {
    const row = await getDb()('projects').count<{ count: number }[]>('* as count').first();
    return Number(row?.count ?? 0);
  }
  const row = await getDb()('projects').where({ ownerId: user.id }).count<{ count: number }[]>('* as count').first();
  return Number(row?.count ?? 0);
}