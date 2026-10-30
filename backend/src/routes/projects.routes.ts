import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler, AppError } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import {
  createProject,
  listProjectsForUser,
  getProjectById,
  assertProjectAccess,
} from '../services/project.service.js';
import { listTargetsForProject } from '../services/target.service.js';
import { listScansForProject } from '../services/scan.service.js';
import { recordAudit } from '../services/audit.service.js';

const router = Router();
router.use(requireAuth);

const createSchema = z.object({ name: z.string().min(1).max(255), description: z.string().max(2000).optional() });

/** POST /api/projects — create a project (analyst+). */
router.post(
  '/',
  validate(createSchema),
  asyncHandler(async (req, res) => {
    const project = await createProject(req.user!, req.body);
    await recordAudit({ actorId: req.user!.id, action: 'project.create', entity: 'project', entityId: project.id, metadata: { name: project.name }, ip: req.ip ?? null });
    res.status(201).json({ project });
  }),
);

/** GET /api/projects — list projects the user can access. */
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const projects = await listProjectsForUser(req.user!);
    res.json({ projects });
  }),
);

const idParam = z.object({ id: z.string().uuid() });

/** GET /api/projects/:id — project detail. */
router.get(
  '/:id',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const project = await assertProjectAccess(req.user!, req.params.id);
    res.json({ project });
  }),
);

/** GET /api/projects/:id/targets — targets within a project. */
router.get(
  '/:id/targets',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const targets = await listTargetsForProject(req.user!, req.params.id);
    res.json({ targets });
  }),
);

/** GET /api/projects/:id/scans — scan history for a project. */
router.get(
  '/:id/scans',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const scans = await listScansForProject(req.user!, req.params.id);
    res.json({ scans });
  }),
);

/** DELETE /api/projects/:id — remove a project (owner/admin). */
router.delete(
  '/:id',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const { getDb } = await import('../db/index.js');
    const project = await getProjectById(req.params.id);
    if (!project) throw new AppError(404, 'Project not found');
    if (req.user!.role !== 'admin' && project.ownerId !== req.user!.id) {
      throw new AppError(403, 'Only the project owner or an admin may delete a project');
    }
    await getDb()('projects').where({ id: req.params.id }).del();
    await recordAudit({ actorId: req.user!.id, action: 'project.delete', entity: 'project', entityId: req.params.id, ip: req.ip ?? null });
    res.json({ ok: true });
  }),
);

export default router;