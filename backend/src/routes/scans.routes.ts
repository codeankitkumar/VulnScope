import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import {
  createScan,
  getScanById,
  listFindingsForScan,
  updateFindingStatus,
} from '../services/scan.service.js';
import { assertProjectAccess } from '../services/project.service.js';
import { recordAudit } from '../services/audit.service.js';

const router = Router();
router.use(requireAuth);

const createSchema = z.object({
  targetId: z.string().uuid(),
  type: z.enum(['quick', 'full']).default('quick'),
  mode: z.enum(['passive', 'active']).default('passive'),
});

const idParam = z.object({ scanId: z.string().uuid() });

const findingIdParam = z.object({ findingId: z.string().uuid() });

const statusSchema = z.object({ status: z.enum(['open', 'in_progress', 'remediated', 'false_positive']) });

/** POST /api/scans — create and run a scan against an allowlisted target. */
router.post(
  '/',
  validate(createSchema),
  asyncHandler(async (req, res) => {
    const scan = await createScan(req.user!, req.body);
    await recordAudit({ actorId: req.user!.id, action: 'scan.triggered', entity: 'scan', entityId: scan.id, ip: req.ip ?? null });
    res.status(201).json({ scan });
  }),
);

/** GET /api/scans/:scanId — scan detail. */
router.get(
  '/:scanId',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const scan = await getScanById(req.params.scanId);
    if (scan) await assertProjectAccess(req.user!, scan.projectId);
    res.json({ scan }); // scan is null when not found; 404 handled by null body
  }),
);

/** GET /api/scans/:scanId/findings — findings for a scan. */
router.get(
  '/:scanId/findings',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const findings = await listFindingsForScan(req.user!, req.params.scanId);
    res.json({ findings });
  }),
);

/** GET /api/scans/:scanId/artifacts — raw scanner artifacts for a scan. */
router.get(
  '/:scanId/artifacts',
  validate(idParam, 'params'),
  asyncHandler(async (req, res) => {
    const { getDb } = await import('../db/index.js');
    const scan = await getScanById(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    await assertProjectAccess(req.user!, scan.projectId);
    const artifacts = await getDb()('scan_artifacts').where({ scanId: req.params.scanId }).orderBy('createdAt', 'asc');
    res.json({ artifacts });
  }),
);

/** PATCH /api/scans/findings/:findingId/status — update finding remediation status. */
router.patch(
  '/findings/:findingId/status',
  validate(findingIdParam, 'params'),
  validate(statusSchema),
  asyncHandler(async (req, res) => {
    const finding = await updateFindingStatus(req.user!, req.params.findingId, req.body.status);
    res.json({ finding });
  }),
);

export default router;