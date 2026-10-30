import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler, AppError } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { recordAudit } from '../services/audit.service.js';
import {
  createTarget,
  getTargetById,
  generateOwnershipToken,
  verifyOwnership,
  setAllowlisted,
} from '../services/target.service.js';
import { assertProjectAccess } from '../services/project.service.js';

const router = Router();
router.use(requireAuth);

const createSchema = z.object({
  projectId: z.string().uuid(),
  name: z.string().min(1).max(255),
  kind: z.enum(['web', 'infrastructure']),
  host: z.string().min(1).max(500),
  port: z.number().int().min(1).max(65535).optional().nullable(),
  ownershipOwner: z.string().max(255).optional(),
  importance: z.number().int().min(1).max(5).optional(),
});

const tokenSchema = z.object({ targetId: z.string().uuid() });

const verifySchema = z.object({
  ownershipToken: z.string().min(1).max(255),
  ownershipOwner: z.string().min(1).max(255),
});

const allowSchema = z.object({ allowlisted: z.boolean() });

/** POST /api/targets — register a new target. */
router.post(
  '/',
  validate(createSchema),
  asyncHandler(async (req, res) => {
    const target = await createTarget(req.user!, req.body);
    res.status(201).json({ target });
  }),
);

/** POST /api/targets/:targetId/ownership-token — generate a verification token. */
router.post(
  '/:targetId/ownership-token',
  validate(tokenSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { ownershipToken } = await generateOwnershipToken(req.user!, req.params.targetId);
    res.json({ ownershipToken });
  }),
);

/** POST /api/targets/:targetId/verify — prove ownership. */
router.post(
  '/:targetId/verify',
  validate(tokenSchema, 'params'),
  validate(verifySchema),
  asyncHandler(async (req, res) => {
    const target = await verifyOwnership(req.user!, req.params.targetId, req.body);
    await recordAudit({ actorId: req.user!.id, action: 'target.verify', entity: 'target', entityId: target.id, ip: req.ip ?? null });
    res.json({ target });
  }),
);

/** PUT /api/targets/:targetId/allowlist — allowlist target for scanning. */
router.put(
  '/:targetId/allowlist',
  validate(tokenSchema, 'params'),
  validate(allowSchema),
  asyncHandler(async (req, res) => {
    const target = await setAllowlisted(req.user!, req.params.targetId, req.body.allowlisted);
    res.json({ target });
  }),
);

/** GET /api/targets/:targetId — target detail with project access check. */
router.get(
  '/:targetId',
  validate(tokenSchema, 'params'),
  asyncHandler(async (req, res) => {
    const target = await getTargetById(req.params.targetId);
    if (!target) throw new AppError(404, 'Target not found');
    await assertProjectAccess(req.user!, target.projectId);
    res.json({ target });
  }),
);

export default router;