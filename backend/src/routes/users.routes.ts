import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth, requireRoles } from '../middleware/auth.js';
import { listUsers } from '../services/user.service.js';
import { recordAudit } from '../services/audit.service.js';

const router = Router();

// All user administration endpoints are admin-only.
router.use(requireAuth, requireRoles('admin'));

/** GET /api/users â€” list all users (admin). */
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const users = await listUsers();
    res.json({ users });
  }),
);

/** GET /api/users/:id â€” return the requesting user's own profile (any role). */
const meOrOnlySchema = z.object({
  id: z.string(),
});

router.get(
  '/:id',
  asyncHandler(async (req, res, next) => {
    const parsed = meOrOnlySchema.safeParse(req.params);
    if (!parsed.success) return next();
    if (req.user!.id !== parsed.data.id && req.user!.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const users = await listUsers();
    const profile = users.find((u) => u.id === parsed.data.id);
    if (!profile) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: profile });
  }),
);

/** GET /api/users/me â€” available to any authenticated user. */
router.get(
  '/me/profile',
  asyncHandler(async (req, res) => {
    const users = await listUsers();
    const profile = users.find((u) => u.id === req.user!.id);
    if (!profile) return res.status(404).json({ error: 'User not found' });
    await recordAudit({ actorId: req.user!.id, action: 'user.profile_read', entity: 'user', entityId: req.user!.id, ip: req.ip ?? null });
    return res.json({ user: profile });
  }),
);

export default router;
