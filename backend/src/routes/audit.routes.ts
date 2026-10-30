import { Router } from 'express';
import { asyncHandler } from '../utils/http.js';
import { requireAuth, requireRoles } from '../middleware/auth.js';
import { listAudit } from '../services/audit.service.js';

const router = Router();

// Audit logs are admin-only.
router.use(requireAuth, requireRoles('admin'));

/** GET /api/audit — recent audit log entries (admin). */
router.get(
  '/',
  asyncHandler(async (_req, res) => {
    const logs = await listAudit(300);
    res.json({ logs });
  }),
);

export default router;