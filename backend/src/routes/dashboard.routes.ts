import { Router } from 'express';
import { asyncHandler } from '../utils/http.js';
import { requireAuth } from '../middleware/auth.js';
import { getDashboardStats } from '../services/dashboard.service.js';

const router = Router();
router.use(requireAuth);

/** GET /api/dashboard — platform/project analytics for the user. */
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const stats = await getDashboardStats(req.user!);
    res.json({ stats });
  }),
);

export default router;