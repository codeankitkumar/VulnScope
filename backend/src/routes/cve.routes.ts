import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler, AppError } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { nvd } from '../services/nvd.service.js';

const router = Router();
router.use(requireAuth);

const cveParam = z.object({ cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i) });
const searchQuery = z.object({ keyword: z.string().min(2).max(200) });

/** GET /api/cve/:cveId — fetch a single CVE record from NVD (cached). */
router.get(
  '/:cveId',
  validate(cveParam, 'params'),
  asyncHandler(async (req, res) => {
    const record = await nvd.getCve(req.params.cveId);
    if (!record) throw new AppError(404, 'CVE not found in NVD');
    res.json({ record });
  }),
);

/** POST /api/cve/search — search NVD by keyword. */
router.post(
  '/search',
  validate(searchQuery),
  asyncHandler(async (req, res) => {
    const records = await nvd.search(req.body.keyword);
    res.json({ records });
  }),
);

export default router;