import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { analyzeFindings } from '../services/scan.service.js';
import { assistant } from '../services/ai.service.js';
import { listFindingsForProject } from '../services/scan.service.js';
import { recordAudit } from '../services/audit.service.js';

const router = Router();
router.use(requireAuth);

const askSchema = z.object({
  projectId: z.string().uuid(),
  question: z.string().min(1).max(2000).optional(),
});

/** POST /api/ai/analyze — explain findings, summarize, or answer a question. */
router.post(
  '/analyze',
  validate(askSchema),
  asyncHandler(async (req, res) => {
    const { projectId, question } = req.body;
    const response = await analyzeFindings(req.user!, projectId, question);
    await recordAudit({ actorId: req.user!.id, action: 'ai.analyze', entity: 'project', entityId: projectId, ip: req.ip ?? null });
    res.json({ ...response });
  }),
);

const groupSchema = z.object({ projectId: z.string().uuid() });

/** POST /api/ai/group — group related findings (by CWE). */
router.post(
  '/group',
  validate(groupSchema),
  asyncHandler(async (req, res) => {
    const findings = await listFindingsForProject(req.user!, req.body.projectId);
    const groups = assistant.groupRelated(findings);
    res.json({ groups });
  }),
);

const cveEnrichSchema = z.object({ projectId: z.string().uuid() });

/** POST /api/ai/cve-enrich — enrich project findings with CVE references. */
router.post(
  '/cve-enrich',
  validate(cveEnrichSchema),
  asyncHandler(async (req, res) => {
    const findings = await listFindingsForProject(req.user!, req.body.projectId);
    const { enrichFindingsWithCve } = await import('../services/scan.service.js');
    const enriched = await enrichFindingsWithCve(findings);
    res.json({ findings: enriched });
  }),
);

export default router;