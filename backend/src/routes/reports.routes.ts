import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler, AppError } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { requireAuth } from '../middleware/auth.js';
import { getScanById, listFindingsForScan } from '../services/scan.service.js';
import { assertProjectAccess } from '../services/project.service.js';
import { getProjectById } from '../services/project.service.js';
import { getTargetById } from '../services/target.service.js';
import { findUserById } from '../services/user.service.js';
import { buildPdfReport } from '../services/report.service.js';
import { recordAudit } from '../services/audit.service.js';

const router = Router();
router.use(requireAuth);

const scanParam = z.object({ scanId: z.string().uuid() });
const projectParam = z.object({ projectId: z.string().uuid() });

const METHODOLOGY =
  'VulnScope performed a non-destructive assessment using the following detectors: ' +
  'technology fingerprinting, HTTP security-header inspection, TLS configuration checks, ' +
  'a basic OWASP Top 10 review, Nmap port/service discovery for infrastructure, and ' +
  'OWASP ZAP (passive by default, safe-active for full scans). Findings are correlated ' +
  'with NVD CVE intelligence. Software version matches are advisory and are not treated ' +
  'as proof of exploitability.';

/** GET /api/reports/scan/:scanId — download a PDF report for a scan. */
router.get(
  '/scan/:scanId',
  validate(scanParam, 'params'),
  asyncHandler(async (req, res) => {
    const scan = await getScanById(req.params.scanId);
    if (!scan) throw new AppError(404, 'Scan not found');
    await assertProjectAccess(req.user!, scan.projectId);

    const [project, target, author, findings] = await Promise.all([
      getProjectById(scan.projectId),
      getTargetById(scan.targetId),
      findUserById(scan.createdById),
      listFindingsForScan(req.user!, scan.id),
    ]);

    const pdf = await buildPdfReport({
      project: project!,
      target: target!,
      scan,
      author: {
        name: author?.name ?? 'VulnScope',
        email: author?.email ?? 'noreply@vulnscope.local',
      },
      findings,
      generatedAt: new Date().toISOString(),
      methodology: METHODOLOGY,
    });

    await recordAudit({ actorId: req.user!.id, action: 'report.generate', entity: 'scan', entityId: scan.id, ip: req.ip ?? null });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="vulnscope-report-${scan.id}.pdf"`);
    res.send(pdf);
  }),
);

/** GET /api/reports/project/:projectId — report access convenience / health. */
router.get(
  '/project/:projectId',
  validate(projectParam, 'params'),
  asyncHandler(async (req, res) => {
    const project = await assertProjectAccess(req.user!, req.params.projectId);
    res.json({ project: project.name, message: 'Generate per-scan PDF reports via /api/reports/scan/:scanId' });
  }),
);

export default router;