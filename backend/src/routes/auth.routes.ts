import { Router } from 'express';
import { z } from 'zod';
import { asyncHandler, AppError } from '../utils/http.js';
import { validate } from '../middleware/validate.js';
import { authLimiter } from '../middleware/rateLimit.js';
import { signToken } from '../middleware/auth.js';
import { findUserByEmail, verifyPassword, createUser } from '../services/user.service.js';
import { recordAudit } from '../services/audit.service.js';

const router = Router();

const registerSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(255),
  password: z.string().min(8).max(128),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

/** POST /api/auth/register — create a new analyst account. */
router.post(
  '/register',
  authLimiter,
  validate(registerSchema),
  asyncHandler(async (req, res) => {
    const user = await createUser(req.body);
    const token = signToken(user);
    await recordAudit({ actorId: user.id, action: 'auth.register', entity: 'user', entityId: user.id, ip: req.ip ?? null });
    res.status(201).json({ token, user });
  }),
);

/** POST /api/auth/login — exchange credentials for a JWT. */
router.post(
  '/login',
  authLimiter,
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const user = await findUserByEmail(email);
    const ok = user ? await verifyPassword(user, password) : false;
    if (!user || !ok) {
      await recordAudit({ actorId: null, action: 'auth.login_failed', entity: 'user', entityId: null, metadata: { email }, ip: req.ip ?? null });
      throw new AppError(401, 'Invalid email or password');
    }
    const token = signToken({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
    await recordAudit({ actorId: user.id, action: 'auth.login', entity: 'user', entityId: user.id, ip: req.ip ?? null });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role, createdAt: user.createdAt, updatedAt: user.updatedAt } });
  }),
);

export default router;