import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/env.js';
import { AppError } from '../utils/http.js';
import type { PublicUser, Role } from '../types/index.js';

export interface AuthPayload extends PublicUser {
  sub: string;
}

export interface AuthedRequest extends Request {
  user?: PublicUser;
}

export function signToken(user: PublicUser): string {
  const payload = { ...user, sub: user.id };
  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn as jwt.SignOptions['expiresIn'],
  });
}

export function verifyToken(token: string): AuthPayload {
  return jwt.verify(token, config.jwtSecret) as AuthPayload;
}

/** Require a valid JWT bearer token; attaches the user to the request. */
export function requireAuth(req: AuthedRequest, _res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    throw new AppError(401, 'Missing or malformed authorization header');
  }
  const token = header.slice('Bearer '.length);
  try {
    const payload = verifyToken(token);
    req.user = { ...payload, id: payload.sub, createdAt: payload.createdAt, updatedAt: payload.updatedAt };
    next();
  } catch {
    throw new AppError(401, 'Invalid or expired token');
  }
}

/** Require one of the allowed roles. */
export function requireRoles(...roles: Role[]) {
  return (req: AuthedRequest, _res: Response, next: NextFunction): void => {
    const user = req.user;
    if (!user) throw new AppError(401, 'Authentication required');
    if (!roles.includes(user.role)) {
      throw new AppError(403, 'Insufficient role for this action');
    }
    next();
  };
}

