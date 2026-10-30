import bcrypt from 'bcryptjs';
import { getDb } from '../db/index.js';
import { newId } from '../utils/ids.js';
import { AppError } from '../utils/http.js';
import type { PublicUser, Role, User } from '../types/index.js';
import { config } from '../config/env.js';

export function toPublicUser(user: User): PublicUser {
  const { passwordHash: _ph, ...rest } = user;
  return rest;
}

export async function findUserByEmail(email: string): Promise<User | undefined> {
  const rows = await getDb()('users').where({ email }).limit(1);
  return rows[0] as User | undefined;
}

export async function findUserById(id: string): Promise<User | undefined> {
  const rows = await getDb()('users').where({ id }).limit(1);
  return rows[0] as User | undefined;
}

export async function createUser(input: {
  email: string;
  name: string;
  password: string;
  role?: Role;
}): Promise<PublicUser> {
  const email = input.email.trim().toLowerCase();
  const existing = await findUserByEmail(email);
  if (existing) throw new AppError(409, 'A user with this email already exists');

  const passwordHash = await bcrypt.hash(input.password, config.bcryptRounds);
  const user: User = {
    id: newId(),
    email,
    name: input.name.trim(),
    passwordHash,
    role: input.role ?? 'analyst',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await getDb()('users').insert({
    ...user,
    // normalize timestamps for sqlite difference
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  return toPublicUser({ ...user, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
}

export async function verifyPassword(user: User, password: string): Promise<boolean> {
  return bcrypt.compare(password, user.passwordHash);
}

export async function listUsers(): Promise<PublicUser[]> {
  const rows = (await getDb()('users').orderBy('createdAt', 'asc')) as User[];
  return rows.map(toPublicUser);
}