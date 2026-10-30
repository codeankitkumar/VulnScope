import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import type { Knex } from 'knex';

export async function seed(knex: Knex): Promise<void> {
  const adminEmail = process.env.ADMIN_EMAIL ?? 'admin@vulnscope.local';
  const existing = await knex('users').where({ email: adminEmail }).first();
  if (existing) return;
  const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD ?? 'ChangeMe123!', 10);
  await knex('users').insert({
    id: crypto.randomUUID(),
    email: adminEmail,
    name: 'VulnScope Admin',
    passwordHash,
    role: 'admin',
    createdAt: new Date(),
    updatedAt: new Date(),
  });
}
