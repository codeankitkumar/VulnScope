import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app, authToken, createUser } from './helpers.js';

describe('Authentication', () => {
  it('registers a new user and returns a JWT', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'new@user.dev', password: 'CorrectHorse99!', name: 'New User' })
      .expect(201);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user.email).toBe('new@user.dev');
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  it('rejects duplicate emails', async () => {
    await createUser({ email: 'dup@user.dev' });
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@user.dev', password: 'CorrectHorse99!', name: 'Dup' });
    expect(res.status).toBe(409);
  });

  it('rejects a weak password', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'weak@user.dev', password: 'short', name: 'Weak' });
    expect(res.status).toBe(400);
  });

  it('logs in with valid credentials', async () => {
    await createUser({ email: 'login@user.dev', password: 'CorrectHorse99!' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@user.dev', password: 'CorrectHorse99!' })
      .expect(200);
    expect(res.body.token).toBeTruthy();
  });

  it('rejects bad credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nobody@user.dev', password: 'WrongPass1!' });
    expect(res.status).toBe(401);
  });

  it('rejects requests without a token', async () => {
    const res = await request(app).get('/api/projects');
    expect(res.status).toBe(401);
  });
});

describe('Authorization', () => {
  it('denies a non-admin access to admin routes', async () => {
    const token = await authToken();
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(403);
  });

  it('allows admins to list users', async () => {
    const admin = await createUser({ role: 'admin', email: 'admin@list.dev' });
    const login = await request(app).post('/api/auth/login').send({ email: 'admin@list.dev', password: 'Password123!' }).expect(200);
    const res = await request(app).get('/api/users').set('Authorization', `Bearer ${login.body.token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users)).toBe(true);
    expect(admin.id).toBeTruthy();
  });
});
