import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app, authToken, createProject, createTarget, prepareTargetForScan } from './helpers.js';

describe('Target management & ownership verification', () => {
  it('blocks scanning until ownership is verified and target is allowlisted', async () => {
    const token = await authToken();
    const projectId = await createProject(token);
    const target = await createTarget(token, projectId, { kind: 'infrastructure', host: '203.0.113.10', port: 22 });

    // Scan should be blocked pre-verification.
    const blocked = await request(app)
      .post('/api/scans')
      .set('Authorization', `Bearer ${token}`)
      .send({ targetId: target.id, type: 'quick', mode: 'passive' });
    expect(blocked.status).toBe(403);

    // Generate ownership token -> verify -> allowlist.
    await prepareTargetForScan(token, target.id);

    const detail = await request(app).get(`/api/targets/${target.id}`).set('Authorization', `Bearer ${token}`).expect(200);
    expect(detail.body.target.ownershipVerified).toBe(true);
    expect(detail.body.target.allowlisted).toBe(true);
    expect(detail.body.target.status).toBe('verified');
  });

  it('rejects an invalid ownership token', async () => {
    const token = await authToken();
    const projectId = await createProject(token);
    const target = await createTarget(token, projectId);

    const gen = await request(app)
      .post(`/api/targets/${target.id}/ownership-token`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(gen.body.ownershipToken).toBeTruthy();

    const bad = await request(app)
      .post(`/api/targets/${target.id}/verify`)
      .set('Authorization', `Bearer ${token}`)
      .send({ ownershipToken: 'wrong-token', ownershipOwner: 'owner@x.com' });
    expect(bad.status).toBe(403);
  });

  it('enforces project access boundaries between users', async () => {
    const owner = await authToken();
    const other = await authToken();
    const projectId = await createProject(owner);
    const target = await createTarget(owner, projectId);

    const res = await request(app).get(`/api/targets/${target.id}`).set('Authorization', `Bearer ${other}`);
    expect(res.status).toBe(403);
  });
});
