import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('users', (t) => {
    t.uuid('id').primary();
    t.string('email', 255).notNullable().unique().index();
    t.string('name', 255).notNullable();
    t.string('passwordHash', 255).notNullable();
    t.string('role', 20).notNullable().defaultTo('analyst');
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable('projects', (t) => {
    t.uuid('id').primary();
    t.string('name', 255).notNullable();
    t.text('description');
    t.uuid('ownerId').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    t.index(['ownerId']);
  });

  await knex.schema.createTable('targets', (t) => {
    t.uuid('id').primary();
    t.uuid('projectId').notNullable().references('id').inTable('projects').onDelete('CASCADE');
    t.string('name', 255).notNullable();
    t.string('kind', 30).notNullable().defaultTo('web');
    t.string('host', 510).notNullable();
    t.integer('port').nullable();
    t.string('ownershipOwner', 255).nullable();
    t.string('ownershipToken', 255).nullable();
    t.boolean('ownershipVerified').notNullable().defaultTo(false);
    t.string('status', 20).notNullable().defaultTo('pending');
    t.boolean('allowlisted').notNullable().defaultTo(false);
    t.integer('importance').notNullable().defaultTo(3);
    t.uuid('createdById').notNullable().references('id').inTable('users');
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.timestamp('updatedAt').notNullable().defaultTo(knex.fn.now());
    t.index(['projectId']);
    t.index(['status']);
  });

  await knex.schema.createTable('scans', (t) => {
    t.uuid('id').primary();
    t.uuid('targetId').notNullable().references('id').inTable('targets').onDelete('CASCADE');
    t.uuid('projectId').notNullable().references('id').inTable('projects').onDelete('CASCADE');
    t.string('type', 20).notNullable().defaultTo('quick');
    t.string('mode', 20).notNullable().defaultTo('passive');
    t.string('status', 20).notNullable().defaultTo('queued');
    t.timestamp('startedAt').nullable();
    t.timestamp('finishedAt').nullable();
    t.text('summary');
    t.text('error');
    t.uuid('createdById').notNullable().references('id').inTable('users');
    t.string('trigger', 20).notNullable().defaultTo('manual');
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.index(['targetId']);
    t.index(['status']);
  });

  await knex.schema.createTable('findings', (t) => {
    t.uuid('id').primary();
    t.uuid('scanId').notNullable().references('id').inTable('scans').onDelete('CASCADE');
    t.uuid('targetId').notNullable().references('id').inTable('targets').onDelete('CASCADE');
    t.uuid('projectId').notNullable().references('id').inTable('projects').onDelete('CASCADE');
    t.string('title', 510).notNullable();
    t.text('description');
    t.string('cweId', 30).nullable();
    t.string('cveId', 40).nullable();
    t.decimal('cvssScore', 4, 2).nullable();
    t.string('severity', 20).notNullable().defaultTo('info');
    t.string('confidence', 20).notNullable().defaultTo('possible');
    t.text('evidence');
    t.text('remediation');
    t.text('references');
    t.string('detector', 60).notNullable();
    t.string('status', 20).notNullable().defaultTo('open');
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.index(['targetId']);
    t.index(['severity']);
    t.index(['status']);
  });

  await knex.schema.createTable('scan_artifacts', (t) => {
    t.uuid('id').primary();
    t.uuid('scanId').notNullable().references('id').inTable('scans').onDelete('CASCADE');
    t.string('detector', 60).notNullable();
    t.text('raw').notNullable();
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.index(['scanId']);
  });

  await knex.schema.createTable('audit_logs', (t) => {
    t.uuid('id').primary();
    t.uuid('actorId').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.string('action', 255).notNullable();
    t.string('entity', 60).notNullable();
    t.string('entityId', 60).nullable();
    t.text('metadata');
    t.string('ip', 64).nullable();
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.index(['entityId']);
    t.index(['createdAt']);
  });

  await knex.schema.createTable('cve_cache', (t) => {
    t.string('key', 255).primary();
    t.text('payload').notNullable();
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.timestamp('expiresAt').notNullable();
  });

  await knex.schema.createTable('scan_schedules', (t) => {
    t.uuid('id').primary();
    t.uuid('targetId').notNullable().references('id').inTable('targets').onDelete('CASCADE');
    t.uuid('projectId').notNullable().references('id').inTable('projects').onDelete('CASCADE');
    t.string('cron', 100).notNullable();
    t.string('type', 20).notNullable().defaultTo('quick');
    t.string('mode', 20).notNullable().defaultTo('passive');
    t.boolean('enabled').notNullable().defaultTo(true);
    t.uuid('createdById').notNullable().references('id').inTable('users');
    t.timestamp('createdAt').notNullable().defaultTo(knex.fn.now());
    t.timestamp('lastRunAt').nullable();
    t.index(['targetId']);
  });
}

export async function down(knex: Knex): Promise<void> {
  const tables = [
    'scan_schedules',
    'cve_cache',
    'audit_logs',
    'scan_artifacts',
    'findings',
    'scans',
    'targets',
    'projects',
    'users',
  ];
  for (const table of tables) {
    await knex.schema.dropTableIfExists(table);
  }
}