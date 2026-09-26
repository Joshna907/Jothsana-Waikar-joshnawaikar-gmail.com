// Focused checks for seams that are easy to miss while the public happy paths pass.
// This script owns a throwaway database and a private server port.

import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, rmSync } from 'node:fs';

import { openDatabase } from '../server/db.js';
import { assertMayGrant } from '../server/permissions.js';

const PORT = 8125;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'check-hardening.db';

for (const suffix of ['', '-wal', '-shm']) {
  if (existsSync(DB + suffix)) rmSync(DB + suffix);
}
execFileSync(process.execPath, ['scripts/load-db.js'], {
  env: { ...process.env, DATABASE_FILE: DB },
  stdio: 'ignore',
});

let passed = 0;
let failed = 0;
function check(label, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? passed++ : failed++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(58)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
}

console.log('\n== exact-scope grant authority ==');
{
  const db = openDatabase(DB);
  try {
    assertMayGrant(db, { userId: 'usr_dana', orgId: 'org_globex' }, ['device:control']);
    check('device grant cannot become an org-wide grant', 'allowed', 'scope_mismatch');
  } catch (error) {
    check('device grant cannot become an org-wide grant', error.reason, 'scope_mismatch');
  } finally {
    db.close();
  }
}

const server = spawn(process.execPath, ['server/index.js'], {
  env: {
    ...process.env,
    DATABASE_FILE: DB,
    PORT: String(PORT),
    NODE_ENV: 'production',
    JWT_SECRET: 'hardening-secret',
    APP_HASH_KEY: 'hardening-hash-key',
  },
  stdio: ['ignore', 'ignore', 'inherit'],
});

async function call(method, path, { token, body, cookie } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    body: await response.json(),
    cookie: response.headers.get('set-cookie'),
  };
}

const login = (email, orgId) => call('POST', '/auth/login', {
  body: { email, password: 'demo1234', ...(orgId ? { orgId } : {}) },
});

await new Promise((resolve) => setTimeout(resolve, 1200));
try {
  console.log('\n== suspended tokens reach the suspension boundary ==');
  const owner = await login('dana@example.test', 'org_acme');
  const viewer = await login('viewer@acme.test', 'org_acme');
  await call('POST', '/orgs/org_acme/members/usr_acme_viewer/suspend', {
    token: owner.body.token,
    body: {},
  });
  const suspended = await call('GET', '/orgs/org_acme/devices', {
    token: viewer.body.token,
  });
  check('suspended member receives 403', suspended.status, 403);
  check('suspension reason is preserved', suspended.body.error.reason, 'suspended');
  await call('DELETE', '/orgs/org_acme/members/usr_acme_viewer/suspend', {
    token: owner.body.token,
  });

  console.log('\n== sign-out revokes the refresh-token family ==');
  const session = await login('sam@example.test', 'org_acme');
  const cookie = session.cookie?.split(';', 1)[0];
  const logout = await call('POST', '/auth/refresh/logout', { cookie, body: {} });
  check('logout is idempotent success', logout.status, 200);
  check('logout clears the cookie', logout.cookie?.includes('Max-Age=0'), true);
  check('old refresh token no longer works', (await call('POST', '/auth/refresh', { cookie, body: {} })).status, 401);

  console.log('\n== offboard then rehire does not restore old grants ==');
  check('remove member', (await call('DELETE', '/orgs/org_acme/members/usr_acme_viewer', { token: owner.body.token })).status, 200);
  const invite = await call('POST', '/orgs/org_acme/invites', {
    token: owner.body.token,
    body: { email: 'viewer@acme.test', role: 'viewer' },
  });
  check('removed member can be invited again', invite.status, 201);
  check('rehire succeeds', (await call('POST', `/invites/${invite.body.inviteToken}/accept`, {
    body: { name: 'Acme Viewer', password: 'not-used-for-existing-user' },
  })).status, 200);

  const db = openDatabase(DB);
  const activeGrantCount = db.prepare(
    `SELECT count(*) AS count FROM grants
      WHERE org_id = 'org_acme' AND user_id = 'usr_acme_viewer' AND revoked_at IS NULL`,
  ).get().count;
  db.close();
  check('rehired member has no surviving old grants', activeGrantCount, 0);
} finally {
  server.kill();
  await once(server, 'exit');
  for (const suffix of ['', '-wal', '-shm']) {
    if (existsSync(DB + suffix)) rmSync(DB + suffix);
  }
}

console.log(`\n${failed === 0 ? 'ALL PASS' : 'FAILURES'} — ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
