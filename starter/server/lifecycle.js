// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { badRequest, forbidden, lastOwner } from './http.js';
import { nowIso } from './db.js';
import { resolve } from './permissions.js';

export function roleRanks(db) {
  return Object.fromEntries(db.prepare('SELECT key, rank FROM roles').all().map((row) => [row.key, row.rank]));
}

export function assertRoleExists(db, role) {
  const found = db.prepare('SELECT key, rank, label FROM roles WHERE key = ?').get(role);
  if (!found) throw badRequest('unknown role');
  return found;
}

export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  if (ranks[callerRole] === undefined || ranks[targetRole] === undefined || ranks[callerRole] <= ranks[targetRole]) {
    throw forbidden('you cannot modify this member', 'role_rank');
  }
}

export function assertNotLastOwner(db, orgId, userId) {
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId);
  if (!membership || membership.role !== 'owner' || membership.status !== 'active') return;

  const { count } = db.prepare(
    `SELECT count(*) AS count FROM memberships
      WHERE org_id = ? AND role = 'owner' AND status = 'active'`
  ).get(orgId);
  if (count <= 1) throw lastOwner();
}

export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const clauses = ["state IN ('connecting','active')"];
  const values = [];
  if (orgId !== undefined) { clauses.push('org_id = ?'); values.push(orgId); }
  if (userId !== undefined) { clauses.push('user_id = ?'); values.push(userId); }
  if (deviceId !== undefined) { clauses.push('device_id = ?'); values.push(deviceId); }
  if (exceptSessionId !== undefined) { clauses.push('id <> ?'); values.push(exceptSessionId); }

  return db.prepare(
    `UPDATE sessions
        SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE ${clauses.join(' AND ')}`
  ).run(reason, nowIso(), ...values).changes;
}

export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const resolved = resolve(db, { userId, orgId, deviceId });
  const grantIds = [...new Set(Object.values(resolved.permissions)
    .map((decision) => decision.source)
    .filter((source) => source?.startsWith('grant:'))
    .map((source) => source.slice('grant:'.length)))];
  return { role: resolved.role, grantIds, snapshotAt: nowIso() };
}

export function sessionExpiry(db, orgId) {
  const org = db.prepare(
    `SELECT max_session_minutes FROM organizations WHERE id = ? AND deleted_at IS NULL`
  ).get(orgId);
  if (!org) throw badRequest('organization does not exist');
  return new Date(Date.now() + org.max_session_minutes * 60_000).toISOString();
}
