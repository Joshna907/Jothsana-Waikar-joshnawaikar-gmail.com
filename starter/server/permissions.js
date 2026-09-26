// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { badRequest, forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const model = loadModel(db, { userId, orgId, now });
  if (deviceId !== null) return resolvedForDevice(model, deviceId);

  const deviceIds = db.prepare(
    `SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY id`
  ).all(orgId).map((row) => row.id);

  return resolvedForOrg(model, deviceIds);
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const model = loadModel(db, { userId, orgId, now });
  const byDevice = {};
  for (const deviceId of deviceIds) {
    byDevice[deviceId] = resolvedForDevice(model, deviceId).permissions;
  }
  return { role: model.membership?.role ?? null, byDevice };
}

export function can(db, ctx, permission, deviceId) {
  return resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission]?.effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  const decision = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission];
  if (decision?.effect === 'allow') return;
  throw forbidden('missing required permission', decision?.reason === 'implicit' ? 'missing_permission' : decision?.reason);
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw badRequest('permissions must be a non-empty array');
  }

  const catalogue = db.prepare('SELECT key FROM permissions ORDER BY key').all().map((row) => row.key);
  const decisions = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions;
  for (const pattern of patterns) {
    const covered = catalogue.filter((permission) => patternMatches(pattern, permission));
    if (covered.length === 0) throw badRequest(`unknown permission pattern: ${pattern}`);
    for (const permission of covered) {
      const decision = decisions[permission];
      if (decision?.effect !== 'allow') {
        throw forbidden('cannot grant a permission you do not hold', denialReason(decision));
      }
    }
  }
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest('unknown session mode');

  const decisions = resolve(db, {
    userId: ctx.userId,
    orgId: ctx.orgId,
    deviceId,
  }).permissions;

  if (decisions['session:start']?.effect !== 'allow') {
    throw forbidden('missing permission to start sessions', 'missing_permission');
  }
  if (decisions[modePermission]?.effect !== 'allow') {
    throw forbidden('missing permission for this device action', 'missing_device_permission');
  }
}

function loadModel(db, { userId, orgId, now }) {
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?`
  ).get(userId, orgId);
  const permissions = db.prepare('SELECT key FROM permissions ORDER BY key').all().map((row) => row.key);

  if (!membership || membership.status !== 'active') {
    return { membership, permissions, baseline: new Set(), grants: [] };
  }

  const baseline = new Set(db.prepare(
    `SELECT permission FROM role_permissions WHERE role = ?`
  ).all(membership.role).map((row) => row.permission));

  const at = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  const grants = db.prepare(
    `SELECT g.id, g.device_id, g.effect, gp.permission
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
      WHERE g.user_id = ?
        AND g.org_id = ?
        AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR ? < g.expires_at)
      ORDER BY g.created_at, g.id, gp.permission`
  ).all(userId, orgId, at, at);

  return { membership, permissions, baseline, grants };
}

function resolvedForDevice(model, deviceId) {
  if (!model.membership) return deniedSet(model, null, 'not_a_member');
  if (model.membership.status === 'suspended') return deniedSet(model, model.membership.role, 'suspended');
  if (model.membership.status !== 'active') return deniedSet(model, model.membership.role, 'not_a_member');

  const permissions = {};
  for (const permission of model.permissions) {
    const applicable = model.grants.filter((grant) =>
      (grant.device_id === null || grant.device_id === deviceId) && patternMatches(grant.permission, permission)
    );
    const deny = applicable.find((grant) => grant.effect === 'deny');
    if (deny) {
      permissions[permission] = { effect: 'deny', source: `grant:${deny.id}`, reason: 'explicit_deny' };
      continue;
    }

    if (model.baseline.has(permission)) {
      permissions[permission] = { effect: 'allow', source: `role:${model.membership.role}`, reason: null };
      continue;
    }

    const allow = applicable.find((grant) => grant.effect === 'allow');
    permissions[permission] = allow
      ? { effect: 'allow', source: `grant:${allow.id}`, reason: null }
      : { effect: 'deny', source: null, reason: 'implicit' };
  }

  return { role: model.membership.role, permissions };
}

function resolvedForOrg(model, deviceIds) {
  if (!model.membership || model.membership.status !== 'active') return resolvedForDevice(model, null);
  if (deviceIds.length === 0) return resolvedForDevice(model, null);

  const deviceSets = deviceIds.map((id) => resolvedForDevice(model, id).permissions);
  const permissions = {};
  for (const permission of model.permissions) {
    const decisions = deviceSets.map((set) => set[permission]);
    const allow = decisions.find((decision) => decision.effect === 'allow');
    if (allow) {
      permissions[permission] = allow;
      continue;
    }
    const explicitDeny = decisions.find((decision) => decision.reason === 'explicit_deny');
    permissions[permission] = explicitDeny ?? { effect: 'deny', source: null, reason: 'implicit' };
  }
  return { role: model.membership.role, permissions };
}

function deniedSet(model, role, reason) {
  return {
    role,
    permissions: Object.fromEntries(
      model.permissions.map((permission) => [permission, { effect: 'deny', source: null, reason }])
    ),
  };
}

function patternMatches(pattern, permission) {
  return pattern === '*' || pattern === permission || (pattern.endsWith(':*') && permission.startsWith(pattern.slice(0, -1)));
}

function denialReason(decision) {
  return !decision || decision.reason === 'implicit' ? 'missing_permission' : decision.reason;
}
