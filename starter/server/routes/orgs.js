import { audit } from '../audit.js';
import { bumpPermVersion, newId, nowIso } from '../db.js';
import { badRequest, forbidden, notFound, selfRoleChange, send } from '../http.js';
import {
  assertCanModify,
  assertNotLastOwner,
  assertRoleExists,
  endActiveSessions,
  roleRanks,
} from '../lifecycle.js';
import { resolve } from '../permissions.js';
import {
  requireActive,
  requirePermission,
  requireText,
  visibleMembership,
  visibleOrg,
} from './helpers.js';

const THEMES = ['cobalt', 'amber', 'emerald', 'violet', 'coral'];

export function registerOrgRoutes(router, { db }) {
  // Specific member path must precede /members/:userId because the router is first-match-wins.
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    requireActive(ctx);
    assertNotLastOwner(db, params.org, ctx.userId);
    db.transaction(() => {
      revokeActiveGrants(db, params.org, ctx.userId);
      db.prepare("UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?")
        .run(params.org, ctx.userId);
      endActiveSessions(db, { orgId: params.org, userId: ctx.userId, reason: 'membership_removed' });
      audit(db, auditMeta(ctx, 'member.leave', 'user', ctx.userId));
    })();
    send(res, 200, { status: 'removed' });
  });

  router.get('/v1/orgs', (ctx, _params, res) => {
    requireActive(ctx);
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY o.name`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  router.post('/v1/orgs', (ctx, _params, res) => {
    requireActive(ctx);
    const name = requireText(ctx.body.name, 'name', { max: 120 });
    const id = newId('org');
    const theme = typeof ctx.body.theme === 'string' && ctx.body.theme.trim()
      ? ctx.body.theme.trim().slice(0, 40)
      : THEMES[Math.abs(hashText(id)) % THEMES.length];

    db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at)
         VALUES (?, ?, ?, 'owner', 'active', ?)`
      ).run(newId('mem'), id, ctx.userId, nowIso());
      audit(db, { ...auditMeta(ctx, 'org.create', 'organization', id), orgId: id });
    })();
    send(res, 201, { id, name, theme, role: 'owner' });
  });

  router.patch('/v1/orgs/:org', (ctx, params, res) => {
    visibleOrg(db, params.org);
    requirePermission(db, ctx, 'org:update', { action: 'org.update', targetType: 'organization', targetId: params.org });
    const name = requireText(ctx.body.name, 'name', { max: 120 });
    db.transaction(() => {
      db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name, params.org);
      audit(db, auditMeta(ctx, 'org.update', 'organization', params.org));
    })();
    send(res, 200, { id: params.org, name });
  });

  router.delete('/v1/orgs/:org', (ctx, params, res) => {
    visibleOrg(db, params.org);
    requirePermission(db, ctx, 'org:delete', { action: 'org.delete', targetType: 'organization', targetId: params.org });
    db.transaction(() => {
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), params.org);
      endActiveSessions(db, { orgId: params.org, reason: 'membership_removed' });
      audit(db, auditMeta(ctx, 'org.delete', 'organization', params.org));
    })();
    send(res, 200, { deleted: true });
  });

  router.get('/v1/orgs/:org/members', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:read', { action: 'member.list', targetType: 'organization', targetId: params.org });
    const members = db.prepare(
      `SELECT u.id, u.email, u.name, m.role, m.status, m.joined_at
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status <> 'removed'
        ORDER BY u.name, u.id`
    ).all(params.org);
    send(res, 200, { members });
  });

  router.patch('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:role:update', { action: 'member.role.update', targetType: 'user', targetId: params.userId });
    if (params.userId === ctx.userId) throw selfRoleChange();
    const target = visibleMembership(db, params.org, params.userId);
    const nextRole = requireText(ctx.body.role, 'role');
    assertRoleExists(db, nextRole);
    assertModification(db, ctx.role, target.role, nextRole);
    if (target.role === 'owner' && nextRole !== 'owner') assertNotLastOwner(db, params.org, params.userId);

    db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE id = ?')
        .run(nextRole, target.id);
      audit(db, auditMeta(ctx, 'member.role.update', 'user', params.userId));
    })();
    send(res, 200, { userId: params.userId, role: nextRole });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:remove', { action: 'member.suspend', targetType: 'user', targetId: params.userId });
    if (params.userId === ctx.userId) throw forbidden('you cannot suspend yourself', 'self_change');
    const target = visibleMembership(db, params.org, params.userId, ['active']);
    assertModification(db, ctx.role, target.role, target.role);
    assertNotLastOwner(db, params.org, params.userId);
    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE id = ?").run(target.id);
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
      audit(db, auditMeta(ctx, 'member.suspend', 'user', params.userId));
    })();
    send(res, 200, { userId: params.userId, status: 'suspended' });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:remove', { action: 'member.reinstate', targetType: 'user', targetId: params.userId });
    const target = visibleMembership(db, params.org, params.userId, ['suspended']);
    assertModification(db, ctx.role, target.role, target.role);
    db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'active', perm_version = perm_version + 1 WHERE id = ?").run(target.id);
      audit(db, auditMeta(ctx, 'member.reinstate', 'user', params.userId));
    })();
    send(res, 200, { userId: params.userId, status: 'active' });
  });

  router.delete('/v1/orgs/:org/members/:userId', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:remove', { action: 'member.remove', targetType: 'user', targetId: params.userId });
    if (params.userId === ctx.userId) throw forbidden('use the leave endpoint to remove yourself', 'self_change');
    const target = visibleMembership(db, params.org, params.userId);
    assertModification(db, ctx.role, target.role, target.role);
    assertNotLastOwner(db, params.org, params.userId);
    db.transaction(() => {
      revokeActiveGrants(db, params.org, params.userId);
      db.prepare("UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?").run(target.id);
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'membership_removed' });
      audit(db, auditMeta(ctx, 'member.remove', 'user', params.userId));
    })();
    send(res, 200, { userId: params.userId, status: 'removed' });
  });

  router.get('/v1/orgs/:org/users/:userId/effective', (ctx, params, res) => {
    if (params.userId !== ctx.userId) {
      requirePermission(db, ctx, 'user:read', { action: 'permission.read', targetType: 'user', targetId: params.userId });
    } else {
      requireActive(ctx);
    }
    visibleMembership(db, params.org, params.userId);
    send(res, 200, resolve(db, { userId: params.userId, orgId: params.org }));
  });

  router.get('/v1/orgs/:org/audit', (ctx, params, res) => {
    requirePermission(db, ctx, 'audit:read', { action: 'audit.read', targetType: 'organization', targetId: params.org });
    const limit = integerQuery(ctx.query.get('limit'), 50, 1, 500, 'limit');
    const offset = integerQuery(ctx.query.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER, 'offset');
    const events = db.prepare(
      `SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`
    ).all(params.org, limit, offset);
    send(res, 200, { events, limit, offset });
  });
}

function assertModification(db, callerRole, targetRole, nextRole) {
  if (callerRole === 'owner' && targetRole === 'owner') {
    if (nextRole !== undefined && nextRole !== 'owner') return;
    throw forbidden('owners may not modify an equal owner without demoting them', 'role_rank');
  }
  assertCanModify(db, callerRole, targetRole);
  if (nextRole !== undefined) {
    const ranks = roleRanks(db);
    if (nextRole === 'owner' && callerRole !== 'owner') throw forbidden('only an owner may confer owner', 'role_rank');
    if (nextRole !== 'owner' && ranks[callerRole] <= ranks[nextRole]) throw forbidden('you cannot assign this role', 'role_rank');
  }
}

function auditMeta(ctx, action, targetType, targetId) {
  return {
    orgId: ctx.orgId,
    actorId: ctx.userId,
    action,
    targetType,
    targetId,
    result: 'allow',
    requestId: ctx.requestId,
  };
}

function integerQuery(raw, fallback, min, max, field) {
  if (raw === null) return fallback;
  if (!/^-?\d+$/.test(raw)) throw badRequest(`${field} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw badRequest(`${field} is out of range`);
  return value;
}

function hashText(value) {
  let hash = 0;
  for (const char of value) hash = ((hash * 31) + char.charCodeAt(0)) | 0;
  return hash;
}

function revokeActiveGrants(db, orgId, userId) {
  db.prepare(
    `UPDATE grants SET revoked_at = ?
      WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL`
  ).run(nowIso(), orgId, userId);
}
