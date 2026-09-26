import { audit } from '../audit.js';
import { bumpPermVersion, newId, nowIso } from '../db.js';
import { badRequest, conflict, forbidden, notFound, normalizeTs, send } from '../http.js';
import { endActiveSessions } from '../lifecycle.js';
import { assertMayGrant, resolveDevices } from '../permissions.js';
import {
  isConstraint,
  requireActive,
  requirePermission,
  requireText,
  visibleDevice,
  visibleMembership,
  visibleOrg,
} from './helpers.js';

const DEVICE_KINDS = new Set(['macos', 'windows', 'linux', 'android', 'ios']);

export function registerDeviceRoutes(router, { db }) {
  router.get('/v1/orgs/:org/devices', (ctx, params, res) => {
    requirePermission(db, ctx, 'device:list', { action: 'device.list', targetType: 'organization', targetId: params.org });
    const rows = db.prepare(
      `SELECT id, name, kind, online, created_at FROM devices
        WHERE org_id = ? AND deleted_at IS NULL ORDER BY name, id`
    ).all(params.org);
    const resolved = resolveDevices(db, {
      userId: ctx.userId,
      orgId: params.org,
      deviceIds: rows.map((row) => row.id),
    });
    const devices = rows
      .filter((row) => resolved.byDevice[row.id]['device:view']?.effect === 'allow')
      .map((row) => ({ ...row, online: Boolean(row.online), permissions: resolved.byDevice[row.id] }));
    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = visibleDevice(db, params.org, params.id);
    requirePermission(db, ctx, 'device:view', {
      deviceId: device.id,
      action: 'device.view',
      targetType: 'device',
      targetId: device.id,
    });
    const permissions = resolveDevices(db, {
      userId: ctx.userId,
      orgId: params.org,
      deviceIds: [device.id],
    }).byDevice[device.id];
    send(res, 200, { ...device, online: Boolean(device.online), permissions });
  });

  router.post('/v1/orgs/:org/devices', (ctx, params, res) => {
    requirePermission(db, ctx, 'device:provision', { action: 'device.create', targetType: 'organization', targetId: params.org });
    const name = requireText(ctx.body.name, 'name', { max: 120 });
    const kind = requireText(ctx.body.kind, 'kind');
    if (!DEVICE_KINDS.has(kind)) throw badRequest('unknown device kind');
    const id = newId('dev');
    db.transaction(() => {
      db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, ?)')
        .run(id, params.org, name, kind, ctx.body.online ? 1 : 0);
      audit(db, successMeta(ctx, 'device.create', 'device', id));
    })();
    send(res, 201, { id, name, kind, online: Boolean(ctx.body.online) });
  });

  router.patch('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = visibleDevice(db, params.org, params.id);
    requirePermission(db, ctx, 'device:update', { deviceId: device.id, action: 'device.update', targetType: 'device', targetId: device.id });
    const name = ctx.body.name === undefined ? device.name : requireText(ctx.body.name, 'name', { max: 120 });
    const online = ctx.body.online === undefined ? device.online : (ctx.body.online ? 1 : 0);
    db.transaction(() => {
      db.prepare('UPDATE devices SET name = ?, online = ? WHERE id = ?').run(name, online, device.id);
      audit(db, successMeta(ctx, 'device.update', 'device', device.id));
    })();
    send(res, 200, { id: device.id, name, kind: device.kind, online: Boolean(online) });
  });

  router.delete('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = visibleDevice(db, params.org, params.id);
    requirePermission(db, ctx, 'device:provision', { deviceId: device.id, action: 'device.delete', targetType: 'device', targetId: device.id });
    db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), device.id);
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
      audit(db, successMeta(ctx, 'device.delete', 'device', device.id));
    })();
    send(res, 200, { deleted: true });
  });

  router.post('/v1/orgs/:org/devices/:id/transfer', (ctx, params, res) => {
    const device = visibleDevice(db, params.org, params.id);
    requirePermission(db, ctx, 'device:provision', { deviceId: device.id, action: 'device.transfer', targetType: 'device', targetId: device.id });
    const targetOrgId = requireText(ctx.body.orgId, 'orgId');
    if (targetOrgId === params.org) throw badRequest('device is already in this organization');
    visibleOrg(db, targetOrgId);
    const targetMembership = visibleMembership(db, targetOrgId, ctx.userId, ['active']);
    const targetCtx = { ...ctx, orgId: targetOrgId, role: targetMembership.role, membership: targetMembership };
    assertMayGrant(db, targetCtx, ['device:provision']);

    db.transaction(() => {
      endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
      const affected = db.prepare(
        `SELECT DISTINCT user_id FROM grants WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL`
      ).all(params.org, device.id);
      db.prepare('UPDATE grants SET revoked_at = ? WHERE org_id = ? AND device_id = ? AND revoked_at IS NULL')
        .run(nowIso(), params.org, device.id);
      for (const row of affected) bumpPermVersion(db, { orgId: params.org, userId: row.user_id });
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, device.id);
      audit(db, successMeta(ctx, 'device.transfer', 'device', device.id));
    })();
    send(res, 200, { id: device.id, orgId: targetOrgId });
  });

  router.get('/v1/orgs/:org/grants', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:read', { action: 'grant.list', targetType: 'organization', targetId: params.org });
    const rows = db.prepare(
      `SELECT * FROM grants WHERE org_id = ? AND revoked_at IS NULL ORDER BY created_at DESC, id`
    ).all(params.org);
    const permissionRows = db.prepare(
      `SELECT gp.grant_id, gp.permission
         FROM grant_permissions gp JOIN grants g ON g.id = gp.grant_id
        WHERE g.org_id = ? ORDER BY gp.grant_id, gp.permission`
    ).all(params.org);
    const byGrant = Object.groupBy(permissionRows, (row) => row.grant_id);
    const grants = rows.map((row) => ({
      ...row,
      permissions: (byGrant[row.id] ?? []).map((item) => item.permission),
    }));
    send(res, 200, { grants });
  });

  router.post('/v1/orgs/:org/grants', (ctx, params, res) => {
    requirePermission(db, ctx, 'grant:create', { action: 'grant.create', targetType: 'organization', targetId: params.org });
    const userId = requireText(ctx.body.userId, 'userId');
    if (userId === ctx.userId) throw forbidden('you cannot grant permissions to yourself', 'self_grant');
    visibleMembership(db, params.org, userId, ['active']);

    const effect = requireText(ctx.body.effect, 'effect');
    if (!['allow', 'deny'].includes(effect)) throw badRequest('effect must be allow or deny');
    const permissions = ctx.body.permissions;
    if (!Array.isArray(permissions) || permissions.length === 0) throw badRequest('permissions must be a non-empty array');
    if (permissions.some((value) => typeof value !== 'string')) throw badRequest('permissions must contain strings');

    const validPatterns = new Set(db.prepare('SELECT pattern FROM permission_patterns').all().map((row) => row.pattern));
    for (const permission of permissions) {
      if (!validPatterns.has(permission)) throw badRequest('unknown permission', 'unknown_permission');
    }

    const deviceId = ctx.body.deviceId ?? null;
    if (deviceId !== null) visibleDevice(db, params.org, deviceId);
    const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
    const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
    if (expiresAt !== null && expiresAt <= nowIso()) throw badRequest('grant is already expired', 'expired_grant');
    if (startsAt !== null && expiresAt !== null && expiresAt <= startsAt) throw badRequest('expiresAt must be after startsAt');
    assertMayGrant(db, ctx, permissions, deviceId);

    const id = newId('grt');
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(id, params.org, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
        const insertPermission = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
        for (const permission of new Set(permissions)) insertPermission.run(id, permission);
        bumpPermVersion(db, { orgId: params.org, userId });
        audit(db, successMeta(ctx, 'grant.create', 'grant', id));
      })();
    } catch (error) {
      if (isConstraint(error)) throw badRequest('grant violates a database constraint');
      throw error;
    }
    send(res, 201, { id, userId, deviceId, effect, startsAt, expiresAt, permissions: [...new Set(permissions)] });
  });

  router.delete('/v1/orgs/:org/grants/:id', (ctx, params, res) => {
    requirePermission(db, ctx, 'grant:revoke', { action: 'grant.revoke', targetType: 'grant', targetId: params.id });
    const grant = db.prepare(
      `SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL`
    ).get(params.id, params.org);
    if (!grant) throw notFound();
    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), grant.id);
      bumpPermVersion(db, { orgId: params.org, userId: grant.user_id });
      audit(db, successMeta(ctx, 'grant.revoke', 'grant', grant.id));
    })();
    send(res, 200, { revoked: true });
  });
}

function successMeta(ctx, action, targetType, targetId) {
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
