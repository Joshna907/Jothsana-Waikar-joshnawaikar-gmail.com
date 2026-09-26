import { auditDenials } from '../audit.js';
import { assertCan } from '../permissions.js';
import { badRequest, forbidden, notFound } from '../http.js';

export function requireActive(ctx) {
  if (ctx.membership?.status !== 'active') throw forbidden('membership is suspended', 'suspended');
}

export function requireText(value, field, { max = 200 } = {}) {
  if (typeof value !== 'string' || value.trim().length === 0) throw badRequest(`${field} is required`);
  const text = value.trim();
  if (text.length > max) throw badRequest(`${field} is too long`);
  return text;
}

export function requirePermission(db, ctx, permission, { deviceId, action, targetType, targetId } = {}) {
  requireActive(ctx);
  return auditDenials(db, ctx, { action: action ?? permission, targetType, targetId }, () =>
    assertCan(db, ctx, permission, deviceId)
  );
}

export function visibleOrg(db, orgId) {
  const org = db.prepare('SELECT * FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound();
  return org;
}

export function visibleDevice(db, orgId, deviceId) {
  const device = db.prepare(
    'SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
  ).get(deviceId, orgId);
  if (!device) throw notFound();
  return device;
}

export function visibleMembership(db, orgId, userId, statuses = ['active', 'suspended']) {
  const membership = db.prepare(
    `SELECT m.*, u.email, u.name
       FROM memberships m JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.user_id = ?`
  ).get(orgId, userId);
  if (!membership || !statuses.includes(membership.status)) throw notFound();
  return membership;
}

export const isConstraint = (error) => error?.code?.startsWith('SQLITE_CONSTRAINT');

