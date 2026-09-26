import { audit, auditDenials } from '../audit.js';
import { newId, nowIso } from '../db.js';
import { deviceBusy, forbidden, notFound, send } from '../http.js';
import { sessionExpiry, snapshotAuthority } from '../lifecycle.js';
import { assertCan, assertCanStartSession } from '../permissions.js';
import { requireActive, requirePermission, visibleDevice } from './helpers.js';

export function registerSessionRoutes(router, { db }) {
  router.post('/v1/orgs/:org/sessions', (ctx, params, res) => {
    requireActive(ctx);
    const device = visibleDevice(db, params.org, ctx.body.deviceId);
    const mode = ctx.body.mode;
    auditDenials(db, ctx, {
      action: 'session.start',
      targetType: 'device',
      targetId: device.id,
    }, () => assertCanStartSession(db, ctx, mode, device.id));

    expireSessions(db);
    const id = newId('ses');
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO sessions
             (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
        ).run(
          id,
          params.org,
          ctx.userId,
          device.id,
          mode,
          JSON.stringify(snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId: device.id })),
          sessionExpiry(db, params.org)
        );
        audit(db, successMeta(ctx, 'session.start', 'session', id));
      })();
    } catch (error) {
      if (error?.code?.startsWith('SQLITE_CONSTRAINT_UNIQUE')) throw deviceBusy();
      throw error;
    }
    send(res, 201, sessionById(db, id));
  });

  router.get('/v1/orgs/:org/sessions', (ctx, params, res) => {
    requirePermission(db, ctx, 'session:view', { action: 'session.list', targetType: 'organization', targetId: params.org });
    expireSessions(db);
    const sessions = db.prepare(
      `SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC, id DESC`
    ).all(params.org).map(parseSession);
    send(res, 200, { sessions });
  });

  router.get('/v1/sessions/:id', (ctx, params, res) => {
    expireSessions(db);
    const session = sessionById(db, params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();
    requireActive(ctx);
    if (session.user_id !== ctx.userId) assertCan(db, ctx, 'session:view');
    send(res, 200, session);
  });

  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    expireSessions(db);
    const session = sessionById(db, params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();
    requireActive(ctx);
    const own = session.user_id === ctx.userId;
    if (!own) {
      auditDenials(db, ctx, {
        action: 'session.terminate',
        targetType: 'session',
        targetId: session.id,
      }, () => assertCan(db, ctx, 'session:terminate'));
    }
    if (session.state !== 'active' && session.state !== 'connecting') throw notFound();
    const reason = own ? 'user_stopped' : 'admin_terminated';
    db.transaction(() => {
      db.prepare(
        `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
          WHERE id = ? AND state IN ('connecting','active')`
      ).run(reason, nowIso(), session.id);
      audit(db, successMeta(ctx, 'session.terminate', 'session', session.id));
    })();
    send(res, 200, sessionById(db, session.id));
  });
}

function expireSessions(db) {
  const at = nowIso();
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = ?
      WHERE state IN ('connecting','active') AND expires_at <= ?`
  ).run(at, at);
}

function sessionById(db, id) {
  const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  return row ? parseSession(row) : null;
}

function parseSession(row) {
  return { ...row, authorized_by: JSON.parse(row.authorized_by) };
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
