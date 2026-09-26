import { audit } from '../audit.js';
import { hashInviteToken, hashPassword, issueAccessToken, newInviteToken } from '../auth.js';
import { newId, nowIso } from '../db.js';
import { badRequest, conflict, forbidden, gone, notFound, send } from '../http.js';
import { assertCanModify, assertRoleExists, roleRanks } from '../lifecycle.js';
import { issueRefreshCookie } from './auth.js';
import { isConstraint, requirePermission, requireText } from './helpers.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export function registerInviteRoutes(router, { db, secret }) {
  router.post('/v1/orgs/:org/invites', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:invite', { action: 'invite.create', targetType: 'organization', targetId: params.org });
    const email = normalizeEmail(ctx.body.email);
    const role = requireText(ctx.body.role, 'role');
    assertRoleExists(db, role);
    assertAssignable(db, ctx.role, role);

    const existing = db.prepare(
      `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active','suspended','invited')`
    ).get(params.org, email);
    if (existing) throw conflict('this email already belongs to the organization');

    const raw = newInviteToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(id, params.org, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
        audit(db, successMeta(ctx, 'invite.create', 'invite', id));
      })();
    } catch (error) {
      if (isConstraint(error)) throw conflict('a live invite already exists for this email');
      throw error;
    }
    send(res, 201, { id, email, role, expiresAt, inviteToken: raw });
  });

  router.get('/v1/orgs/:org/invites', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:invite', { action: 'invite.list', targetType: 'organization', targetId: params.org });
    const invites = db.prepare(
      `SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
         FROM invites WHERE org_id = ? ORDER BY created_at DESC`
    ).all(params.org);
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', (ctx, params, res) => {
    requirePermission(db, ctx, 'user:invite', { action: 'invite.revoke', targetType: 'invite', targetId: params.id });
    const invite = db.prepare(
      `SELECT * FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
    ).get(params.id, params.org);
    if (!invite) throw notFound();
    db.transaction(() => {
      db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
      audit(db, successMeta(ctx, 'invite.revoke', 'invite', params.id));
    })();
    send(res, 200, { revoked: true });
  });

  router.get('/v1/invites/:token', (ctx, params, res) => {
    const invite = inviteByToken(db, params.token);
    assertInviteUsable(invite);
    const org = db.prepare('SELECT name FROM organizations WHERE id = ? AND deleted_at IS NULL').get(invite.org_id);
    if (!org) throw notFound();
    send(res, 200, { orgName: org.name, role: invite.role, email: invite.email, expiresAt: invite.expires_at });
  });

  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const invite = inviteByToken(db, params.token);
    assertInviteUsable(invite);
    const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(invite.org_id);
    if (!org) throw gone('the invited organization is no longer available');
    const name = requireText(ctx.body.name, 'name', { max: 120 });
    const password = requireText(ctx.body.password, 'password', { max: 1000 });
    if (password.length < 10) throw badRequest('password must be at least 10 characters');

    let user;
    try {
      user = db.transaction(() => {
        const changed = db.prepare(
          `UPDATE invites SET accepted_at = ?, accepted_by = coalesce(accepted_by, ?)
            WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
        ).run(nowIso(), null, invite.id).changes;
        if (changed !== 1) throw conflict('invite has already been accepted');

        let found = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
        if (!found) {
          const userId = newId('usr');
          db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
            .run(userId, invite.email, name, hashPassword(password));
          found = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        }

        const membership = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
          .get(invite.org_id, found.id);
        if (membership?.status === 'active') throw conflict('user is already a member');
        if (membership) {
          db.prepare(
            `UPDATE memberships
                SET role = ?, status = 'active', joined_at = ?, perm_version = perm_version + 1
              WHERE id = ?`
          ).run(invite.role, nowIso(), membership.id);
        } else {
          db.prepare(
            `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at)
             VALUES (?, ?, ?, ?, 'active', ?, ?)`
          ).run(newId('mem'), invite.org_id, found.id, invite.role, invite.invited_by, nowIso());
        }
        db.prepare('UPDATE invites SET accepted_by = ? WHERE id = ?').run(found.id, invite.id);
        audit(db, {
          orgId: invite.org_id,
          actorId: found.id,
          action: 'invite.accept',
          targetType: 'invite',
          targetId: invite.id,
          result: 'allow',
          requestId: ctx.requestId,
        });
        return found;
      })();
    } catch (error) {
      if (isConstraint(error)) throw conflict('invite could not be accepted');
      throw error;
    }

    const membership = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?')
      .get(invite.org_id, user.id);
    issueRefreshCookie(db, res, user.id);
    send(res, 200, {
      token: issueAccessToken({
        userId: user.id,
        orgId: invite.org_id,
        role: membership.role,
        permVersion: membership.perm_version,
      }, secret),
      role: membership.role,
      orgId: invite.org_id,
    });
  });
}

function inviteByToken(db, token) {
  if (typeof token !== 'string' || token.length < 20) throw notFound();
  const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(hashInviteToken(token));
  if (!invite) throw notFound();
  return invite;
}

function assertInviteUsable(invite) {
  if (invite.accepted_at) throw conflict('invite has already been accepted');
  if (invite.revoked_at || invite.expires_at <= nowIso()) throw gone();
}

function normalizeEmail(value) {
  const email = requireText(value, 'email', { max: 320 }).toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) throw badRequest('email is invalid');
  return email;
}

function assertAssignable(db, callerRole, role) {
  if (role === 'owner') {
    if (callerRole !== 'owner') throw forbidden('only an owner may confer owner', 'role_rank');
    return;
  }
  const ranks = roleRanks(db);
  if (ranks[callerRole] <= ranks[role]) assertCanModify(db, callerRole, role);
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
