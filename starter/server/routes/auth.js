import {
  REFRESH_TTL_SECONDS,
  hashRefreshToken,
  issueAccessToken,
  newRefreshToken,
  verifyPassword,
} from "../auth.js";
import { newId, nowIso } from "../db.js";
import { badRequest, send, unauthenticated } from "../http.js";
import { resolve } from "../permissions.js";
import { requireActive, requireText } from "./helpers.js";

export function registerAuthRoutes(router, { db, secret }) {
  router.post("/v1/auth/login", (ctx, _params, res) => {
    const email = normalizeEmail(ctx.body.email);
    const password =
      typeof ctx.body.password === "string" ? ctx.body.password : "";
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !verifyPassword(password, user.password_hash))
      throw unauthenticated("invalid email or password");

    const memberships = activeMemberships(db, user.id);
    const membership = ctx.body.orgId
      ? memberships.find((entry) => entry.org_id === ctx.body.orgId)
      : memberships[0];
    if (!membership) throw unauthenticated("invalid email or password");

    const token = accessFor(membership, secret);
    issueRefreshCookie(db, res, user.id);
    send(res, 200, loginBody(db, user, membership, memberships, token));
  });

  router.post("/v1/auth/refresh", (ctx, _params, res) => {
    const raw = cookieValue(ctx.req.headers.cookie, "remoteops_refresh");
    if (!raw) throw unauthenticated("missing refresh token");

    const stored = db
      .prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?")
      .get(hashRefreshToken(raw));
    if (!stored) throw unauthenticated("invalid refresh token");
    if (stored.revoked_at) {
      db.prepare(
        "UPDATE refresh_tokens SET revoked_at = coalesce(revoked_at, ?) WHERE family_id = ?",
      ).run(nowIso(), stored.family_id);
      throw unauthenticated("refresh token replayed");
    }
    if (stored.expires_at <= nowIso())
      throw unauthenticated("refresh token expired");

    const memberships = activeMemberships(db, stored.user_id);
    const membership = ctx.body.orgId
      ? memberships.find((entry) => entry.org_id === ctx.body.orgId)
      : memberships[0];
    if (!membership) throw unauthenticated("no active organization");

    const rotated = db.transaction(() => {
      const changed = db
        .prepare(
          "UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        )
        .run(nowIso(), stored.id).changes;
      if (changed !== 1) throw unauthenticated("refresh token replayed");
      return createRefresh(db, stored.user_id, stored.family_id);
    })();

    const user = db
      .prepare("SELECT id, email, name FROM users WHERE id = ?")
      .get(stored.user_id);
    setRefreshCookie(res, rotated.raw);
    send(
      res,
      200,
      loginBody(
        db,
        user,
        membership,
        memberships,
        accessFor(membership, secret),
      ),
    );
  });

  // The refresh cookie is deliberately scoped to /v1/auth/refresh. Keeping the
  // logout endpoint below that path lets the browser send and clear the HttpOnly
  // credential without widening its exposure to unrelated API routes.
  router.post("/v1/auth/refresh/logout", (ctx, _params, res) => {
    const raw = cookieValue(ctx.req.headers.cookie, "remoteops_refresh");
    if (raw) {
      const stored = db
        .prepare("SELECT family_id FROM refresh_tokens WHERE token_hash = ?")
        .get(hashRefreshToken(raw));
      if (stored) {
        db.prepare(
          "UPDATE refresh_tokens SET revoked_at = coalesce(revoked_at, ?) WHERE family_id = ?",
        ).run(nowIso(), stored.family_id);
      }
    }
    clearRefreshCookie(res);
    send(res, 200, { signedOut: true });
  });

  router.post("/v1/auth/token", (ctx, _params, res) => {
    requireActive(ctx);
    const orgId = requireText(ctx.body.orgId, "orgId");
    const membership = db
      .prepare(
        `SELECT m.*, o.name AS org_name, o.theme
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`,
      )
      .get(ctx.userId, orgId);
    if (!membership)
      throw unauthenticated("not an active member of this organization");
    send(res, 200, {
      token: accessFor(membership, secret),
      role: membership.role,
      orgId,
    });
  });

  router.get("/v1/auth/me", (ctx, _params, res) => {
    requireActive(ctx);
    const user = db
      .prepare("SELECT id, email, name FROM users WHERE id = ?")
      .get(ctx.userId);
    const memberships = activeMemberships(db, ctx.userId);
    send(res, 200, {
      user,
      orgId: ctx.orgId,
      role: ctx.role,
      orgs: memberships.map(orgShape),
      roles: roleCatalogue(db),
      permissions: resolve(db, { userId: ctx.userId, orgId: ctx.orgId })
        .permissions,
    });
  });
}

function normalizeEmail(value) {
  const email = requireText(value, "email", { max: 320 }).toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) throw badRequest("email is invalid");
  return email;
}

function activeMemberships(db, userId) {
  return db
    .prepare(
      `SELECT m.*, o.name AS org_name, o.theme
       FROM memberships m JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY m.joined_at, o.id`,
    )
    .all(userId);
}

function orgShape(row) {
  return {
    id: row.org_id,
    name: row.org_name,
    theme: row.theme,
    role: row.role,
  };
}

function accessFor(membership, secret) {
  return issueAccessToken(
    {
      userId: membership.user_id,
      orgId: membership.org_id,
      role: membership.role,
      permVersion: membership.perm_version,
    },
    secret,
  );
}

function loginBody(db, user, membership, memberships, token) {
  return {
    token,
    user: { id: user.id, email: user.email, name: user.name },
    orgId: membership.org_id,
    role: membership.role,
    orgs: memberships.map(orgShape),
    roles: roleCatalogue(db),
    permissions: resolve(db, { userId: user.id, orgId: membership.org_id })
      .permissions,
  };
}

function roleCatalogue(db) {
  return db
    .prepare("SELECT key, label, rank FROM roles ORDER BY rank DESC, key")
    .all();
}

function createRefresh(db, userId, familyId = newId("fam")) {
  const raw = newRefreshToken();
  const expiresAt = new Date(
    Date.now() + REFRESH_TTL_SECONDS * 1000,
  ).toISOString();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(newId("rft"), userId, hashRefreshToken(raw), familyId, expiresAt);
  return { raw, expiresAt };
}

function setRefreshCookie(res, raw) {
  res.setHeader(
    "set-cookie",
    `remoteops_refresh=${raw}; HttpOnly; SameSite=Strict; Secure; Path=/v1/auth/refresh; Max-Age=${REFRESH_TTL_SECONDS}`,
  );
}

function clearRefreshCookie(res) {
  res.setHeader(
    "set-cookie",
    "remoteops_refresh=; HttpOnly; SameSite=Strict; Secure; Path=/v1/auth/refresh; Max-Age=0",
  );
}

export function issueRefreshCookie(db, res, userId, familyId) {
  const refresh = createRefresh(db, userId, familyId);
  setRefreshCookie(res, refresh.raw);
  return refresh;
}

function cookieValue(header, name) {
  if (typeof header !== "string") return null;
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}
