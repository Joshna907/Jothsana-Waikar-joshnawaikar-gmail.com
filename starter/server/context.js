// Per-request context: turn a bearer token into an authenticated caller.
//
// What it has to do (BRIEF.md §3, PERMISSIONS.md §6):
//   - read the bearer token, verify it with verifyAccessToken() from ./auth.js
//   - look the membership up and refuse a token whose org or membership is gone
//   - THE TOKEN'S org CLAIM IS THE ONLY ORG THE CALLER MAY ADDRESS. A request that
//     names a different org is INVISIBLE — 404, never 403. Isolation is structural:
//     the caller cannot name another org, rather than being filtered afterwards.
//   - check freshness against memberships.perm_version (AUTH-DATA-MODEL.md §3), so a
//     role or grant change takes effect on the NEXT request, not at token expiry
//   - throw through the one error path in ./http.js
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries at
// least { userId, orgId, role, membership, claims }.

import { assertFresh, verifyAccessToken } from './auth.js';
import { notFound, unauthenticated } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const authorization = req.headers.authorization;
    const match = typeof authorization === 'string' && /^Bearer\s+([^\s]+)$/i.exec(authorization.trim());
    if (!match) throw unauthenticated('missing bearer token');

    const claims = verifyAccessToken(match[1], secret);

    // The token chooses the organization. Do this before any route can query a
    // resource in another organization, so a cross-org request is invisible.
    if (params.org !== undefined && params.org !== claims.org) throw notFound();

    const membership = db.prepare(
      `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
         FROM memberships m
         JOIN organizations o ON o.id = m.org_id
        WHERE m.org_id = ? AND m.user_id = ? AND o.deleted_at IS NULL`
    ).get(claims.org, claims.sub);

    if (!membership || !['active', 'suspended'].includes(membership.status)) {
      throw unauthenticated('not an active member of this organization');
    }

    // Suspension is intentionally distinguishable from invalid credentials. It
    // bumps perm_version, but suspended callers must still reach requireActive()
    // and receive the documented 403/suspended response on every protected route.
    // Removed memberships remain a 401 above.
    if (membership.status === 'active') assertFresh(claims, membership);

    return {
      userId: membership.user_id,
      orgId: membership.org_id,
      role: membership.role,
      membership,
      claims,
    };
  };
}
