# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

### 2026-09-26 · Setup was not as automatic as I expected

I started with Node 24.19.0 because that was already installed and assumed `npm ci` would be the
boring part. It was not: `better-sqlite3` had no prebuilt binary for that version, then `node-gyp`
sent me towards the Visual Studio C++ build tools. The useful clue was actually the repo's
`.nvmrc`, which says Node 22. After switching to Node 22.22.3, the same install completed in about
14 seconds with 0 vulnerabilities.

The next failure looked like I had typed a path twice: the loader tried to open
`C:\C:\Users\dell\Desktop\rhinostream\starter\db\schema.sql`. The command was fine. The path came
from `new URL(...).pathname`, whose result was being passed directly to the Windows filesystem.
I changed that conversion to `fileURLToPath(new URL(...))`. After that, the load completed with
3 organizations, 20 permissions, and the personalized `reviewer` / `device:reboot` data. That
also made the warning about hardcoding the documented matrix concrete rather than theoretical.

With setup working, the untouched JWT suite was 0/43. This was the expected failure: every case
was reaching the deliberate `verifyAccessToken` stub.

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

### 2026-09-26 · The decoder was more forgiving than the verifier should be

My first model was straightforward: split the token, decode the pieces, verify the signature,
then validate the claims. One detail changed after checking Node directly. I expected
`Buffer.from(value, 'base64url')` to reject punctuation, but
`Buffer.from('!!!not-base64!!!', 'base64url')` silently produced seven bytes and re-encoded as
`not-base6w`. Relying on the decoder alone would therefore accept malformed input farther into
the verifier than intended.

I added two checks for every token segment: an explicit base64url character check and a
decode/re-encode check for canonical encoding. For signatures, I check the byte lengths before
calling `timingSafeEqual`, because that function throws on unequal lengths. Finally, I collapse
JSON, decoding, and crypto failures into the same `401 UNAUTHENTICATED` result so parser details
cannot leak through the HTTP layer.

Result: `node scripts/check-jwt.js` moved from 0/43 to 43/43. The verifier returns the original
claims for a valid token and rejects malformed tokens, algorithm substitution, bad signatures,
expired tokens, wrong issuer/audience, and missing JTIs through the same error type.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-26 · One resolver, with the database as its input

I treated `resolve()` as the only place that can decide allow versus deny. It loads the permission
catalogue, membership role, role baseline, and active grants from SQLite; no role names or
permission list are encoded in the implementation. The public vectors confirmed the important
precedence rule: an org-wide deny still wins when there is a device-scoped allow, so a narrower
allow is not an exception mechanism.

For an organization-level answer, I resolve each active device and take the union of the allowed
results. That matches the navigation question: an action should be available at org level when it
is possible on at least one device, while a device-row action still uses that row's exact result.
The database-only overlay was the useful check here: `npm run personalisation` passed 18/18 for
the undocumented `reviewer` role and `device:reboot` permission, including separate allow and
explicit-deny decisions on two devices. `check-permissions.js` passed 35/35.

The context step keeps organization scope structural. A valid Acme token produced an Acme caller,
while that same token addressed to a Globex route produced `404 NOT_FOUND`; it did not get far
enough to ask a permission question.

#### Review pass

My first completed version still had two avoidable gaps. First, the public JWT suite validates
the envelope but does not try a correctly signed token with a missing `sub`, `org`, `role`, `pv`,
or `iat`. Such a token could pass verification and send `undefined` into the membership query,
turning malformed credentials into a 500. I added structural validation for the complete claim
set; a missing-`sub` smoke test now returns `401 UNAUTHENTICATED`.

Second, the first compound-session check called the full resolver once for `session:start` and
again for the mode permission. The first grant-laundering check did the same for every expanded
permission in a wildcard. I changed both to resolve one snapshot and inspect all required
decisions from it. This keeps both answers on the same timestamp and prevents query work from
growing with the number of permissions in a grant.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

### 2026-09-26 · Transactions around identity changes

I kept organization creation, membership changes, and invite acceptance transactional with their
success audit row. Invite acceptance has to handle both a new identity and an existing platform
user without duplicating either one, while an accepted/revoked/expired token must stay dead. The
public flow now creates a hashed single-use invite, exposes only the four preview fields, accepts
it once, and lets the new user authenticate with their chosen password.

One contract conflict affected the role-change route: the prose says equal-ranked members cannot
modify each other, while `check-api.js` expects one owner to demote another non-last owner. I used
a narrow owner-to-owner demotion exception, still guarded by `LAST_OWNER`; equal-rank changes in
the other cases remain forbidden. I recorded the conflict in `DECISIONS.md` rather than hiding it.

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

### 2026-09-26 · Navigation scope is not grant-authority scope

My first `assertMayGrant` reused the org-level resolved set. That set is intentionally a union for
navigation—allowed on any device means the action can appear somewhere—but it was the wrong
answer for creating an org-wide grant. Dana's one-device control grant in Globex would have let
her grant control across the whole org. I changed org-wide grant validation to ignore
device-scoped authority and added a smoke check: org-wide returned `403`, the granted device
returned allow, and the other device returned `403`.

Device listing resolves all rows from one loaded permission model and removes rows where
`device:view` is denied. Transfers require provisioning authority in both organizations, reject a
same-org transfer, end live sessions, and revoke the old org's device-scoped grants.

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

### 2026-09-26 · Explicit stop and lifecycle cascade are different operations

Session start resolves one snapshot, checks `session:start` first, then the mode-specific device
permission so the two denial reasons stay distinct. The partial unique index remains the arbiter
for exclusive control/terminal sessions; the route translates its constraint failure to
`DEVICE_BUSY` instead of doing a racy check before insert.

During review I noticed I had initially called the broad lifecycle cascade helper from the
explicit stop route. That could end sibling sessions belonging to the same user and device. I
removed it there and made explicit stop update exactly one session; the broad helper is now used
only for suspension, membership removal, and device transfer. Permission and role changes do not
call it, which preserves grandfathering.

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

### 2026-09-26 · Denials are events too

Successful mutations write one audit row inside the same transaction as the state change. A
shared permission wrapper records `403` attempts before rethrowing, including the machine-readable
reason and request id. I kept authentication failures and invisible cross-org `404`s out of that
wrapper because writing them against a guessed organization would itself cross the isolation
boundary. Audit pagination rejects invalid limits rather than silently clamping them.

The complete backend contract finished at 66/66, alongside JWT 43/43, permission resolution
35/35, and personalization 18/18.

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

### 2026-09-26 · The interface is a projection, not a second policy engine

I started by reading the UI inventory alongside the browser tests rather than making a generic
admin dashboard. The crucial constraint is that a permission-controlled element is either
present with `data-state="unlocked"` or absent. In particular, the same screen must show Dana a
Control action on one Globex device but not the other; that ruled out a role-based navigation
matrix and also ruled out disabled controls.

The console now keeps the access token only in module memory, restores it from the refresh cookie
on reload, and changes organization only by asking `/auth/token` for a new org-scoped token. Each
view fetches only its active organization. I used a dark, compact operations layout with a single
cobalt accent, but made org themes change the actual shell background so the organization change
is visible as well as structural. The first build exposed an incorrect icon export from the icon
package; replacing it with the package's `ActivityIcon` export made the production build pass.

The first browser run exposed an assumption I had made while testing manually: I had put the
organization choices behind a dropdown, but the inventory says those choices are always present
and the tests interact with them directly. I changed the switcher into a permanent compact list.
That is clearer for an operations console anyway, because the current scope is never hidden.

The same run found a race after invite acceptance. The accept endpoint issues a refresh cookie,
so changing the route to `/` immediately restored a session before the required sign-in screen
could render. I now deliberately skip that one automatic refresh transition. I also removed the
last frontend fixture assumption: role choices come from the database catalogue returned by the
auth API rather than a copied list of role names. The production build and all 25 public browser
cases now pass, alongside the four backend suites (43 + 35 + 66 + 18).

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

### 2026-09-26 · A demo needs a repeatable boot path

I added a Render Blueprint at the repository root rather than relying on dashboard settings that
cannot be reviewed with the submission. It treats `starter/` as the service root, builds the SPA,
seeds the fixture at startup, and starts the existing one-process server. The deployment has a
generated JWT secret and uses Render's port rather than a hardcoded one.

I am deliberately treating this as a demo, not production storage. SQLite is appropriate for the
take-home and the published fixture, but Render's free filesystem is ephemeral, so a restart can
reset the demo data. Moving it to a persistent disk would require a paid service and is outside
the evaluation contract.

### 2026-09-26 · The public suites were green, but two boundaries were still wrong

I expected the permission-version check to be harmless for suspended members because suspension
already empties their resolved set. A focused check showed the opposite: suspension increments
`perm_version`, so the old token stopped at `TOKEN_STALE` before the route could return the
documented `403 suspended`. I now skip freshness only for a recognized suspended membership;
removed memberships still fail authentication, and `requireActive` blocks every route.

The second problem was in the browser rather than the resolver. “Sign out” cleared the access
token in memory, but the refresh cookie survived, so a reload signed the same person straight back
in. The new logout endpoint sits under the cookie's narrow `/auth/refresh` path, revokes the whole
refresh family, and expires the cookie before the client drops local state. I also made the grant
failure distinguish an absent permission from authority held at the wrong scope. The new focused
suite covers suspended tokens, scope laundering, refresh-family logout, and offboard/rehire grant
cleanup.

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
