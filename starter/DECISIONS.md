# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Removing a membership also revokes its active grants

**What I chose:** Offboarding marks the membership removed, ends its sessions, and revokes its
active grants in the same transaction.
**Why:** A removed membership can later be reactivated through the invite path. Leaving the old
grant rows active would silently restore exceptional access on rehire, including grants that the
new inviter may not know existed. Removal is a permanent tenancy event, unlike suspension.
**What I rejected:** Keeping grants dormant only because resolution ignores a removed membership.
That makes their safety depend on the membership never becoming active again.
**What would change my mind:** An explicit product requirement that rehire restores the person's
previous exceptional access, together with UI that shows and confirms those grants during rehire.

---

### Grant authority is checked at the destination scope

**What I chose:** Creating an org-wide grant checks only authority held org-wide; a permission
held on one device cannot be promoted into organization-wide authority.
**Why:** Dana's Globex fixture is the discriminating case: she can control one device, while the
other remains denied. The Phase 4 smoke check and `npm run hardening` both prove that attempting
to grant `device:control` without naming the device fails with `scope_mismatch`.
**What I rejected:** Reusing the org-level navigation union for grant creation. That union answers
“does this appear anywhere?” and would turn one-device authority into control of every device.
**What would change my mind:** A separate product rule allowing delegation beyond the caller's
own scope, with an approval workflow outside this permission model.

---

### Exclusive sessions are arbitrated by SQLite

**What I chose:** The route attempts the insert and translates the partial unique-index failure
into `409 DEVICE_BUSY`.
**Why:** `one_exclusive_session_per_device` is the only place that can decide correctly when two
control requests arrive together. The API suite proves a second exclusive session is rejected
while a concurrent view session remains allowed.
**What I rejected:** A `SELECT` followed by `INSERT`. Two callers can both observe an empty device
before either insert commits, making the check correct only when requests happen serially.
**What would change my mind:** Moving session ownership to a datastore with an equivalent atomic
compare-and-set primitive; the invariant would still live in storage.

---

### Successful mutations and their audit rows share a transaction

**What I chose:** Success events are written inside the mutation transaction; the shared
permission boundary writes denied attempts once and then rethrows the original refusal.
**Why:** The audit suite finds both allow and deny events with their request/reason metadata. More
importantly, a failed audit insert rolls back the state change instead of creating unaudited
authority.
**What I rejected:** Logging after sending the response, or logging both in the permission wrapper
and the route. The first can lose events and the second produces two rows for one action.
**What would change my mind:** An external append-only event store with an outbox transaction that
provides the same atomicity guarantee.

---

### Suspended credentials remain identifiable but powerless

**What I chose:** Authentication recognizes a signed token for a suspended membership, then every
protected route stops it at `requireActive` with `403` and reason `suspended`.
**Why:** Suspension increments `perm_version`, so applying the normal freshness check first turned
the same request into `401 TOKEN_STALE`. `npm run hardening` now covers the ordering explicitly.
**What I rejected:** Treating suspension as removal. It erases the distinction the API and console
need between an invalid identity and a reversible account-integrity action.
**What would change my mind:** A contract that deliberately conceals suspension state from the
account holder and specifies `401` for that case.

---

### Sign-out revokes the refresh family without widening cookie scope

**What I chose:** Sign-out calls a public endpoint below `/auth/refresh`, revokes the presented
token family, expires the HttpOnly cookie, and then clears the in-memory access token.
**Why:** Clearing React state alone appeared to sign out, but reloading immediately restored the
session from the still-valid cookie. The hardening check proves that the old refresh token returns
`401` after logout.
**What I rejected:** Moving the cookie to `/` just to make a conventional `/logout` route easier.
That would send the credential to every application request instead of only the auth boundary.
**What would change my mind:** A separate authentication origin where the cookie is never sent to
the application API in the first place.

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

### The grading weights are described in two different ways

`DISCOVERY-BRIEF.md` assigns 50% to code, 30% to `BUILD-LOG.md` plus `DECISIONS.md`, and 20% to
the walkthrough. `BRIEF.md` instead lists 30% hidden API, 20% hidden UI, 25% code quality, and
25% walkthrough, without a separate write-up percentage. I am treating both as signals rather
than choosing one: functional behavior, code quality, the contemporaneous write-up, and the live
explanation all need to stand on their own. I would ask the organizers which table controls any
formal score calculation, but the disagreement does not change an implementation decision.

### The console inventory says seven cards but defines six

`UI-INVENTORY.md` says “Seven cards,” then names Devices, People, Grants, Sessions, Audit, and
Admin. The table contains six entries, and the public owner test also says “all six cards.” I am
building the six explicitly named/tested cards because those are the concrete interface contract;
I am not inventing an unnamed seventh card.

### Equal-rank modification conflicts with the owner-demotion test

`PERMISSIONS.md` says a caller may modify only a strictly lower role and that equal-role changes
are forbidden. The public API suite nevertheless expects Dana (owner) to demote another active
owner to viewer when Acme has more than one owner. I implemented that exact narrow exception:
an owner may demote another owner only after the last-owner check succeeds. Admin-to-admin and
other equal-rank modifications remain forbidden. I chose the executable public contract for this
case because it is more specific, while keeping the broader rank rule everywhere else.

### The console renders server decisions rather than inferring them from roles

**What I chose:** Navigation and device actions are rendered from the `permissions` objects in
`/auth/me` and `/devices`; the client contains no role-to-permission map.
**Why:** The browser suite intercepts the device response, changes `device:control` to deny, and
expects the button to disappear after the Devices view remounts. A polished role-based UI can
look correct for the seed data while still fail the one-device Globex grant and a grading fixture
with an undocumented role.
**What I rejected:** Building a convenient client matrix such as `operator -> control`. It would
not know about a new database role, a time-bounded grant, or an explicit deny, and would create a
second authorization implementation that can drift from the server.
**What would change my mind:** A versioned, server-provided capability catalogue designed for
offline use. It would still be data from the server, not a copied role matrix.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.

- The Render deployment does not provide durable production storage. It is a resettable demo of
  the submitted SQLite fixture; a persistent disk is paid infrastructure and not part of the
  take-home contract.
- Remote session buttons create and govern session records, but they do not open a real remote
  desktop, shell, or file-transfer channel. The brief explicitly treats sessions as records and
  prohibits input injection, shell execution, and screen capture.
- There is no client-side permission cache or offline mode. Decisions are time-sensitive and must
  be resolved by the server on each request, so an offline capability layer would undermine the
  model rather than improve it.
