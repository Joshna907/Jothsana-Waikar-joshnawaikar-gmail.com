# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### <the decision, as a claim — not "permissions", but "the org-level view counts device-scoped grants">

**What I chose:**
**Why:** _(evidence: test, log line, commit)_
**What I rejected:** _(the plausible alternative, and the specific reason it fails)_
**What would change my mind:**

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

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

### Stub — the shape of a weak "Why"

**What I chose:** the obvious thing.
**Why:** it is what the brief says to do.
**What I rejected:** nothing, the alternative seemed worse.
**What would change my mind:** I do not know.

_Reads as a memory of the document, not a model of the system. Scores nothing._

---

### Stub — the shape of a strong "Why"

**What I chose:** X.
**Why:** I implemented Y first, because Y is the intuitive precedence rule. `node scripts/check-
permissions.js` reported `<the actual reason string it reported>` on the case where the two grants
disagree. That is only reachable if the two are evaluated in a different order than Y assumes.
Moved to X in `<commit>` and the case passed. Logged in `BUILD-LOG.md` under Phase 2.
**What I rejected:** Y, and also "resolve the narrower one last" — both fail the same case for the
same reason.
**What would change my mind:** a case where a narrower grant is expected to survive a broader
refusal. I could not construct one, which is itself evidence for X.

_Shows what you believed, what disproved it, and what you did next._

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

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
