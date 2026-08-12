# security-forge — Access-control analysis methodology
*(authorization + authentication soundness)*

Access control is the class SAST tools miss most, because "who is *allowed* to do
this" lives in the app's intent, not in a dangerous function call. This is the
catalog the `authz-analyzer` agent works through, driven by the project model
(`ENTRYPOINTS.md`, `ROLES.md`, `AUTH.md`, `model.json`). It is **model-driven**:
every check is "for *this* entrypoint and *these* roles, what should happen vs.
what the code actually enforces."

Three questions frame everything:
- **AuthN presence** — must the caller be *someone* (is identity required at all)?
  → checks A, D.
- **AuthN soundness** — can an attacker *become* someone else (is the mechanism
  itself forgeable, brute-forceable, or bypassable)? → checks K–P. A guard that
  exists but can be defeated is worth more to an attacker than a missing one.
- **AuthZ** — may *this* someone do *this* to *this object* (vertical vs.
  horizontal)? → checks B, C, E–J.

Checks A–J are per-entrypoint. Checks **K–P are per-mechanism** — you audit the
reset flow, the token verifier, the session lifecycle once each, not route by
route. They are assigned to a dedicated `auth-mechanism` pass.

## What counts as a real check (read before judging any entrypoint)

A check is valid only when the caller's **verified identity constrains the data
access** — the query or service call itself, not the handler signature and not an
annotation. **Read the actual sink.** Recognizing a known idiom (`@PreAuthorize`,
a Pundit policy, an ORM scope) is fine; *assuming* it is wired up without tracing
it to the sink is not.

**Counts as enforced** (always cite the `file:line`):
- **Query scoped by the caller** — `WHERE id = :id AND owner_id = :caller`;
  `current_user.orders.find(id)` (Rails); `Order.objects.filter(owner=request.user)`
  (Django); `findOne({where:{id, ownerId: req.user.id}})` (Sequelize/TypeORM);
  `findByIdAndOwnerId(id, caller)` (JPA). A bare `findById(id)` is **not** scoped.
- **Row-level security** — a DB policy `USING (owner_id = current_setting('app.user_id'))`
  *and* the request provably sets that variable from the verified token.
- **Route-bound guard / policy** — `@PreAuthorize("#id == principal.id")`,
  DRF `has_object_permission`, Pundit `authorize @order`, a Nest/Express guard
  comparing `resource.ownerId === req.user.id`. Counts only if bound to *this*
  handler (or a prefix that provably covers it) **and** it checks the object.
- **Server-side id derivation** — the handler ignores the client id and uses the
  token's (e.g. `/me/profile`).
- **Tenant binding** — constrained by `tenant_id = :caller_tenant`, not `user_id` alone.

**Does not count — this absence *is* the finding:**
- An authn annotation alone (`@Authenticated`, `requireLogin`) — proves logged-in,
  not entitled.
- A check on a **client-supplied** owner/tenant id (`owner_id = :ownerIdFromBody`) —
  the attacker sets it.
- A check on a **different input** than the one reaching the sink (validates
  `path:id`, but the query uses `query:id`).
- A check that runs **after** the data is fetched / returned / logged — already leaked.

**Easy to miss — check each explicitly:**
- **Nested resource** — `/users/1/invoices/9` verifies you own user `1` but never
  that invoice `9` belongs to it. **Check the leaf id.**
- **Sibling verb** — enumerate every HTTP verb on a path separately; a guarded
  `GET` routinely sits beside an unguarded `PUT`/`PATCH`/`DELETE`.
- **Mass assignment** — a body field overriding server state (`ownerId`, `role`,
  `isAdmin`, `tenant`, `verified`). A finding even when the path id is safe.

## The checks

### A. Missing authentication (CWE-306)
Sensitive entrypoint reachable with no identity established. For every entrypoint
in the model: is there an authn guard on the path to the handler? Watch for
routes registered *outside* the guarded middleware group, `/internal`, `/debug`,
health/actuator endpoints that leak, and new routes added under an unguarded
blueprint.

### B. Missing / broken function-level authz — vertical escalation (CWE-862/285)
A lower privilege tier reaches an action reserved for a higher one. Compare each
entrypoint's *required* role (from `ROLES.md`) to what the handler actually
checks. Classic gaps: admin action guarded only by *authentication* (any logged-in
user), UI hides the button but the API is open, role checked on `GET` but not on
the `POST/PUT/DELETE` sibling.

### C. Broken object-level authz — IDOR / BOLA (CWE-639/863)
Handler loads an object by a caller-supplied id **without checking the caller
owns/may access it**. The highest-yield authz bug. For every entrypoint whose
params include an id / slug / uuid and whose body does an object lookup
(`findById`, `get_object_or_404`, `.find(id)`): is the lookup scoped to the
caller (`where owner_id = current_user`) or a bare global lookup? Check indirect
references in nested resources (`/orgs/:o/projects/:p`) and **every verb**
(GET/PUT/PATCH/DELETE) on the same object.

**Analyze the ID structure — it drives exploitability and severity — and READ
THE TESTS to find it.** Test files, fixtures, factories, seed data and DB
migrations are the fastest ground truth for what identifiers actually look like,
and they routinely leak seed accounts / default creds you can reuse for the
two-principal PoC. Classify each object reference:
- **auto-increment / sequential integer** → trivially enumerable (walk `1..N`) →
  **raise severity**; mass-harvest is possible.
- **short / predictable** (timestamps, UUIDv1/ULID time-ordered, snowflake,
  small or sequential-ish) → **partially enumerable** → moderate raise.
- **UUIDv4 / long random / HMAC'd** → not guessable on its own → **lower severity
  BY ITSELF** — but see disclosure.
- **natural keys** (email, username, slug) → enumerable if public.
Record the id type on the finding (`id_structure`, `enumerable`).

**Disclosure — does the id (or the object) leak?** An unguessable id is still
exploitable if the victim's id is *disclosed* to an attacker who then acts on it.
Check whether object ids or sensitive data are exposed via: list / search /
export endpoints returning other principals' ids; ids embedded in
responses/HTML/JS; verbose errors; logs; URLs / `Referer`; emails /
notifications; public profiles; autocomplete; or another user's view. **If ids
are disclosed, treat the BOLA as enumerable for severity even with random ids**,
and record where they leak (`disclosure`). Separately, a plain
**information-disclosure** endpoint (exposing PII / ids / internal data with
absent or weak authz) is itself worth reporting — capture those in `disclosures`.

**Consult `DISCLOSURE_INDEX.md` before you conclude "no leak found."** The leak
that makes a UUID-keyed BOLA exploitable is usually in a *different* area of the
codebase from the missing check — an export endpoint, a JS bundle, an email
template, a log line. A per-area hunt systematically misses it and under-rates the
finding. So the run builds a **repo-wide id-disclosure index** once (before this
phase) mapping each object type → every place its id or data is emitted → to which
principal. Check the index first, then hunt locally for anything it missed, and
report anything new back so the index improves. A leak you cite from the index is
just as valid as one you found yourself — cite its `file:line`.

### D. Inconsistent enforcement across siblings
Routes under the same prefix protected unevenly — one handler checks, its
neighbour forgot. Enumerate each router group and diff which handlers carry a
guard. A single unguarded sibling in a protected group is the finding.

### E. Mass assignment / privilege field tampering (CWE-915)
User-controlled payload can set fields that grant privilege or reassign
ownership: `role`, `is_admin`, `is_staff`, `owner_id`, `tenant_id`, `verified`,
`balance`. Look for `update(**request.json)`, `Object.assign(user, req.body)`,
`Model(**data)`, serializers without an allow-list / with `fields = '__all__'`.

### F. Tenant / org isolation (CWE-1230/639)
Multi-tenant apps: does every query filter by the caller's tenant, or can a
`tenant_id` in the path/body cross the boundary? Check shared caches, global
lookups, and background jobs that run without a tenant scope.

### G. Trusting client-controlled identity (CWE-807/290)
Authorization decided on data the client can set: `X-User-Id`/`X-Role` headers,
a `role` field in the JWT *payload* that the app never re-verifies, `user_id` in
a cookie without integrity, JWT `alg=none` / unverified signature, `admin=true`
query param. Identity must come from a verified session/token, never from raw
request fields.

### H. Enforcement in the wrong place / order (CWE-863)
The check exists but is ineffective: authorization *after* the state-changing
side effect; check on a variable other than the one used in the sink; a
`return`/early-exit bug that skips the check; caching an authorized result across
principals; TOCTOU between check and use.

### I. Sensitive action without step-up / re-auth
Password/email change, MFA disable, fund transfer, role grant performed with only
an ambient session and no re-authentication or current-password proof.

### J. GraphQL / batch field-level authz
Object-level guard on the REST route but not on the GraphQL resolver / batch
endpoint that returns the same data; introspection exposing admin mutations.

---

# Authentication soundness (checks K–P) — the `auth-mechanism` pass

Checks A–J ask *"is a guard present on this route."* These ask *"can the attacker
satisfy the guard as someone else."* Audit each mechanism **once**, end to end,
rather than per-route. The prize is **account takeover (ATO)**, so state for every
finding whether it yields ATO, of *whose* account, and what the attacker must know
first. Cite `file:line` for the generator, the verifier, and the storage.

### K. Session lifecycle (CWE-384/613/539)
Read the login handler, the logout handler, and the session store. Look for: the
session id **not rotated on privilege change** (login, role grant, impersonation)
⇒ session fixation; logout that clears the cookie but never invalidates
server-side; sessions **not invalidated on password change / reset / MFA
enrolment** (so a hijacker keeps access after the victim remediates); no absolute
or idle timeout; session id in a URL or `Referer`; the session token derived from
predictable material (user id, timestamp, non-CSPRNG — cross-check the weak-random
signatures); "remember me" cookies that are unsigned or never expire.

### L. Password reset & email verification tokens (CWE-640/330/613/620)
The single richest pre-auth ATO surface. Trace the token from generation to
consumption:
- **Generation** — non-CSPRNG (`Math.random`, `rand()`, `uuid1`, time-seeded), a
  hash of predictable input (`md5(email+timestamp)`), or too short. Predictable ⇒
  forge a token for any account ⇒ CRITICAL.
- **Binding** — is the token bound to the account server-side, or does the consume
  step trust a **client-supplied** `email`/`user_id` alongside it? (Reset accepted
  with a valid-but-other-user's token = ATO.)
- **Lifecycle** — no expiry, **not single-use**, not invalidated when a new one is
  issued, still valid after the password changes.
- **Leakage** — the token in a URL that leaks via `Referer` to third-party
  scripts; the reset link's host built from the **`Host`/`X-Forwarded-Host` header**
  (host-header poisoning ⇒ the victim's token is delivered to the attacker's
  domain) ⇒ CRITICAL, and a classic that static tools never find.
- **Response** — does the "forgot password" response or timing differ for existing
  vs unknown accounts (enumeration; see P).
- Apply the same checks to **email-change**, **invite**, and **magic-link** tokens.

### M. Token / signature verification — JWT and friends (CWE-347/290/345/287)
Find the **verify** call, not the sign call, and read what it enforces:
`alg: none` accepted; **algorithm confusion** (`RS256` key used as an `HS256`
secret, i.e. the public key becomes the HMAC key); signature simply not checked
(`decode` where `verify` was meant, `verify=False`, `verify_signature: False`);
missing `exp`/`nbf` validation; missing `aud`/`iss` so a token from a sibling
service or another tenant is accepted; the algorithm taken from the **token's own
header** instead of a server-side allowlist; `kid` used as a file path (traversal)
or `jku`/`x5u` fetched from a URL in the token (SSRF + key substitution); a weak,
guessable, or hardcoded HMAC secret (cross-check the secrets signatures); **role
or tenant claims read from the payload and never re-derived server-side** (this is
check G, reached through the token); refresh tokens that are never revoked or
rotated, so logout and password change do not end the session.

### N. OAuth / OIDC / SSO flow (CWE-352/601/863)
- **`state` missing or not verified** ⇒ login CSRF / account linking to an
  attacker's identity.
- **`redirect_uri` not exact-matched** (prefix/substring match, wildcard subdomain,
  open path append, or an open redirect on an allowed host) ⇒ authorization code
  exfiltration ⇒ ATO. Chain this with any open-redirect finding from the dataflow
  phase.
- **PKCE absent on a public client**; implicit flow still enabled; `nonce` not
  verified on the `id_token`; the `id_token` accepted without validating `iss`/`aud`
  (see M).
- **Account linking by unverified email** — an IdP asserting an email the app trusts
  without checking `email_verified` ⇒ takeover of the matching local account.

### O. MFA / step-up correctness (CWE-304/287/308)
MFA required at one entry point but **not on a sibling** (the mobile/API login,
a legacy endpoint, the refresh-token path, or basic auth) ⇒ full bypass; the
"MFA passed" state stored client-side (cookie/JWT claim/body field) rather than
server-side; the second factor verified against a value the client also supplied;
OTP not invalidated after use or after a new one is issued; unlimited verification
attempts on a 6-digit OTP (see P — this is the common CRITICAL); remember-device
tokens that are predictable or not bound to the device; backup codes unlimited or
not single-use; **MFA disable / phone or email change performed with only an
ambient session** and no re-auth (this is check I, and it is where MFA is usually
undone).

### P. Anti-automation on authentication endpoints (CWE-307/799/204)
Rate limiting is normally a MEDIUM best-practice nit — **except on the auth
mechanism, where its absence is the exploit.** Check for a limit/lockout, and
whether it is keyed on something the attacker controls (a header, `X-Forwarded-For`,
a body field) rather than the account or the real peer:
- **OTP / MFA verify with no attempt cap** ⇒ brute-force a 6-digit code ⇒ ATO ⇒
  **CRITICAL**. Same for a short reset PIN or an SMS code.
- **Login / token endpoint with no lockout** ⇒ credential stuffing. Rate as HIGH
  only with a real amplifier (no MFA anywhere, a weak or default password policy,
  seeded default creds); otherwise it is below the bar.
- **Account enumeration** (differing status/message/timing between known and
  unknown accounts, on login, reset, or signup) — by itself **below the bar**;
  report it only as the enabling step of a chain, or as a `disclosure` entry when
  it supplies the ids another finding needs.

### Severity for K–P
These are pre-auth by construction, so rate on **what the attacker ends up
holding**, and always say what they must know first:
- **CRITICAL** — unauthenticated takeover of an **arbitrary or attacker-chosen**
  account: forgeable/predictable reset token, `alg: none` or alg-confusion,
  signature unverified, host-header reset poisoning, uncapped OTP brute force,
  `redirect_uri` code theft, MFA fully bypassable on a sibling endpoint.
- **HIGH** — takeover requiring a realistic precondition: the victim's email or a
  targeted single account, one click from the victim, a leaked-but-obtainable
  token, a non-default configuration, or cross-tenant token acceptance.
- **MEDIUM** — a confirmed, traced flaw whose exploitation needs a precondition you
  can name: a reset token valid far too long (but still random), a session not
  invalidated on password change where you can show the hijack path is narrow,
  cross-tenant token acceptance with limited data. State the precondition.
- **Below the bar — drop, do not file as MEDIUM** — no session rotation with **no**
  demonstrated hijack path, missing idle timeout, account enumeration on its own, a
  login rate-limit gap with no amplifier, "consider adding PKCE" style hardening.
  These are the classic authn false positives; they must not survive.
Apply the same evidence discipline as check C: if you cannot show the path to ATO,
take the lower rating and say what is missing.

---

## Confirming an authz finding (static → runtime)
1. **Static proof**: cite the entrypoint, the missing/incorrect check
   (`file:line`), the role/ownership expectation from the model, and the exact
   gap.
2. **Runtime proof (two-principal test)** — the canonical PoC the
   `finding-verifier` runs:
   - create/seed **two principals** A and B (or anon + user);
   - as B, capture the id of B's object (or an admin-only action);
   - **replay the request as A** (A's session/token, B's object id / the
     privileged path);
   - success = A gets B's data or performs the action ⇒ **verified**. Access
     denied (401/403/404-by-policy) ⇒ not exploitable.
   For missing-authn: make the request with **no** credentials.
3. **Runtime proof for K–P (single-attacker test)** — the two-principal shape does
   not fit an authn-soundness bug; the PoC is *"attacker ends up authenticated as
   the victim."* Seed a victim account, then as an unauthenticated attacker forge
   or brute-force the credential (mint a token with `alg: none` / the public key as
   HMAC secret; request a reset with a poisoned `Host`; iterate the OTP; replay a
   consumed token), and prove the result **is** the victim: call an
   identity-revealing endpoint (`/me`) with the obtained session and show it
   returns the victim. Success ⇒ verified ATO. Log the forged credential and the
   `/me` response as evidence.

## Severity — a decision procedure, not a vibe

Severity is **derived**, never asserted. Rate each finding by answering four
questions in order and recording each answer on the finding. If you cannot answer
a question from evidence, say so and take the **lower** rating — never round up.

**1. Reachable by whom?** anonymous → any authenticated user → a specific
low-privilege role → admin-only. Fewer required privileges = higher.
**2. Action?** **write outranks read.** Any change to another principal's data is
at least as severe as reading it. Delete/refund/role-grant are writes.
**3. Data sensitivity?** credentials/financial/PII → business data → non-sensitive.
**4. Exposure — can the attacker actually obtain a usable id?** This is the gate
that decides HIGH vs MEDIUM for every BOLA. See the enumerability/leak rules below.

### Enumerability (question 4, part one)
`enumerable` is a property of the **real** id, confirmed from tests/fixtures/
factories/migrations — not guessed from the parameter name:
- **`yes`** — auto-increment / sequential integer, short numeric, or a natural key
  an attacker already holds or can iterate (email, username, public slug).
- **`partial`** — time-ordered or semi-predictable: UUIDv1/v7, ULID, snowflake,
  timestamp-derived, short random (< ~64 bits of entropy).
- **`no`** — UUIDv4, long random, or HMAC'd. **A UUID is not enumerable.** Do not
  treat one as brute-forceable, ever.

### The leak hunt (question 4, part two) — mandatory for every `enumerable: no`
A non-enumerable id only becomes exploitable if the attacker can *obtain* it. You
must **actively hunt** for that before rating, and record the result. Check: a
list / search / export / dump endpoint that returns other principals' ids; ids
echoed in a response body, HTML, or JS bundle; a verbose error or debug page; a
JWT or cookie payload; a URL or `Referer`; an email / notification / reset or
referral link; a public profile or autocomplete; an OpenAPI example; another
user's view; logs. Correlation from a value the attacker knows (email, order
number) counts as a leak.

Outcomes:
- **Leak found** → cite it `file:line` and rate as if `enumerable: yes`.
- **Honest hunt, no leak found** → it stays **MEDIUM**. Say where you looked.
- **Provably never obtainable** by any principal → **not a finding**; drop it.

### The rubric
**Object-level (BOLA / IDOR):**

| Severity | When |
|---|---|
| **CRITICAL** | Reachable **unauthenticated**, or cross-tenant; or enumerable/leaked id + attacker can **modify** another principal's data, or **read** their PII/financial data (mass-harvestable — iterate ids to hit every user). |
| **HIGH** | Authenticated, enumerable/leaked id, **read-only of non-PII** data; **or** a write / PII-read where the id is non-enumerable **but a concrete leak path is cited**. |
| **MEDIUM** | Real, confirmed, traced missing check, but the id is **non-enumerable and no leak was found** after an honest hunt (index + local). Reportable — say plainly in the `poc` and `severity_rationale` that exploitation **requires an already-known or leaked id**, and name where you looked. Never inflate to HIGH; never pad with unconfirmed candidates. |

**Function-level (BFLA / vertical escalation):**

| Severity | When |
|---|---|
| **CRITICAL** | A low-privilege (or anonymous) caller performs a privileged **write** — refund, role/permission grant, config change, delete-any, bulk action. |
| **HIGH** | A low-privilege caller **reads** admin-only data, or runs a privileged action against a single record they must name. |

**Missing authentication** outranks both: rate by the same rubric and take at
least that severity, since no login is required. Mass-assignment of
`role`/`is_admin`/`owner_id` is priv-esc — rate it on the BFLA table.

### Consequences of the bar
security-forge reports **MEDIUM, HIGH and CRITICAL** — nothing below. So the
enumerability + leak-hunt result does not decide *whether* a genuine missing check
is reported; it decides **at what severity**:
- a UUID-keyed BOLA with a cited leak path → **HIGH/CRITICAL**;
- the same missing check with no leak path found → **MEDIUM**, reported with the
  precondition stated in the headline, and re-rated upward by the composition pass
  if a disclosure turns up in another area;
- provably unobtainable id → **not a finding at all**.

**The confirmation standard does not soften as severity drops.** A MEDIUM must be
as well-evidenced as a CRITICAL: confirmed in code you read, traced to the sink
with `file:line` per hop, user-reachable, with a concrete impact sentence and a
named false-positive filter ruled out. MEDIUM describes an attacker's
*precondition*, never your *uncertainty*. Unconfirmed, untraced, unreachable,
defense-in-depth, and best-practice items are **dropped** — they do not become
MEDIUMs. One false positive costs more credibility than ten true findings earn.

Every finding carries `id_structure`, `enumerable`, `disclosure` (the cited leak
path, or where you looked and found none), `trace`, and a `severity_rationale`
that names the row of the table you landed on.

### Verdict per entrypoint
Assign exactly one, first match wins — this is what makes coverage provable:
- **SAFE** — a check that *counts* (see above) constrains the access.
- **UNVERIFIABLE** — enforcement is out-of-band (API gateway / ALB allowlist,
  webhook signature, service mesh) and not visible in code. Name the exact check
  a human must confirm. **Never rate this as vulnerable.**
- **VULNERABLE** — reachable, takes a client-controlled id or runs a privileged
  action (or needs no authn), and no check that counts exists. Record the missing
  check as `authentication` (outranks) / `role` / `ownership`, then rate severity.
- **UNTRACED** — looks vulnerable but the path to the sink could not be fully
  traced. Goes to `notes` for human review, **not** to `findings`.

## What is NOT an authz finding
Defense-in-depth nits where a real guard exists upstream; UI-only hiding that the
API also enforces; endpoints intentionally public (documented). Note these as
dismissed with the reason — don't inflate the count.
