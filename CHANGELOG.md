# Changelog

## Version 0.13.0

v0.12 added a `Dockerfile` and a README whose first line says `docker compose
up`. Nothing was building that Dockerfile. A promise with nothing behind it is
worse than no promise, so this version makes every commit prove the claim.

### Added

- **`.github/workflows/ci.yml`** — two jobs answering two different questions.
  **checks** runs the 300+ assertions and builds the dashboard, because a
  broken component is a broken product even when every Python test passes.
  **container** builds the image, starts it, and replays a scripted attack
  against it over real HTTP.
- **`demo.py --assert`** — the replay becomes an end-to-end check. Every step
  already printed what it expected; now that claim is recorded and verified,
  and the run exits non-zero naming any step that failed to raise what it said
  it would. Plus four assertions no single alert can establish: that an incident
  correlated at all, that the kill chain is at least four stages, that it starts
  at Reconnaissance (which only happens if the ingested finding attached), and
  that the ledger still verifies.

### Why the container job is the one that matters

The unit suite never leaves the process. This exercises ingest, sixteen
detectors, correlation, kill-chain ordering, findings-envelope ingest, the
sign-in throttle and the hash-chained ledger — against a real server, over real
HTTP, **in the image that ships**. It also checks the things that would leave
the product broken while every unit test still passed:

- the image builds at all;
- it runs as a **non-root** user;
- the dashboard is served from the API's own origin;
- an API route is **not** shadowed by the static mount (a `401` proves the
  endpoint answered; a `404` would mean the mount had swallowed it);
- `shadowfax check` still exits **non-zero when alerts match** — the inversion
  that lets an agent harness fail its own build. The replay leaves criticals
  behind, so a zero exit there means the gate has quietly stopped working.

### The "expect →" line is now load-bearing

It was decoration. A step that silently stopped firing read exactly like a step
that was never meant to fire. Naming the expected category makes the claim
checkable, and the failure output names the step:

```
━━ ASSERTIONS FAILED

  ✗ step 8: expected shadowfax-auth / brute_force_auth (401s, then 429s — and
    Shadowfax alerting on the attempt) — not raised
```

Expectations are recorded **qualified by actor as well as category**, because
Act 1 and Act 3 both raise `brute_force_auth`. An unqualified check would pass
on Act 1's alert and never notice that self-monitoring had stopped working —
which is exactly the regression that failure above was produced by, running the
replay against a server started with `SHADOWFAX_SELF_MONITOR=0`.

Without `--assert` the replay is still a demo and still returns 0 whatever
happens: a person watching can see for themselves.

### Tests

3 new checks covering the assertion machinery itself: that a step's declared
expectation is recorded, that what was raised is tracked both bare and qualified
by actor, and that the replay never fails without `--assert`. 326 in all, green.

## Version 0.12.0

Shadowfax could do a great deal by v0.11 and almost nobody could see it. Trying
it meant installing Python dependencies, installing npm dependencies, running
two processes and getting the CORS allowlist to agree with whichever port the
dashboard ended up on. Every one of those is a place to give up.

This version is one command, and a scripted attack that makes the engine
demonstrate itself.

```bash
docker compose up --build          # then open http://localhost:8000
docker compose exec shadowfax python demo.py
```

### Added

- **`Dockerfile`** — two stages. Node builds the dashboard; Python runs the API
  and serves the built dashboard **from its own origin**. Node does not survive
  into the final image: a build toolchain inside a running security container is
  attack surface that earns nothing. Runs as a non-root user, because a tool
  that spends its time reporting privilege escalation should not need root to
  say so.
- **`docker-compose.yml`** — one service, one port, a named volume for the
  event store. `docker compose down` keeps the database and `down -v` discards
  it; losing an investigation should take an extra flag.
- **`demo.py`** — a narrated attack replay against a running instance, in three
  acts, each covering something a screenshot cannot show:
  1. An AI agent exceeds its brief, and five separate alerts turn out to be one
     kill chain running **Privilege Escalation → Exfiltration**.
  2. Another tool's findings arrive over the shared envelope, attach to the same
     actor, and push the chain back a stage to **Reconnaissance** — from a tool
     Shadowfax knows nothing about.
  3. The attacker turns on Shadowfax, and Shadowfax's own front door raises an
     ordinary `brute_force_auth` alert about the attack on Shadowfax.
- **`GET /healthz`** — unauthenticated by necessity, since an orchestrator has
  no credential, and deliberately uninteresting: status, service name, version.
  A health check that reported internals would be a free reconnaissance endpoint
  for anyone who could reach the port.
- **`SHADOWFAX_DB`** — the database path from the environment, so the container
  can point it at a mounted volume instead of an image layer.
- **`.dockerignore`** — notably excluding `*.db`. A database copied into an
  image would ship someone's events and, worse, would look like seed data to
  whoever ran it.

### Changed

- **The API serves the dashboard when a build is present.** The mount is
  registered after every route, so API paths keep winning and only genuinely
  unclaimed paths fall through to a file. In development there is no `dist/`,
  nothing is mounted, and the Vite dev server on `:5173` works exactly as
  before — which is what the CORS allowlist is for.
- **`VITE_API_BASE` is read with `??`, not `||`.** An explicitly empty value is
  a real answer meaning "same origin as this page", not a missing one. That is
  the single change that lets one process serve both halves with CORS still
  closed, rather than widening it to make a demo work.

### Notes on the replay

The attack's own clock and the replay's pacing are separate. Events carry
timestamps minutes apart so the time-windowed detectors behave as they would in
life; `--speed` and `--fast` only change how fast the narration is read out. Tie
the two together and a fast replay quietly stops tripping half the engine.

In Act 3 the replay **waits out the server's `Retry-After`**, because hammering
only collects 429s: the v0.10 backoff stops the guessing before the detector has
enough failures to call it brute force. A demo that did not wait would be
demonstrating the throttle while silently failing to demonstrate the detection.

The replay is an ordinary client. It signs in, holds a bearer token, uses the
same endpoints as the dashboard and the CLI, and reaches the database never.

### Tests

16 new checks: `/healthz` needing no credential and leaking nothing beyond
status, service and version; `SHADOWFAX_DB` choosing the path and the default
standing without it; API routes not being shadowed by the dashboard mount (the
failure mode if that ordering ever regressed is a static-file 404 where an
endpoint should be); and the replay's own invariants — attack clock separate
from pacing, each step printing only what it newly raised, standard library
only, and no path to the database. 323 checks in all, green.

## Version 0.11.0

`findings-envelope.md` has sat in this repository since v0.4 describing a wire
format three tools in this portfolio could share — maltriage from a file's
bytes, claude-recon-agent from a target's services, Shadowfax from an actor's
event history. This version builds Shadowfax's side of it. Anything that writes
the envelope is now ingestible, and `maltriage sample.exe --envelope |
shadowfax ingest -` is a pipe rather than an integration.

Nothing in this release names another tool, and nothing in it is allowed to.
That is the whole point of a contract.

### Added

- **`envelope.py`** — strict validation of the wire format and translation into
  Shadowfax events. Pure: no I/O, and the native category list is passed in
  rather than imported, so the collision rule can be driven directly in a test.
- **`POST /findings`** (ingest key or analyst). Returns what was accepted, what
  was already known, and the alerts raised.
- **`shadowfax ingest` detects an envelope**, by the presence of
  `envelope_version`, rather than taking a flag. The spec's own example works as
  written; asking which kind of JSON was just piped in would be asking for
  something the document already states.
- **The `info` severity level**, the fifth rung of the shared ladder, weighted
  **0** in risk scoring, incident scoring and the triage digest. The envelope
  called this out as the only new decision the ladder forces on Shadowfax, and
  it is the right one: a hundred informational findings must not out-score one
  critical. Shadowfax's own detectors still emit the top four; `info` arrives
  from outside.
- **Provenance on alerts.** `source_tool`, `validated` and `evidence` columns,
  shown in the dashboard as a `via <tool>` badge, an `unvalidated` marker and
  the emitter's observed evidence under the message. An alert Shadowfax raised
  itself carries `validated: null` — "nobody claimed this, we found it" and
  "somebody claimed it without checking" are different statements and are
  stored differently.
- **21 more ATT&CK techniques** in the shared registry: static-triage and
  reconnaissance territory the other two emitters work in. The registry has
  always been the portfolio's single source of technique metadata; it now
  covers more than Shadowfax's own detectors need, because a finding may
  reference any technique and an id the registry does not know is dropped
  rather than guessed at.

### Design decisions worth the words

- **Findings become events, not alerts.** Writing an alert row per finding would
  have been fewer lines and would have broken the invariant everything else
  rests on: alerts are a pure function of `(an actor's events, policy)`,
  recomputed on every rescan and never patched. An alert with no event behind it
  would have survived until the next rescan of that actor and then silently
  vanished. As events, findings are reproduced by rescans, covered by the
  hash-chained ledger, and visible to correlation and kill-chain detection —
  **a recon finding can now form the first stage of a chain whose later stages
  Shadowfax detected itself**, with no special-casing anywhere.
- **The detector stops at a finding.** Running the native heuristics over
  finding events would measure the *emitter's* cadence rather than the subject's
  behaviour: a tool reporting forty findings at once would trip `rate_anomaly`,
  and a scanner that runs nightly would trip `dormant_reappearance` every night.
  Neither tells an analyst anything true.
- **A key may not impersonate a detector.** A finding's `key` becomes the alert
  category, so an emitter may not use one of Shadowfax's sixteen native
  categories. An alert reading `destructive_action` must mean Shadowfax's
  detector found it, not that somebody else said so. The rejection names the
  collision.
- **The emitter's id is derived from, never used as, the alert id.** Deriving it
  under a fixed `external` namespace makes re-ingestion idempotent — analyst
  state follows the finding, which is what the envelope's id rule exists for —
  while making a collision with a native alert id impossible by construction.
  An emitter sending a crafted id cannot inherit another alert's acknowledgement.
- **A whole envelope is rejected on any structural error**, with the exact field
  path at fault. Keeping the findings we happen to like would hide the emitter's
  bug, and whoever writes the next emitter deserves to be told what is wrong
  with theirs.
- **Unvalidated findings are marked, never downgraded.** The envelope is
  explicit that a consumer may treat them differently but may not treat them as
  absent. Quietly lowering another tool's severity would be a hidden policy;
  Shadowfax says who claimed it and whether they checked, and leaves the
  judgement to the analyst.
- **A non-actor subject is namespaced by its kind** (`file:sha256:…`,
  `host:10.0.0.9`) under a new `external` actor type, so a file called `admin`
  cannot quietly become the user `admin`. A `kind: actor` subject lands on that
  actor's real timeline — which is the point — and inherits its existing actor
  type rather than introducing a second one for the same actor.
- **Ingested evidence is fenced as untrusted in the assistant's prompt**,
  alongside agent-reported fields. It is another tool's report of a file's bytes
  or a service's banner: exactly where an injection would be planted.

### Tests

65 new checks. Validation (every required field, the five-level ladder,
snake_case keys, boolean `validated`, duplicate ids, native-category collisions
for all sixteen, future versions, bad timestamps); translation (namespacing,
actor-type inheritance, UTC normalisation including offsets, unknown fields
dropped, technique extraction); ingest over HTTP (acceptance, de-duplication on
re-run, derived alert ids, whole-document rejection with the field named, and
that nothing from a rejected envelope is stored); the `info` level weighing
nothing; composition (a finding extending a detected kill chain, the ledger
still verifying, a burst of findings not tripping `rate_anomaly` or
`dormant_reappearance`); and the CLI detecting an envelope without being told.
307 checks in all, green.

## Version 0.10.0

Shadowfax has shipped a `brute_force_auth` detector since v0.1. Until this
version, its own sign-in endpoint would have sailed straight past it: unlimited
attempts, no delay, no record. A tool that detects the attack it is itself
vulnerable to is not a serious tool. This version hardens the front door — and
then points the engine at it, so an attack on the monitoring platform raises the
same alerts, through the same detectors, as an attack on anything it watches.

### Added

- **`throttle.py`** — backoff, then lockout. After a few failures the caller
  must wait a growing interval (2s, 4s, 8s … capped); past the limit the scope
  is refused outright until the lockout expires. `evaluate()` is a pure function
  of `(failure timestamps, now, settings)`: it reads no clock and touches no
  store, which is what lets the tests drive a lockout, a backoff and an expiry
  in microseconds instead of waiting fifteen real minutes.
- **Nothing sleeps.** A server that answers a flood of bad sign-ins by holding
  connections open has turned its own defence into a resource-exhaustion vector.
  Shadowfax answers immediately with `429` and an honest `Retry-After`.
- **Two scopes, with different powers.** Hard lockout applies to a
  **(username, source)** pair — never to the account, because locking an account
  after N failures hands anyone who knows a username a denial-of-service against
  its owner. A second, looser scope covers a **source address across every
  username it tries**, which is what catches password spraying. That one
  **slows but never locks**: an office, a VPN exit or a NAT gateway is shared,
  so locking one out would let a single attacker deny sign-in to everyone behind
  it — the exact attack the control exists to prevent, delivered by the control.
- **`GET /auth/lockouts`** and **`DELETE /auth/lockouts/{username}`** (admin).
  The lockout view asks the same `throttle.evaluate()` the sign-in path does, so
  it cannot drift from the behaviour it describes.
- **`shadowfax lockouts`**, with `--unlock USERNAME`. Exits non-zero while any
  scope is locked, so a script can notice the front door is under attack without
  anyone reading the output.
- **A "Front door" drawer** in the dashboard (admin), showing what is locked and
  the one button needed to let a colleague back in.

### Changed

- **Shadowfax now watches its own front door.** Failed sign-ins and lockouts are
  ingested as ordinary events under the actor `shadowfax-auth`, into the same
  hash-chained ledger as everything else. The existing `brute_force_auth`
  detector fires on them with the same `T1110` mapping, with **no special-casing
  anywhere in the engine** — there is no separate audit path to keep in sync,
  and no privileged log a compromised admin could edit more quietly than the
  rest. Switched off with `SHADOWFAX_SELF_MONITOR=0`.
- **The attempted username is metadata, never the actor id.** It is
  attacker-controlled text: keying actors on it would let anyone mint actors at
  will, or post events into a real actor's timeline by "signing in" as them and
  poison the evidence for an unrelated investigation.
- **`auth.dummy_verify()` closes a timing side channel.** The old endpoint
  returned immediately for an unknown username and spent 200,000 PBKDF2 rounds
  for a known one — a difference trivially measurable over the network, and so a
  reliable oracle for which accounts exist. Both paths now cost the same.
- **`dormancy_exempt_actors` in the policy.** An endpoint that only speaks when
  something happens to it is idle by definition, and alerting on that silence
  would train an analyst to ignore the whole category. The exemption lives in
  the policy rather than as a hardcoded name in `detectors.py`, so detectors stay
  a pure function of `(events, policy)`.
- Configuration comes from the environment (`SHADOWFAX_LOGIN_*`), **not** the
  detection policy. The policy governs detection; this is enforcement of the
  platform's own door. Putting it in the policy would blur the line the project
  rests on, and would put an auth control behind `PUT /policy` where any analyst
  could widen it to nothing. A malformed value falls back to the default rather
  than stopping the API from starting.
- `POST /reset` leaves recorded sign-in attempts alone. Clearing a lockout is
  its own explicit, audited action, not a side effect of a data reset.

### Notes on what this is not

`X-Forwarded-For` is deliberately ignored; the source is the socket peer.
Keying a security control on a header the client sets would hand the control to
the attacker — rotate the header, reset the counter. An operator behind a proxy
must terminate it somewhere that presents the real peer address, and that is
stated in the README rather than quietly assumed.

This slows credential guessing; it does not stop a distributed attacker with
many source addresses, and it is not a replacement for good passwords or a
second factor. Recorded attempts are operational state, pruned on a retention
window — the ledger is what keeps the evidence.

### Tests

52 new checks. The throttle's rules are driven as pure functions (backoff curve,
cap, lockout, expiry, window, source-scope never locking, strictest-wins,
environment parsing including garbage and negatives). Over HTTP: the 401→429
transition, the `Retry-After` header, a locked scope refusing the *correct*
password and accepting it again once released, an unknown username behaving
byte-identically to a known one, admin-only access to both new endpoints, and
releasing a lockout on a username that does not exist. Self-monitoring: failures
and lockouts becoming events, the attempted username staying out of the actor
id, `brute_force_auth` firing against the platform with its ATT&CK mapping, the
ledger still verifying, the dormancy exemption holding, and `dummy_verify`
costing what a real verification costs. 242 checks in all, green.

## Version 0.9.0

The tamper-evident event ledger. Every version until now made Shadowfax better at
judging whether an actor should be trusted. This one asks the prior question: can
the *record* be trusted? An event history that could have been quietly edited
after the fact is not evidence, it is an assertion — and an assertion is not
worth building a detection engine on top of.

### Added

- **`ledger.py`** — a hash chain over the event log. Each stored event carries
  `entry_hash = sha256(prev_hash | canonical_json(content))`, chaining from a
  fixed genesis hash. Because every link folds in the one before it, changing any
  byte of any event invalidates that entry and every entry after it. Pure, no
  I/O, no dependencies beyond the standard library.
- **Breaks are located, not just announced.** `verify_chain()` walks the log and
  reports the *first* position where the recomputed value diverges, with the
  event id, timestamp and actor, plus how many entries before it verified
  cleanly. It distinguishes three failure modes in the message it returns: an
  entry whose content no longer matches its hash (**edited**), an entry that no
  longer chains to the one before it (**deleted or reordered**), and a log that
  is internally consistent but shorter than the recorded head (**truncated**).
- **`ledger_head` table** — the stored entry count and head hash. This is what
  makes truncation visible: lopping entries off the end leaves a shorter but
  internally valid chain, so the chain alone cannot catch it.
- **`GET /ledger/verify`** and **`GET /ledger/head`** (read-only, viewer). The
  head endpoint exists so the head can be exported somewhere outside the
  database's own trust boundary — a log server, a signed commit, a colleague's
  inbox. Anchoring it off-box is what turns "we can tell it changed" into
  something a third party can check.
- **`shadowfax verify`** — exits 0 on an intact ledger, 1 on a broken one, so a
  cron job or CI step can fail on tampering without anyone reading output.
- **Evidence-integrity badge in the dashboard.** It sits next to the connection
  indicator, because both answer the same question: can I believe what I am
  looking at right now. It re-verifies whenever the event count changes, so a
  break surfaces on its own. A broken chain is styled louder than a critical
  alert — every finding below it is suspect until the break is explained.

### Changed

- **`insert_event` now chains.** It reads the current head, computes the new
  entry's hashes and advances the head in the same transaction as the insert, so
  the log and its head cannot drift apart. The chain follows **insertion order**
  (the autoincrement id), not the claimed `timestamp`: events legitimately arrive
  out of chronological order, and ordering by attacker-supplied data would be a
  poor foundation for a proof. What is proven is "these entries were appended in
  this order and none has changed since" — a statement about the store.
- **Existing databases migrate in place.** `init_db` adds the two columns if
  absent and backfills the chain in id order, so a v0.8 database keeps its
  history rather than having to be thrown away.
- `POST /reset` resets the head to genesis along with the events, so the demo
  data verifies cleanly rather than inheriting a stale head.

### Notes on what this is not

Tamper-**evident**, not tamper-**proof**. It makes silent modification and
deletion detectable by anyone who can read the log; it does not prevent them. An
attacker with full write access to the database could rewrite the events, the
chain and the head together — which is exactly why `GET /ledger/head` exists and
why anchoring the head externally is left to the operator rather than quietly
claimed here. Overstating this would be worse than not building it.

### Tests

27 new checks: the head advances on append, a clean log verifies, an edit is
detected *and located* at the right position, restoring the original value makes
it valid again, a deletion breaks the chain link, a truncation is caught by the
head record, hashing is deterministic and independent of metadata key order, and
the endpoints reject unauthenticated callers. Plus the CLI's exit codes.
Full suite green.

## Version 0.8.0

The triage digest. An analyst does not want every alert; they want to know which
few things need them today. Detection says what fired, correlation groups it and
chain detection says which bursts are real attacks — this turns all of that into
a short, ranked queue: *these N need you, and here is why.*

### Added

- **`digest.py`** — `build_digest()` ranks the **open** incidents (those with
  unacknowledged alerts) into a triage queue. Pure function of
  `(incidents, alerts_by_id, now)`.
- **The ranking is deterministic, and it shows its working.** Priority is
  arithmetic over facts already on record: severity, whether the incident
  completed a kill chain, how many alerts are still unacknowledged, and how long
  it has sat. Every item carries the `reasons` that produced its score, so an
  analyst can interrogate the order instead of taking it on trust. A ranking you
  cannot question is one you cannot rely on.
- **It ranks; it does not decide.** Nothing is closed, suppressed or acted on. An
  incident leaves the queue only when a human acknowledges its alerts — there is
  a test for exactly that.
- **`GET /digest`** (read-only, viewer) returns the queue, a deterministic text
  rendering, and optionally the assistant's covering narrative (`?narrative=`,
  `?limit=`). The assistant is handed the order and the reasons *after* they are
  fixed, and its prompt forbids re-ordering the queue.
- **`shadowfax digest`** in the CLI, with `--plain` for the deterministic text
  and `--no-narrative` to skip the model entirely — the "read one thing a day"
  workflow from a terminal or a cron job.
- **Dashboard.** A "Triage digest" view: the covering summary, then each ranked
  item with its severity, unacknowledged count, priority score, kill chain and
  the reasons behind its position. Clicking an actor opens their timeline.

Detection, correlation and chain detection are unchanged. The digest is a pure
reading of what they already produced.

## Version 0.7.0

A command-line interface. Shadowfax watches AI agents, and agents are most at
home in a terminal — they reach for tools they can invoke and output they can
parse. Everything the dashboard does is now reachable from a shell, which also
makes Shadowfax something a harness can wire itself into.

### Added

- **`cli.py`** — a single-file, stdlib-only CLI (argparse + urllib, no new
  dependency): `status`, `login`, `ingest`, `alerts`, `check`, `incidents`,
  `explain`, `search`, `actors`, `stats`, `policy`.
- **It goes through the HTTP API, never the database.** The CLI is just another
  client, so authentication, roles and every policy check apply exactly as they
  do to the dashboard. A convenience tool must not become a way around the
  security model of a security tool.
- **Built to be scripted.** `--json` on every command (and on either side of the
  subcommand), errors to stderr, and meaningful exit codes: `0` success, `1`
  failure, `2` usage, `3` auth, `4` unreachable.
- **`shadowfax check` is a CI gate.** It exits non-zero when alerts match its
  filters, so a harness or pipeline can fail a run the moment the agent's own
  behaviour trips a detector:
  `shadowfax check --severity critical || exit 1`.
- **`shadowfax ingest -`** reads events as JSON from a file or stdin — the
  integration point for a harness emitting its own trace.
- **Config follows the same convention**: `~/.shadowfax/config.json` (written
  `0600` because it holds a session token), overridable by `SHADOWFAX_URL`,
  `SHADOWFAX_TOKEN`, `SHADOWFAX_API_KEY`, `SHADOWFAX_CONFIG` or a flag.
- The transport is injectable, so the test suite drives the real command paths
  against the API's own test client — end-to-end coverage with no live server.

## Version 0.6.0

Attack-chain correlation. Correlation grouped an actor's alerts by time; now it
also asks whether they *advance through the kill chain in order*. A single
mid-severity alert rarely tells the story — an attacker gains access, escalates,
moves laterally, then exfiltrates or destroys. Shadowfax now recognises that
progression and escalates the incident, the "combo move" a lone alert never
shows.

### Added

- **Kill-chain detection in `correlate.py`.** For each incident, the longest
  run of its alerts whose ATT&CK tactics step *forward* through the canonical
  MITRE tactic order (`attack.TACTIC_ORDER`) is found as a strictly-increasing
  subsequence over the time-ordered alerts. Pure and deterministic, like the
  detectors — no LLM decides this. Each incident now carries a `chain`
  (`stages`, `length`, `terminal_tactic`, `escalated`) plus a `base_severity`.
- **Escalation.** A chain of at least `attack_chain_min_stages` tactics (default
  3) that reaches a *terminal* tactic — lateral movement, collection, C2,
  exfiltration or impact — escalates the incident to **critical**, so a burst of
  individually-high alerts that together complete an attack surfaces at the top.
  `base_severity` keeps the un-escalated verdict for transparency.
- **`attack.py` kill-chain ordering.** `TACTIC_ORDER`, `TACTIC` ranking
  (`tactic_rank`), and `TERMINAL_TACTICS` / `is_terminal_tactic`, derived from
  MITRE ATT&CK Enterprise.
- **Dashboard.** The Incidents view shows the chain as an ordered
  tactic → tactic flow, an "escalated high → critical" marker when a chain lifts
  the verdict, and a ⛓ badge on escalated incidents in the list. The incident
  report gains an "Attack chain" section, and the investigation assistant's
  brief includes the chain so explanations can name it.
- **Seed.** `apt-agent-9` walks a clean four-stage kill chain — privilege
  escalation → credential access → lateral movement → exfiltration — in one
  window; its incident escalates from high to critical. Visible after `/reset`.

Detection stays deterministic and unchanged; chain detection is a pure function
of the already-computed alerts and the policy, layered on top of correlation.

## Version 0.5.2

Natural-language alert search — the last item in the v0.5 line. The analyst
types a plain-English request and the assistant *translates* it into a filter
Shadowfax runs. As with the investigation assistant, the model only translates:
it never touches alert data, never decides what is suspicious, and every value
it proposes is validated against Shadowfax's known enums before it can reach a
query.

### Added

- **`assistant.translate_query()`.** Turns a query like "critical destructive
  actions by AI agents last week" into `{severity, actor_type, category,
  actor_id, search, since, until}`. The model returns strict JSON;
  `validate_filters()` then keeps only recognised severities, actor types and
  categories, a non-empty actor id / search term, and parseable ISO time bounds
  — a hallucinated value is simply dropped, so the query that runs is always
  built from values Shadowfax recognises. Time bounds are parameterised, so the
  translated filter cannot inject SQL.
- **`POST /search`.** Read-only: translate, validate, run `query_alerts`, and
  return `{ query, filters, interpretation, source, count, alerts }`. It selects
  which existing alerts to show and reports how it read the query; it creates
  and changes nothing.
- **Time filtering.** `query_alerts` (and `GET /alerts`) gain optional
  `since` / `until` ISO bounds, matched against the stored ISO timestamps.
- **Dashboard.** A plain-English search box above the alert table. Results show
  with a banner stating how the query was interpreted — the exact filters that
  ran — and whether a model or the offline keyword parser read it; Clear returns
  to the live filtered view.
- **Zero-setup.** With no `ANTHROPIC_API_KEY`, a conservative keyword parser
  handles the common cases (severities, actor types, category synonyms, relative
  time windows like "today" / "last week"), so search and its tests work
  offline.

Detection remains deterministic and LLM-free; natural-language search only
chooses which already-computed alerts to display.

## Version 0.5.1

The AI investigation assistant: the first and only place an LLM is used in
Shadowfax, confined to a single verb -- **explain**. Detection, correlation and
ATT&CK mapping have already decided the facts deterministically; the assistant
turns those facts into prose for a human analyst. It creates nothing, decides
nothing, and has no tools.

### Added

- **`assistant.py`.** Builds a deterministic *evidence brief* from an alert (or
  a correlated incident) and its actor's events, then asks a model to explain
  it. `build_alert_brief` / `build_incident_brief` are pure and fully
  unit-testable with no network. `explain()` never raises: on any model or
  network error it falls back to a deterministic narrative and records that in
  the reply's `source`.
- **Read-only explain endpoints.** `GET /alerts/{id}/explain` and
  `GET /incidents/{id}/explain` return `{ narrative, source, model, brief }`.
  They perform no writes and publish no change event -- the assistant explains,
  it never creates or closes an alert. `GET /assistant/status` reports whether a
  model is configured so the dashboard can label narratives honestly.
- **Dashboard.** A "✦ explain" link on every alert row opens a modal with the
  alert's explanation; the Incidents drawer gains an "Explain this incident"
  threat summary. A badge states whether each narrative was written by a model
  or generated deterministically, and a footer restates that the assistant
  explains rather than decides.
- **Zero-setup / provider config.** With no `ANTHROPIC_API_KEY` the narratives
  are generated deterministically, so the feature and the test suite work
  offline. The model (`SHADOWFAX_LLM_MODEL`) and base URL
  (`SHADOWFAX_LLM_BASE_URL`) are overridable; the call uses the stdlib only, no
  new dependency.

### Security

- **Untrusted input is fenced.** Agent-reported fields (tool arguments, targets,
  completion-claim text) are attacker-controlled, so the prompt labels them as
  data inside an `<agent_reported>` block and instructs the model to never treat
  them as instructions. The real safeguard is architectural: the assistant has
  no tools and the endpoints are read-only, so a prompt-injected narrative can
  be wrong but cannot make Shadowfax act.

Detection remains entirely deterministic and LLM-free; the assistant sits
strictly downstream of it.

## Version 0.5.0

Two agent-integrity detectors: completion fraud and token-spend anomaly. Both
are pure functions of an actor's trace and policy -- the deterministic half of
v0.5. (The LLM investigation assistant is a later v0.5 item.)

### Added

- **Completion-fraud detection.** An agent emits a `completion_claim` event
  carrying `metric` and `claimed`; the detector counts what the trace actually
  shows (distinct targets touched, or tool calls) and fires `completion_fraud`
  when delivery falls short of the claim beyond `completion_claim_tolerance`
  (default 0.9). Critical when the agent delivered under half of what it
  claimed, otherwise high. A counting problem, not a judgement -- the exact
  failure practitioners describe (an agent reporting coverage of 40 targets
  whose trace holds 4) and one no LLM is needed to catch.
- **Token-spend anomaly.** Accrues `metadata.tokens` per actor over a rolling
  window and fires `token_spend_anomaly` when spend exceeds the actor's own
  baseline by `token_spend_multiplier` -- the same window shape as
  `rate_anomaly`, reusing its baseline logic.
- Sample `completion_claim` in the seed (recon-agent-3 claims 40 targets, trace
  shows 4), visible after `/reset`.

Both categories are deliberately unmapped to ATT&CK: they are agent-integrity
and cost signals, not adversary techniques. A `completion_claim` is a report,
not a target access, so it does not count toward lateral movement. Sixteen
alert categories now.

## Version 0.4.7

Alert correlation and incident reports (the rest of the roadmap's v0.4).
Detectors say *what* fired; correlation says *these fired together*, collapsing
a stream of alerts into the smaller set of incidents an analyst actually works.

### Added

- **`correlate.py`** groups an actor's alerts into **incidents** by temporal
  proximity: a new incident starts whenever the gap to the previous alert
  exceeds `policy.correlation_window_minutes` (default 30). Pure function of
  `(alerts, window)` -- no I/O, no LLM, deterministic like detection. Each
  incident carries its window, alert count, severity breakdown, unioned
  categories and ATT&CK techniques, a risk score, and a one-line summary.
  Incident ids are deterministic (actor + first alert id).
- **Deterministic incident reports.** `render_report()` produces a factual
  markdown report -- summary, ATT&CK techniques, and a timeline table -- from
  the incident's own data. (The v0.5 investigation assistant is where an LLM
  gets to *explain*; here we only summarise what is already known.)
- `GET /incidents` (correlated list) and `GET /incidents/{id}` (with member
  alerts and the markdown report), computed on read from stored alerts, so
  there is no new table or migration.
- **Incidents view in the dashboard.** An Incidents drawer lists incidents and
  shows the selected one's summary, ATT&CK badges, timeline, and a
  "Copy report" button.

### Changed

- `DEFAULT_POLICY` gains `correlation_window_minutes` (30).
- Backend version is now `0.4.7`.

## Version 0.4.6

MITRE ATT&CK mapping (the roadmap's v0.4 item). Every alert now carries the
ATT&CK technique(s) it corresponds to, so analysts see intent in a shared
vocabulary.

### Added

- **Shared technique registry** (`attack_registry.json`): id -> name, tactic,
  URL. It is the single source of technique metadata for the whole portfolio
  (Shadowfax, claude-recon-agent, maltriage) -- one place a technique id is
  corrected. Technique ids are used verbatim from it; nothing generates one.
- **`attack.py`** maps Shadowfax's alert categories to technique ids and
  enriches them from the registry. `enrich()` silently drops any id the
  registry doesn't know, so a typo shows up as a missing badge, never an
  invented technique. `validate()` (enforced by a test) asserts every id the
  category map and the default policy reference exists in the registry.
- **Per-rule techniques for destructive actions.** Each `destructive_action`
  rule in policy declares its own `attack` id, because `rm -rf` (T1485 Data
  Destruction) and a system shutdown (T1529) are both destructive but different
  techniques. Fixed detectors use the category mapping; unmapped categories
  (policy controls, pure anomalies) carry no technique, which is honest.
- Alerts now include an `attack` array (`[{id, name, tactic, url}]`) on
  `/alerts` and `/actors/{id}`, and the dashboard shows a linked technique
  badge (e.g. `T1485`) on each alert. `GET /attack` returns the registry.

### Changed

- `alerts` gains an `attack` column (JSON). A pre-v0.4 alerts table without it
  is dropped and rebuilt on startup (alerts are derived; `alert_state` is
  keyed by id and preserved).
- Backend version is now `0.4.6`.

## Version 0.4.5

Agent traces as events. Shadowfax now watches an AI agent's tool calls, not just
human-style activity. No schema change: a tool call is an event with
`event_type: "tool_call"` and its shape (`tool`, `arguments`, `exit_status`,
`duration_ms`, optional `host`/`port`/`url`) in `metadata`.

### Added

- **Destructive-action detection.** A new `destructive_action` category fires
  when a tool call matches a policy pattern -- recursive delete, database drop,
  credential write, disk wipe, system shutdown. Rules live in
  `policy.destructive_action_rules` (label + severity + case-insensitive
  substrings), so the patterns are governed by policy and reachable by tests,
  and detection stays deterministic. First matching rule wins; one alert per
  call.
- **Engagement scope.** `policy.engagement_scope` (allowed domains, IP ranges,
  ports) defines the rules of engagement. A tool call whose destination host,
  IP or port falls outside it fires `out_of_scope_action`. IP ranges are
  matched with the stdlib `ipaddress` module; only calls with a real network
  destination are checked, so filesystem and symbolic targets are left alone.
- Sample agent traces in the seed data (an offensive-security agent that runs
  in-scope, out-of-scope and destructive tool calls), visible after `/reset`.

Detectors remain a pure function of `(actor history, policy)`; both new
categories are just rules in `detectors.py`. The dashboard needed no change --
the new categories flow through the existing table and category filter.

### Note on rescan cost

A recon session is one actor with potentially hundreds of tool calls, and a
rescan replays an actor's full history (linear in its length). This is accepted
deliberately for now rather than bounded: the stateful detectors
(capability resurrection, privilege tracking) need the whole history, so a
naive recompute-window cap would break them. When trace volume makes this hurt,
the fix is incremental detector state, not a shorter replay -- recorded here so
it is a decision, not a surprise in v0.5.

## Version 0.3.2

Live updates over Server-Sent Events, replacing the poll loop.

- **The poll loop is gone.** The dashboard opens one `EventSource` to
  `GET /stream` and refreshes on demand instead of fetching every five seconds.
  Ingesting an event, editing policy, resetting, or acknowledging an alert now
  reaches every open dashboard in well under a second (measured ~0.3s), and the
  browser holds one long-lived connection rather than a request every 5s.
- A small in-process bus (`bus.py`) fans a `change` signal to each subscriber;
  the stream carries only the signal, so each client re-queries with its own
  server-side filters. `publish()` is safe to call from the sync endpoints.
- The stream authenticates by `?token=` (the browser `EventSource` cannot set
  an `Authorization` header) or a Bearer header for non-browser clients; a
  15-second keepalive comment holds the connection open. Service API keys
  cannot stream. The connection indicator now reflects the live stream.
- Backend version is now `0.3.2`.

## Version 0.3.1

Authentication, roles and API keys.

- **Sign-in with user accounts.** `POST /auth/login` issues an opaque bearer
  token; `POST /auth/logout` revokes it; `GET /auth/me` returns the current
  user. Sessions expire after 12 hours. Passwords are hashed with PBKDF2 and a
  per-user salt; only token and API-key fingerprints are stored, never the
  secrets themselves. Stdlib only -- no new dependencies.
- **Roles.** `admin` > `analyst` > `viewer`. Reads need `viewer`; acknowledge,
  assign and policy edits need `analyst`; reset, user management and API-key
  management need `admin`. Every previously open endpoint is now protected.
- **API keys for ingest.** Agents and harnesses push events with an
  `X-API-Key` header. `POST /api-keys` (admin) returns the key once; it is
  ingest-only and cannot read alerts.
- **`acknowledged_by` is server-set** from the session, so an acknowledgement
  always records who really made it -- the request body can no longer spoof it.
- **First admin** is created on a fresh database from
  `SHADOWFAX_ADMIN_USERNAME` / `SHADOWFAX_ADMIN_PASSWORD`; with none set, a
  default `admin`/`admin` is created and a loud console warning is printed.
- **CORS is locked down** to the dashboard origin (default
  `http://localhost:5173`, override with `SHADOWFAX_CORS_ORIGINS`) instead of
  being open to all origins.
- **Dashboard login.** A sign-in screen gates the console; the token is kept in
  `localStorage` so a reload stays signed in, and a 401 drops back to login.
  The top bar shows the current user and role with a sign-out button, and the
  UI hides actions a role cannot perform (a viewer sees state read-only).
- Backend version is now `0.3.1`.

## Version 0.3.0

Stable alert identity and the analyst state it unblocks. First backend change
since v0.1.

### Added

- Deterministic alert ids. An alert's id is now
  `sha256("shadowfax|{actor}|{category}|{event_id}")[:16]` rather than an
  autoincrement integer, so recomputing the same alert from the same input
  yields the same id. `detectors.alert_identity` is the single source of the
  rule, and it follows the shared findings-envelope id form (actor as subject,
  `category` as the machine-stable key, event as the discriminator).
- `alert_state` table holding per-alert acknowledgement, assignment and notes,
  keyed on the deterministic id. It is deliberately not foreign-keyed to
  `alerts`, so a rescan's delete-and-reinsert leaves it untouched and the state
  re-attaches to the same alert when it is rebuilt.
- `PATCH /alerts/{id}/state` to acknowledge, assign or annotate an alert.
  Unknown ids 404. Alert responses (`/alerts`, `/actors/{id}`) now carry
  `acknowledged`, `acknowledged_by`, `assigned_to` and `note`.
- Startup rebuilds alerts when events exist but the alerts table is empty
  (after a restart or the schema migration below).

### Changed

- `alerts.id` is now `TEXT PRIMARY KEY`. A pre-v0.3 database with an integer
  `alerts.id` is migrated on startup by dropping the alerts table (alerts are
  derived data) and rebuilding it with deterministic ids; `alert_state` is
  keyed by id and is preserved.
- Backend version is now `0.3.0`.

### Why message is excluded from the id

The roadmap and `architecture.md` originally described the id as a hash of
"actor, event, category and message". Including the human-readable message
would mean that editing a detector's wording silently changed every historical
alert's id and destroyed any acknowledgement attached to it -- the exact
failure the findings envelope warns against for titles. The id therefore hashes
the machine-stable `category` (the envelope's "key") and excludes `message`.

### Dashboard

- The alert table has a Status column with per-row **Acknowledge** and
  **Assign** controls, wired to `PATCH /alerts/{id}/state` through the single
  `api.js` client. Acknowledged rows are dimmed and show who acknowledged them;
  assignment shows an `@user` tag. Updates are optimistic and reconciled on the
  next poll.
- Acting analyst is a placeholder (`CURRENT_USER` in `constants.js`) until
  authentication lands; it fills `acknowledged_by` / `assigned_to`.
- Because ids are now stable, `AlertTable` and `ActorDrawer` update rows in
  place instead of tearing them down each poll.

## Version 0.2.1

Defect-clearing pass over the v0.2 dashboard and backend. No new features.

### Fixed

- Unticking every severity or actor type now shows no alerts instead of all.
  An empty selection short-circuits the alert request rather than sending no
  parameter, which the API reads as unfiltered.
- The search box is debounced (300 ms), so typing fires one request after it
  settles instead of one per keystroke. The input stays responsive; only the
  settled value drives a fetch.
- Category filtering is wired to the sidebar. "Categories seen" is now a set
  of checkboxes that filter server-side via the `category` parameter `/alerts`
  already supported. The list is accumulated from alerts ever seen, so options
  don't vanish when a category filter narrows the view. Empty selection means
  all categories (opt-in narrowing, since the category set is discovered, not
  fixed).

### Changed

- Backend startup migrated from the deprecated `@app.on_event("startup")` to a
  `lifespan` context manager.
- `app.py` type hints aligned to the `str | None` style used elsewhere;
  dropped the `Optional` import.

### Notes

Alert identity is still keyed on `alerts.id`, which changes on every rescan.
That is the v0.3 stable-alert-identity item, not part of this pass.

## Version 0.2.0

Dashboard release. The backend is unchanged.

### Added

- React dashboard under `frontend/`, built with Vite
- Live alert table, sortable by severity, category, actor or time
- Actor timeline drawer, showing an actor's full event history with alerts
  attached to the events that produced them
- Risk composition bar, breaking an actor's risk score down by severity
- Filtering by severity, actor type and free-text search, applied server-side
- Policy editor, editing the live policy as JSON and triggering a full rescan
  on save
- Connection status indicator, reflecting whether the last poll succeeded
- Severity counts in the top bar, refreshed on every poll

### Notes

The dashboard polls `/stats` and `/alerts` every five seconds. This is a
deliberate choice for v0.2: it needs no backend changes, no connection
lifecycle handling and no reconnect logic, and a five second delay is
invisible to an analyst reading a screen. WebSocket or SSE push is a v0.3
item.

`frontend/src/api.js` is the only file in the dashboard that calls `fetch`,
which is what makes the dashboard-talks-only-to-the-API rule enforceable by
reading one file.

The dashboard holds no detection logic. Severity colours and sort order are
presentation only.

Alert identity is still not stable. Rows are keyed on `alerts.id`, which
changes on every rescan, so the table re-renders rather than updates. This
matters more now than it did in v0.1.0 and is the blocker for any per-alert
analyst state. See Known Constraints in `architecture.md`.

Neither the API nor the dashboard has authentication. Both are v0.3.
