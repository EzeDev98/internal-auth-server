
## Step 17c — userActivationExecutor cleanup ticket (2026-09-05)
Confirmed via grep across src/main and src/test: AsyncConfig's
"userActivationExecutor" bean has zero call sites. No @Async("userActivationExecutor"),
no @Qualifier reference, no manual executor.execute() lookup anywhere in the codebase.
The only other @Async mention in the repo is an unrelated comment in CorrelationIdFilter.java.

Decision: dead code, not a test gap. Filed as a cleanup ticket to either:
  (a) delete the unused bean (and @EnableAsync if nothing else needs it), or
  (b) wire it up if async user-activation processing was actually intended.
No test added for this step.

## Step 20A — Running the tests

### Unit tests (fast, no Docker)
./mvnw test
Runs everything matching *Test.java via Surefire. No external services required.

### Integration tests (Docker required)
./mvnw verify
Runs *IT.java via Failsafe, spinning up Testcontainers Postgres + Redis (Step 1A/1B).
Requires a running Docker daemon — confirm with `docker info` first if this fails.
Also produces the JaCoCo report at target/site/jacoco/index.html.

### Security-boundary tests only (Step 5 / 13 / 14 — release blockers)
./mvnw test -Dgroups=security-boundary
./mvnw failsafe:integration-test failsafe:verify -Dgroups=security-boundary

### Coverage-gate policy (Step 18C)
JaCoCo enforces a minimum 65% line coverage on ./mvnw verify (see the
jacoco-check execution in pom.xml). The build fails if coverage drops
below that floor. This is a starting threshold, expected to ratchet up in
later sprints — it is not a target to stay at.

CI (.github/workflows/ci.yml) mirrors this locally-runnable split:
unit tests on every push, integration tests pre-merge on PRs/main, and
security-boundary tests as their own required check independent of the
general coverage gate.

## Step 20B — Living checklist policy

This roadmap is not a one-time checklist to close out and forget. Every time
a new endpoint, service, or repository method is added to this codebase, it
must get an explicit same-day test-coverage decision — not silently deferred
"for later."

That decision is one of:
- **Covered now** — a unit and/or integration test is added in the same PR.
- **Deliberately deferred** — documented here (or in the PR description) with
  a reason and a follow-up ticket, the same way Step 17C documented the
  unused `userActivationExecutor` bean as a cleanup ticket rather than
  silently skipping it.

What this policy explicitly rules out: adding a new authenticated endpoint,
a new RBAC-touching service method, or a new multi-tenant code path with
zero test-coverage decision recorded anywhere. Untracked debt is how the
original cross-tenant RBAC/session bugs (Steps 14A) went unnoticed in the
first place — this step exists so that class of gap doesn't recur silently.

## Step 20C — Quarterly multi-tenancy regression policy

The Step 14 multi-tenancy boundary suite (same-username-across-tenants
login/role/session isolation, JWT tenant scoping, and the "RBAC stays
global" guard) must be re-run on two independent triggers, not just once:

- **Every quarter**, on a fixed schedule, regardless of whether anything
  tenant-related was touched — as a backstop against silent regressions
  introduced by unrelated refactors.
- **Immediately, on-demand**, whenever a new tenant-touching feature ships
  (anything that adds or changes a `client_application_id`-scoped lookup,
  a new per-tenant uniqueness constraint, or a new JWT claim consumed in a
  tenant-scoping decision).

This is a standing policy, not a one-time task: the original cross-tenant
RBAC/session leaks (fixed in Step 14A) already proved this class of bug
recurs quietly when it isn't deliberately re-checked. Wire the on-demand
trigger into PR review (flag any diff touching a `client_application_id`
column/claim/param and require a linked Step 14 suite run before merge);
the quarterly run can be a calendar reminder or a scheduled CI job.
