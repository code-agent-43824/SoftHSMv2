# AGENTS.md — rules for coding agents

The owner's canonical rules, shared by all of his projects. Copy this file into a
repository as is; project-specific material goes in the [Appendix](#appendix--what-to-add-per-project).

## 0. How the rules are organised

- **`AGENTS.md` is the single source of rules**, read by every agent: Claude Code, Codex, Copilot, Gemini.
- **`CLAUDE.md`, `.github/copilot-instructions.md` and `GEMINI.md` never restate the
  rules.** They hold an import of this file plus a map of the code — architecture,
  commands, pitfalls, what is *not* here. Two copies drift, and the stale one gets followed.
- **Project rules extend this file; they never override it.** A necessary departure is
  stated with its reason under "Departures" in the project's `AGENTS.md`; a silent one
  is a mistake.
- If the owner asks otherwise on a task, that is his call — no rule broken, no change to this file.

## 1. Git

- **One working branch — the repository's trunk** (`main`, or `master` in older
  repositories; same thing). **No branches, no pull requests.**
- **Each completed logical step is its own commit, pushed immediately.** Do not pile
  work into one large commit or mix unrelated changes.
- **The trunk is always green.** A commit that breaks the build, the tests or the linter does not go in.
- **A red trunk outranks your own task.** Broke it yourself — fix it now. Someone else
  broke it — tell the owner and get his go-ahead first, since another agent may be on
  it already. Ask immediately: this comes before the work you arrived to do.
- **`git fetch` before starting** — the local trunk may be behind another agent's work.
- **Before committing, run `git diff --check` and `git status`** — no stray temp, generated or other agents' files.
- **Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/),
  in English:** `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `ci:`, `test:`. Say what
  and why; the message stands without the diff.
- **Use plain git commands.** The GitHub API is for reading only — statuses, logs, releases, artifacts.

## 2. Project documents

Six documents, each answering one question. **A fact lives in exactly one of them** — when unsure, this table decides.

| Document | Answers | How it lives |
| --- | --- | --- |
| `docs/ROADMAP.md` | **Where we are going** — the product, its stages, their order | Long-lived; changes rarely |
| `docs/PLAN.md` | **What we are doing in the current stage** — actions with `[ ]` / `[~]` / `[x]` / `[!]` | Rewritten when the stage closes |
| `docs/STATUS.md` | **What state the project is in now** — what works, what is broken, version, where work stopped | One screen; overwritten |
| `docs/WORKLOG.md` | **What we did** — one entry per chunk: plan → done → next | Append-only, newest on top |
| `docs/JOURNAL.md` | **What we learned** — hypothesis → what we did → what the check showed → conclusion | Append-only, newest on top |
| `HANDOFF.md` | **What is unfinished right now** — in-flight work and the exact next step | Overwritten; says so when nothing is in flight |

`AGENTS.md` and `HANDOFF.md` sit in the repository root and are read first; the rest lives in `docs/`.

**`WORKLOG` vs `JOURNAL`** is the easy one to get wrong. Worklog is operational — what I
set out to do, did, and have left, so interrupted work can be picked up; a typo fix belongs
there. Journal is about knowledge — what we now know and did not yesterday: a hypothesis
tested on real hardware, the cause of a bug, a settled question. Routine edits never reach it.

- **Never delete failed attempts from `JOURNAL`.** Each closes off a hypothesis you would return to.
- **`STATUS` and `HANDOFF` do not update themselves.** Checked or changed the real state — reconcile them in the same session.
- **Overwrite another agent's `HANDOFF` entry only once that work is finished.** Unfinished
  work is never erased — carrying it is why the file exists. Cannot tell? Treat it as
  unfinished.
- **What is not written down was not started.**
- **When code and documentation disagree, fix the documentation in the same change.**
- Create a document when first needed; do not pre-create empty files.

## 3. Order of work

1. **Read** `AGENTS.md`, `HANDOFF.md`, `docs/STATUS.md`, `docs/PLAN.md` and the top of
   `docs/JOURNAL.md`.
2. **Write down the intent before the code** — the action in `docs/PLAN.md` as
   `[ ]`/`[~]`, the reasoning in `docs/WORKLOG.md`. **Commit that separately, before
   touching code**: a docs-only commit is always green.
3. **Do the work.**
4. **Verify it**, proportionally to the risk of the change (§4).
5. **Record the result in the same change as the code:** `WORKLOG` (done / next),
   `PLAN` (`[x]`/`[!]`), `STATUS` (if the project's state changed), `JOURNAL` (if
   something was learned), `HANDOFF` (if stopping before finishing).

The goal: the next agent can tell **what was planned, what shipped and what is next
from the documents alone**, without reading the diff.

## 4. Verification and honest reporting

- **Never present the unverified as verified.** Could not run the tests — no SDK, no device,
  no access — say so plainly. Silence reads as "checked".
- **A green CI badge is not proof.** For build and deploy changes, read the actual logs and artifacts.
- **Simulation is not a claim about hardware or security.** Fakes exercise logic, not devices.
- **Close gaps with data, not reasoning.** Do not put a property into an algorithm that is not
  in the confirmed facts: guessed changes have already produced wrong results.
- **Do not invent domain content** — statute text, expert commentary, readings, constants.
- **Report the actual outcome.** Tests failed — show the output. A step was skipped — say so.
  Work is blocked — finish the rest and name what was left undone.

## 5. Actions an agent does not take alone

Most mistakes are undone by the next commit. These are not, so ask the owner first:

- **Losing data** — migrations that drop or rewrite data, destructive fixtures, clearing any
  store holding the only copy of something.
- **Removing published artifacts** — branches, tags, releases.
- **Rewriting history** — `force-push`, rebasing published commits, `filter-branch`. The
  trunk's history is append-only.
- **Changing a public contract** — API shape, wire and stored-data formats, identifiers other
  systems depend on.
- **Revoking or replacing keys and credentials** (§7).
- **Anything inside someone else's system** — another project's server, a shared host, a
  third-party account.

Say what would be lost, what the alternative is, and what you recommend. Once he agrees, do it
and record his decision in `JOURNAL`, so the next agent sees it was sanctioned, not improvised.

## 6. Deployment

Who deploys depends on **whether deployment needs manual work on the server**: a project that
**deploys itself through CI** may be deployed by **any agent**; one that **needs manual work on
the server** is deployed by **Watson only**, and other agents do not touch production.

- **If a push to the trunk means a production deploy, the project's rules say so.** There is no
  staging, which makes the green-trunk rule critical: a red commit is a broken production.
- **Do not create deploy keys, server credentials or release jobs** without the owner's decision.
  A change in the repository is never permission to deploy it.
- **No destructive operations on shared resources.** Where a webroot, database or host is shared
  with other projects, use only the deployment script provided — no `rsync --delete` over a whole
  directory. Unfamiliar directories are someone else's.
- **After deploying, verify what is live** — your project and its neighbours.

Production broken: **tell the owner immediately**, before investigating; **fix forward with a new
commit** — a revert is an ordinary commit and the bad one stays in history (§5); once back up,
record in `JOURNAL` what broke, why, and what now prevents it.

## 7. Secrets

- **Never commit** credentials, tokens, private keys, personal data or production config.
- **Keep vendor binaries out of git** — fetch them with build scripts, pinned by SHA-256.
- **Found a secret? Report it. Do not remove it yourself, and never without the owner's
  knowledge.** It may be a deliberate exception; deleting it from the working tree leaves it in
  git history while suggesting the leak is closed; and revoking the key is his action in external
  systems. Name the exact file and commit, then let him decide.
- **A deliberate exception must be explicit.** Something secret-looking committed on purpose is
  recorded under "Settled decisions" with its reason — without it, every later agent re-raises it.

## 8. Settled decisions

Every project's rules carry a **"Settled decisions"** section: things decided deliberately that
look like mistakes to a fresh pair of eyes.

- **Each decision is recorded with its reason.** The reason is mandatory — without it the next
  agent clears the decision away as junk.
- **An agent never reopens these on its own initiative.** Only the owner reverses them.
- Closed topics belong here too. Do not raise them again unasked.
- Durable architectural decisions become ADRs under `docs/decisions/` where a project needs it.

## 9. Scope and style of changes

- **Prefer clear, boring, maintainable solutions over speculative abstractions.**
- **Add dependencies, frameworks and infrastructure only as the adopted spec and the current
  stage require.** Anything beyond the adopted stack, including any third-party cloud service,
  needs a settled decision first.
- **Add or update tests alongside the code they cover.**
- **Preserve unrelated work.** Unrelated cleanup goes into `PLAN.md` as its own item.
- **UTF-8, LF line endings.**

## 10. Language

- **Reply to the owner in Russian.**
- **Project documentation in Russian.**
- **Code identifiers and commit messages in English.**
- **Agent instruction files — this one, `CLAUDE.md`, `copilot-instructions.md` — in English.**
  They are instructions executed by a model, not documentation for a reader.
- **UI strings follow the project's convention.** Where tests assert on them, change both.

## 11. Working alongside other agents

Several agents may work in a repository at once, and any session can be interrupted.

- **Keep changes narrow and independently reviewable.**
- **Every task must stay resumable** — unfinished state belongs in `HANDOFF.md`.
- **Roles may be split** (only Watson deploys, for example); the project's rules say so.

## 12. Environment

- **The environment is ephemeral.** Redo the GitHub access setup each session if it does not persist.
- **The proxy returns HTTP 403 on some writes** — pushing a tag, deleting a branch, writing
  through the REST API. This is policy, not a failure: **do not work around it, report it.**
  Where the operation is genuinely needed, a workflow performs it.

## 13. Owner review

Where the owner checks by hand — installing a build on his phone, opening the site — **pause
after each completed stage** before starting the next. What he checks is in the project's rules.

## Appendix — what to add per project

This file is copied unchanged; project-specific material goes below it or in `CLAUDE.md`:

- **Commands** — build, tests, linter, formatter, and how to run a **single** test.
- **Map of the code** — architecture, entry points, non-obvious couplings.
- **Settled decisions**, with reasons (§8).
- **Departures from this file**, with reasons (§0).
- **Version discipline** — where the version lives and what changes with it.
- **Deployment** — CI or manual, who may do it, what to verify after (§6).
- **What the owner reviews**, and where a pause is expected (§13).

---

# Project appendix — SoftHSMv2 portable fork

Project-specific material. It extends the rules above; it never overrides them.

## What this repository is

A private fork of `opendnssec/SoftHSMv2`, forked at upstream commit `f12916e`.
It builds an installer-free PKCS #11 module that emulates a Rutoken ECP token,
so software written against a Rutoken can be tested where no physical token can
be plugged in — a cloud server, a CI runner, a developer machine without a USB
port. GOST 2012 support exists to serve that goal.

**The fork is terminal.** Nothing goes upstream, nothing is pulled from
upstream, and upstream compatibility is not a constraint on any change.

## Commands

Third-party versions and their SHA-256 pins live in `.github/workflows/ci.yml`
(`OPENSSL_*`, `BOTAN_*`); the portable build scripts require them in the
environment and fail without them.

| Task | Command |
| --- | --- |
| Ordinary build | `cmake -S . -B build && cmake --build build --parallel` |
| Portable build (Linux) | `PORTABLE_ARCH=x64 OPENSSL_VERSION=… OPENSSL_SHA256=… BOTAN_VERSION=… BOTAN_SHA256=… scripts/portable/build-linux.sh` |
| Portable build (macOS / Windows) | `scripts/portable/build-macos.sh`, `scripts/portable/build-windows.ps1` |
| Unit tests | `cmake -S . -B build && cmake --build build --parallel && ctest --test-dir build --output-on-failure` |
| A single unit test | `ctest --test-dir build -R cryptotest --output-on-failure` |
| End-to-end PKCS #11 test | unpack a test kit, then `bash run-test.sh` (`run-test.cmd` on Windows) |
| E2E against another vendor's module | `tests/portable/run-pkcs11-integration.sh <module.so>` — see `tests/portable/README.md` |

ctest targets: `cryptotest`, `p11test`, `objstoretest`, `datamgrtest`,
`sessionmgrtest`, `slotmgrtest`, `handlemgrtest`, `softhsm2utiltest`.

There is no linter or formatter configured. `ENABLE_STRICT` is ON by default;
the portable builds compile with warnings-as-errors settings from
`cmake/modules/CompilerOptions.cmake`.

## Map of the code

- `src/lib/SoftHSM.cpp` — the Cryptoki entry points. Reads `FAKE_RUTOKEN_ECP`
  and, when set, rewrites the library/slot/token presentation and the advertised
  mechanism list. The object store and the cryptography are untouched by it.
- `src/lib/common/SimpleConfigLoader.cpp` — configuration discovery. The
  portable path logic sits behind `SOFTHSM2_PORTABLE_USER_CONFIG`; ordinary
  builds keep upstream's `SOFTHSM2_CONF` behaviour.
- `src/lib/common/Configuration.cpp` — the table of known configuration keys.
- `src/lib/crypto/` — the two backends. **Non-obvious coupling:**
  `OSSLCryptoFactory` instantiates `BotanStreebog256` when
  `WITH_GOST_3411_2012` is set, so an OpenSSL-backend build links Botan for
  GOST 2012. See "Settled decisions".
- `src/lib/crypto/BotanGOST2012{KeyGenerator,Signer}.{cpp,h}`,
  `BotanStreebog256.{cpp,h}` — GOST R 34.10-2012/256 and Streebog-256.
- `src/lib/pkcs11/pkcs11.h` — the TC26 mechanism identifiers.
- `src/lib/pkcs11/rutoken.h` — the Rutoken `C_EX_*` extension ABI, written from
  the vendor SDK rather than copied from it. `docs/RUTOKEN-EXTENSIONS.md`
  describes every entry point and names the SDK release the layout came from.
- `src/lib/object_store/` — token and object persistence.
- `scripts/portable/` — per-platform build scripts and OpenSC bundling.
- `tests/portable/` — the vendor-neutral PKCS #11 client
  (`portable-token-e2e.cpp`), its launchers, and the test kits.
- `.github/workflows/ci.yml` — one job: build the portable dependency
  combination and audit the produced archive.
- `.github/workflows/portable-release.yml` — six build jobs, six fresh-runner
  verification jobs that consume the published archives as an outside user
  would, then the release job.

Portable behaviour is gated by the CMake option `ENABLE_PORTABLE` (default OFF)
and requires the OpenSSL backend. GOST 2012 is gated by
`ENABLE_GOST_3411_2012` and `ENABLE_GOST_3410_2012_256` (both default OFF).

## Settled decisions

- **Upstream's CI matrix was deleted deliberately.** `ci.yml` no longer builds
  Botan-backend, OpenSSL 1.1.1, OpenSSL 3.0, OpenSSL 4.0, macOS or Windows unit
  test configurations. *Reason:* the fork is terminal — nothing is contributed
  upstream and nothing is merged from it — so building configurations we do not
  ship is wasted CI time. Do not restore those jobs.
- **Upstream's documents are abandoned, not maintained.** `README.md`, `NEWS`,
  `CMAKE-NOTES.md`, `CMAKE-WIN-NOTES.md`, `OSX-NOTES.md`, `WIN32-NOTES.md`,
  `FIPS-NOTES.md` are upstream leftovers. *Reason:* they describe a project we
  no longer track. This appendix and `docs/` are the only authority; ignore the
  contradictions and do not spend effort reconciling them.
- **`FAKE_RUTOKEN_ECP` — presenting the module as a Rutoken ECP — is the
  point of the fork, not a trick.** *Reason:* it exists to test software that
  talks to a Rutoken ECP in places where the physical token cannot be inserted,
  such as a cloud server. It is opt-in and defaults to false.
- **Under that profile the module advertises the reference device's whole
  mechanism list, including mechanisms this build does not implement.** This
  reverses the earlier decision not to advertise what is not implemented.
  *Reason:* the owner's decision of 13 August 2026 — applications judge
  compatibility from the list alone, and the missing algorithms are planned.
  Calling an unimplemented mechanism fails with `CKR_MECHANISM_INVALID` from
  the operation itself. The list, its order, key sizes and flags come from one
  source: the raw `pkcs11-tool -M` output of the owner's device, mirrored in
  `verifyRutokenProfile` in `tests/portable/portable-token-e2e.cpp`. Change
  either only against a new reading of a real device.
- **The Rutoken extended function table is exported unconditionally, while the
  one entry point that reports anything answers only under the profile.**
  *Reason:* applications treat a missing `C_EX_GetFunctionListExtended` as
  proof the module is not a Rutoken, an export cannot be hidden at runtime
  anyway, and the profile flag is read from configuration during
  `C_Initialize` — too late for a function that, like `C_GetFunctionList`, has
  to work before it. Returning the table claims nothing on its own;
  `C_EX_GetTokenInfoExtended` is the claim, and it is gated.
- **Portable modules ignore `SOFTHSM2_CONF`, adjacent files and system
  configuration paths**, using one fixed per-user configuration and token store
  (`%USERPROFILE%\softhsm\softhsm.conf`, `~/softhsm/softhsm.conf`). *Reason:*
  portability — the module must behave identically wherever it is unpacked, and
  32-bit and 64-bit processes must share one store.
- **GOST 2012 is implemented with Botan even in the OpenSSL-backend portable
  build.** *Reason:* a deliberate choice; the OpenSSL backend has no usable
  GOST 2012 and the alternative was a GOST engine dependency that portable
  builds cannot statically carry.
- **Rutoken Control Center is out of scope, and PC/SC is not a direction.**
  *Reason:* the owner's decision of 21 August 2026. The application connects to
  a PC/SC reader by name and its import table has no `SCardListReaders`, so no
  amount of PKCS #11 fidelity makes its device card appear; satisfying it needs
  a virtual reader answering APDUs, which is a separate product. The library is
  for other programs. Work its start-up cycle prompted was still done, because
  other software asks the same things.
- **The device is the reference even when it refuses.** An attribute the
  reference Rutoken does not carry is not carried here either, however plainly
  an application asks for it — `0x80003010`, `0x80000009` and `0x80003304` are
  refused for exactly this reason, and the refusal of the first is pinned in
  the gate. *Reason:* answering where the device refuses is a departure from
  the device, not better compatibility. "The application got further" is a
  weaker test than "this is what the device does", and the two have already
  disagreed once.

## Departures from the rules above

- **§9 "Preserve unrelated work" does not extend to upstream code we drop.**
  Removing upstream build configurations, jobs and documents is expected here.
  It still applies in full to work done inside this fork.
- **§2 "a fact lives in exactly one document" is violated by the abandoned
  upstream documents.** They are not being fixed; see "Settled decisions".
- **Commits `1f65ddd`…`c688ea8` (1–11 August 2026) predate these rules in this
  repository** and largely do not follow Conventional Commits. History is
  append-only (§5), so they stand. Every commit from `2ff7bd0` onward follows
  the convention.

## Version discipline

`VERSION` lives in `CMakeLists.txt` (`set(VERSION "2.7.0")` plus the
`VERSION_MAJOR/MINOR/PATCH` triple) and in `configure.ac`. It still tracks the
upstream version and is not bumped by fork work.

Releases are tagged `v2.7.0-portable.N`; `N` increments by one per release and
is not reused. The current tag is `v2.7.0-portable.25`.

## Deployment

There is no server. A "deploy" is a GitHub release of the portable archives,
produced only by the `Portable release` workflow. It builds six platform
archives, verifies each on a fresh runner of the same architecture as an
outside consumer would, and publishes only if all six pass.

That workflow runs in two modes:

- **Automatically**, after `CI` succeeds on `main` (`workflow_run`). It builds
  and verifies all six platforms. If anything except project documentation has
  changed since the latest portable release, it then increments `N` and
  publishes the verified archives. Documentation-only changes still get the
  full build but no new tag. This is the owner's decision of 21 August 2026:
  significant changes must become public without a manual follow-up. A newer
  automatic run supersedes an older one.
- **On `workflow_dispatch` with an explicit `release_tag`**, which remains an
  emergency path for creating or replacing a deliberately named release.

Under `workflow_run` the checkout must name
`github.event.workflow_run.head_sha`: `github.sha` there is the default
branch's tip, which is not necessarily the commit CI approved.

- **Never create or push a release tag from a session.** The workflow creates
  the tag; the proxy refuses tag pushes by policy (§12).
- Any agent may run the manual workflow, since it needs no work on a server.
- **After a release, read the run's logs and download one published archive**
  before reporting success. A green run badge is not proof (§4).

## What the owner reviews

The owner installs a portable build or a test kit by hand and runs his own
Rutoken-facing software against it. **Pause after each completed stage** and
let him check before starting the next.
