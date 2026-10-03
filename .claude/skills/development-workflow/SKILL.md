---
name: development-workflow
description: How implementation work is run in spring-config-guard so the maintainer keeps an accurate mental model of the system while changes land faster than they can be read line by line — plan and stop at defined checkpoints, implement autonomously, prove the result with evidence (tests, before/after findings, the /actuator/env benchmark), review adversarially, record decisions in the repository, report in a fixed shape, and commit/push only after explicit approval. Use for every task that changes code, tests, fixtures or project documentation.
---

# Development workflow

The assistant can produce more code than the maintainer can read line by
line. The goal is not to slow down, but to change the level of the
interaction: the assistant does the mechanical and investigative work; the
maintainer keeps ownership of architecture, invariants, trade-offs, risks and
long-term maintenance. Speed is fine. **Unreviewed work piling up is not.**

This skill builds on `CLAUDE.md` (Critical Analysis, Technical Discussions,
Implementation and Validation, Commit Messages) instead of repeating it.

## 1. Before implementing

A plan comes first for any task that changes behavior, touches a pipeline
stage (`ConfigLoader`, `ConfigFileGrouper`, `ProfileMerger`, `RuleEngine`,
`Main`), adds or changes a rule, or spans more than one production file.
Trivial Java choices (naming, a helper method, collection types) never need
one.

Keep the plan short and cover:

* **Problem**: what is wrong or missing, with a concrete input that shows it
  (a config fixture, a command and its output) whenever possible.
* **Current state**: the files, classes and flow involved, read from the
  code, not assumed.
* **Invariants to preserve**: the relevant `CLAUDE.md` sections (relaxed
  binding, placeholders, Zero-Trust, pipeline boundaries) and ADRs in
  `ARCHITECTURE.md`.
* **Side effects and regressions**: what else could change, including
  findings on real-world projects.
* **Verification**: which evidence from section 4 will prove the change.
* **Proposal**: the approach, and the simpler alternative if one exists.

## 2. Checkpoints: stop and ask

Stop, present alternatives with trade-offs and a recommendation, and wait
for the maintainer when a decision:

* changes a public contract: `Finding` fields, the JSON report, console
  format, exit codes, CLI flags, the Policy file schema, rule IDs or
  severities of existing rules;
* changes merge, precedence, discovery or placeholder semantics;
* adds a severity, a pipeline stage, or an abstraction other code will
  depend on;
* alters, reverses or contradicts an ADR, or needs a new one;
* changes findings on the reference corpus (section 4) in a way the plan
  did not predict;
* removes or weakens a test.

If one of these appears mid-implementation, stop there, even if the plan was
already approved.

## 3. Implementing

After the plan is agreed, implement autonomously: related edits across
files, running tests, fixing breakage the change itself caused, iterating.
Don't ask permission for low-risk local corrections. Don't hide an
architecturally meaningful concept behind an abstraction; if a simpler
solution works adequately, use it or mention it before adding structure.

## 4. Verifying with evidence

Passing tests are necessary, not sufficient. Use the evidence the change
calls for, and in the report say exactly what ran, the numbers it produced,
and what was **not** run and why.

* **Unit/integration tests**: `mvn test`, reporting the test count.
* **Before/after findings** for any change to discovery, grouping, merging
  or rules. Compare the jar of the change with the jar of the last
  published release, downloaded from the release and checked first (its
  sha256 must equal the release asset's digest); for a comparison inside
  unreleased work, build the jar at the base commit. Run both on the same
  inputs, and diff the JSON, stderr included:
  * `demo-project/` showcases and `demo-project-clean/`;
  * the `VALIDATION.md` repositories at their pinned SHAs. A sparse, blobless
    fetch of `application*` files is enough; include `pom.xml` and
    `build.gradle*` too, since discovery depends on them.

  Every added or removed finding must be explained. If a documented number
  changes, `VALIDATION.md` changes in the same commit.
* **`/actuator/env` benchmark** when merge or discovery semantics are
  touched: start `spring-env-benchmark` with the `prod` profile on port
  8081, then `mvn test -Dgroups=benchmark -DexcludedGroups=`
  (`VALIDATION.md`, "ProfileMerger correctness benchmark"). Stop the app
  afterwards.
* **Scenarios in a running app** (Actuator, CORS, SpringDoc, ...): start one
  app per scenario, wait until the previous one has released the port and
  the new one has logged `Started` (or failed, which is a result too), and
  only then measure. A leftover app answers instead and silently
  contaminates every following scenario, as in the first run of the SCG003
  review; `spring-env-benchmark/cors-scenarios.sh` shows the pattern.
* **Rules**: apply `.claude/skills/review-security-rule/SKILL.md`.

## 5. Adversarial self-review

Before reporting, look for: behavioral regressions; false positives and
false negatives; edge cases (placeholders, relaxed binding, explicit null,
empty lists and maps, multi-document files, profiles); violated invariants;
unnecessary coupling, abstraction, duplication or complexity; tests that
pass without demonstrating the behavior their name claims; documentation
that no longer matches the code.

A self-review shares the author's blind spots. Compensate in two ways:

* name the **one to three places in the diff most worth reading by hand**,
  and why;
* for larger changes, run an independent review (`/code-review`, or a
  subagent given the diff but not the implementation reasoning).

## 6. Recording decisions in the repository

The maintainer's mental model must live in the repository, not in a chat
transcript that disappears. In the same commit as the change:

* project-wide decisions with trade-offs → a new ADR in `ARCHITECTURE.md`
  (never edit an accepted ADR's decision; supersede it);
* rule-scoped decisions → the rule's own Javadoc;
* new or changed conventions and invariants → `CLAUDE.md`;
* boundaries users need to know → README, "Scope & Limitations";
* changed validation numbers → `VALIDATION.md`;
* work discovered but not done now → `BACKLOG.md`, and a finished item is
  removed from it (its record is the ADR, `VALIDATION.md` or the commit).

Source code and Javadoc never reference backlog items or files that aren't in
the repository: the reason for a decision belongs next to the code or in an
ADR. Documentation may point to `BACKLOG.md`. If existing references like
that turn up while working, report them to the maintainer.

## 7. Commit and push

* One coherent concern per commit. If the pending work spans more, say so
  and propose separate commits.
* **No commit and no push without the maintainer's explicit approval of
  that commit.** Before every commit, in this order: show the diff, explain
  in plain words what changes and why, and present the full commit message
  (`CLAUDE.md`, "Commit Messages"). Then stop and wait. Commit and push only
  after an explicit "yes" to what was shown.
  * A conditional go-ahead ("if X holds, commit") is not approval: report
    whether X holds, with the evidence, and ask again. Never judge the
    condition alone.
  * An approval covers only the diff and message shown. Any change after it
    (a fix, an extra file, a reworded message) needs the gate again.
  * A request to make a commit ("make a commit for this") is a request to
    prepare one: it still goes through the gate above.
* **Verify before proposing, not after approval.** Errors found only when
  carrying out an approved commit mean the proposal wasn't checked. Before
  showing a diff and message:
  1. Re-read the rules the text must follow: `CLAUDE.md`, "Commit
     Messages" (title, scope, bullet-list body), and the format of each
     document the diff touches.
  2. Check every factual claim in the diff and the message against the
     repository, with the command that proves it: class, package and file
     names, the rules cited and what each does, numbers, dates, quoted
     text. Nothing written from memory. A Spring property cited is checked
     in the configuration metadata of the Boot version measured: it
     exists, has the type stated, and is not deprecated at level `error`
     (no longer bound). A property that is deprecated but still bound is
     named as such.
  3. Re-read the diff as a reviewer looking for what is wrong (section 5).
  Only then present it. An error found after approval still stops the
  commit: show it with its before and after, and ask again.
* Never start a second change while one is still unreviewed.
* After approval: commit, push to `main`, then check the CI run for that
  commit and report its result. No `Co-Authored-By` trailer.
* Commit identity, the same rule in every environment (cloud session or
  local, e.g. Claude Code Desktop): the maintainer is always the
  **author**, and the **committer** is never overridden.
  * Check `git config user.email`. If it is already the maintainer's (a
    local session using their own git configuration), commit as is: their
    own identity and signing key apply.
  * If it is another identity (a cloud session's own), set only the
    author to the maintainer (`git commit --author=...` or
    `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL`), the same author as the existing
    history.
  * Why the committer stays: cloud sessions sign commits with a platform
    key registered to the session's identity, so GitHub shows them as
    Verified; setting the committer to the maintainer's email makes GitHub
    look for that key on the maintainer's account and mark the commit
    Unverified. Never register the platform key on the maintainer's
    account: it isn't theirs to control.

## 8. Reporting

Two shapes, by what the report answers: an **analysis** (a rule review, a
code review, an investigation: what is wrong, what is right, what must be
decided) or an **implementation** (a change ready for the commit gate: what
changed and how it was proven). A task that does both reports the analysis
first and stops for decisions before implementing.

In both, conclusions come first and stay short. Raw data (scenario tables,
logs, command output, long test lists) never carries the argument: it goes
to the repository (`VALIDATION.md`, a script, a test) or to a file the
maintainer can open, and the report cites only the row or line that
supports each conclusion (e.g. "A8: the app refused
`http://localhost.evil.com`").

### Analysis report

Five sections, in this order, each kept even when empty ("None"), so an
empty one reads as checked rather than forgotten:

1. **Confirmed bugs**: wrong behavior in the code under analysis, each with
   the concrete input, the wrong result measured and its impact (a false
   negative hides a risk; a false positive fails builds). Only what was
   reproduced belongs here; a suspicion not yet verified goes to section 4
   as something to check, or isn't reported.
2. **Documentation and policy**: Javadoc, README, `VALIDATION.md` or
   messages that state something false or leave out a boundary users need
   to know, and code that departs from a `CLAUDE.md` invariant (relaxed
   binding, placeholders, Zero-Trust, Findings severity).
3. **Verified correct**: what was checked and holds, one line each with
   the evidence (e.g. "upper-case `HTTP://` origins: reported, and Spring
   matches them"). It keeps the maintainer from re-checking it and shows
   what the analysis covered.
4. **Decisions needed**: each trade-off the maintainer owns, as options
   (Option A, Option B, ...) with their pros and cons, and a
   recommendation (`CLAUDE.md`, "Critical Analysis"). Section 2's
   checkpoints are decided here.
5. **Out of scope**: what was found outside the subject (another rule, the
   pipeline, a neighboring setting), with where it goes: a `BACKLOG.md`
   item, or a separate change proposed after this one. It never mixes into
   sections 1 to 4.

For a rule review, `review-security-rule`'s classes map onto these
sections: implementation bug → 1; inherent static-analysis limitation not
yet documented → 2; deliberate scope decision and verified Spring Boot or
library behavior → 3; design preference, or a technically weak decision
that needs a choice → 4; speculative or non-existent requirement → 3, with
why it was rejected.

### Implementation report

Keep it proportional to the change; a comment fix gets a few lines. Start
with the part that matters most:

1. **What you need to understand**: only the concepts, decisions and
   behavior changes the maintainer must own to master this change.
2. What changed, and why.
3. Technical decisions taken, with the alternatives considered.
4. Evidence: what ran, the numbers, what didn't run and why.
5. Side effects investigated, and what they showed.
6. Tests added or changed.
7. Remaining risks.
8. Where to look in the diff (section 5).

Anything the change touches beyond what was approved (an extra fix that
fell out of the same cause) is named in item 1, with the offer to split it
into its own commit.

### Both shapes

When something in a draft you wrote turns out to be wrong before you show
it (a claim, a number, a test), say so in the report and show it before and
after the correction, rather than presenting only the corrected version.

No line-by-line walkthrough. Where a task is genuinely complex, say where the
complexity is instead of simplifying the explanation. When the maintainer's
proposal has a problem, say so directly, as `CLAUDE.md` "Critical Analysis"
requires: the goal is better decisions, not agreement.

The report is written in the conversation's language; section names may be
translated.
