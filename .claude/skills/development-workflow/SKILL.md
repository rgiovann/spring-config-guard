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
  or rules. Build the jar at the base commit and at the change, run both on
  the same inputs, and diff the JSON:
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
* changed validation numbers → `VALIDATION.md`.

Never reference files that aren't in the repository (backlog item labels,
untracked notes). If existing references like that turn up while working,
report them to the maintainer.

## 7. Commit and push

* One coherent concern per commit. If the pending work spans more, say so
  and propose separate commits.
* Propose the commit message (`CLAUDE.md`, "Commit Messages") and **wait for
  explicit approval** before committing or pushing.
* Never start a second change while one is still unreviewed.
* After approval: commit with the maintainer's git identity (the same
  author as the existing history, no `Co-Authored-By` trailer), push to
  `main`, then check the CI run for that commit and report its result.

## 8. Reporting

Keep the report proportional to the change; a comment fix gets a few lines.
Start with the part that matters most:

1. **What you need to understand**: only the concepts, decisions and
   behavior changes the maintainer must own to master this change.
2. What changed, and why.
3. Technical decisions taken, with the alternatives considered.
4. Evidence: what ran, the numbers, what didn't run and why.
5. Side effects investigated, and what they showed.
6. Tests added or changed.
7. Remaining risks.
8. Where to look in the diff (section 5).

No line-by-line walkthrough. Where a task is genuinely complex, say where the
complexity is instead of simplifying the explanation. When the maintainer's
proposal has a problem, say so directly, as `CLAUDE.md` "Critical Analysis"
requires: the goal is better decisions, not agreement.
