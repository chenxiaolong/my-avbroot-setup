# Upstream relationship strategy

This fork tracks [`chenxiaolong/my-avbroot-setup`](https://github.com/chenxiaolong/my-avbroot-setup). The strategy below operationalises [PixeneOS ADR-0002](https://github.com/0cwa/PixeneOS/blob/main/docs/planning/decisions/ADR-0002-compatible-fork-of-my-avbroot-setup.md) ("Maintain a compatible fork of `my-avbroot-setup`").

## Goal

Carry the minimum diff against upstream that still lets PixeneOS ship a working LineageOS / non-Pixel ROM build. Promote hunks upstream when upstream is willing to take them; keep the rest as a small, rebase-able patchset.

## Branch layout

| Branch | Role | Rebase policy |
|---|---|---|
| `master` | Tracks `upstream/master`, plus the smallest set of fork-only hunks. | Rebased onto upstream on every upstream release. Force-push allowed because the branch is treated as a topic-on-upstream, not a long-lived line of independent history. |
| `docs/upstream-strategy` (this branch) | Documentation only — no code change. | Merge into `master` once reviewed. Then delete. |
| `pr/<topic>` (when active) | Single-topic branches cut from `upstream/master`, used to open upstream PRs. | Each is rebased on `upstream/master`, never on fork `master`. Deleted when the PR merges or is rejected. |

There is intentionally **no** long-lived `compat-lineage` branch. The earlier ADR-0002 proposed one, but with only ~21 commits ahead of upstream — and several of those being incremental "thread the variable" patches — a single rebase-clean `master` is simpler than a topic branch + master.

## What lives in `master` (fork-only hunks)

The authoritative split is in [`upstream-disposition.md`](./upstream-disposition.md). In summary, the fork-only hunks are:

- The `--compatible-sepolicy` CLI flag and the `Module.inject(..., compatible_sepolicy)` plumbing.
- ODM partition handling (when `--compatible-sepolicy` is set).
- The CIL fallback path (`patch_cil_policy`, `get_cil_rules_for_partition`) and `lib/modules/cil_rules.py`.
- `patch_vendor_cil_for_ueventd` (the IPA / `vendor_firmware_file` bootloop fix).
- The compatible-mode multi-partition `seapp_contexts` append.

Everything else either belongs upstream (and will be PR'd separately) or should be dropped (formatter churn, license-wording revert, leaky log line).

## What does **not** live in `master`

- **Formatter churn** (single→double quotes, reflowed `argparse`/`subprocess` calls). Upstream uses single quotes consistently. The next rebase pass should drop the formatter run; see disposition hunk 1.
- **`README.md` GPLv3 wording revert.** Upstream clarified to `GPL-3.0-only` in `e59576e`; reverting to `GPLv3` is strictly weaker. Drop on next rebase; see disposition hunk 11.
- **`logging.info(f"Provided arguments: {args}")` in `main()`.** Logs a raw `argparse.Namespace` that includes passphrase env-var names and key paths. Drop or downgrade to debug-level with explicit safe-fields only; see disposition hunk 12.

## Rebase checklist (run on every upstream release)

1. `git fetch upstream`.
2. `git rebase upstream/master` on `master`. Resolve conflicts conservatively — prefer upstream wording for unrelated changes (see "What does not live in master" above).
3. Run the existing scripts against a known-good OTA in `--debug-shell` mode to catch regressions.
4. If a previously fork-only hunk has been merged upstream, drop it from the rebase and update [`upstream-disposition.md`](./upstream-disposition.md) to mark it landed.
5. Force-push `master` with `--force-with-lease`.
6. PixeneOS pins this fork by commit SHA (see PixeneOS `src/declarations.sh` `VERSION[AVBROOT_SETUP]`); update that pin in a PixeneOS PR once the rebase is verified.

## Upstream PR cadence

PRs are opened one at a time, smallest and least-opinionated first. The current sequencing is in [`upstream-prs/`](./upstream-prs/):

1. `PR-A` — partition-specific `file_contexts` (correctness fix; no flag).
2. `PR-C` — extract `append_seapp_contexts` helper (pure refactor).
3. `PR-B` — sepolicy existence checks (defensive coding).

The `--compatible-sepolicy` flag, ODM handling, and CIL fallback are **not** scheduled for upstream PRs without a separate design discussion. They stay fork-only.

## Provenance / authorship note

The fork's 21-commit history (vs upstream merge-base `8413918`) was developed iteratively, partly with AI assistance (commits authored as `cto-new[bot]`). Three commits accidentally added planning notes (`COMPATIBLE_SEPOLICY_ANALYSIS.md`, `FINDINGS.md`, `SELINUX_FILE_CONTEXTS_FIX.md`) that were later removed; the final tree is clean. When cherry-picking these commits into `pr/*` branches for upstream PRs, the AI-planning-file additions must be elided via interactive rebase.
