# Upstream disposition — per-hunk decomposition of the `master` delta

> **Authoritative copy.** This document lives in the fork repo because it describes *this repo's* delta against upstream. PixeneOS links here from `docs/tickets/ROMCOMPAT-1.md`, `docs/tickets/META-3.md`, and `docs/planning/decisions/ADR-0002-compatible-fork-of-my-avbroot-setup.md`.

**Fork:** `0cwa/my-avbroot-setup` at `91e49bc255672c98bf92d7d747f7b0cf12e01a80` (tip of `master`)
**Upstream:** `chenxiaolong/my-avbroot-setup` at `e59576e` (`README.md: Clarify that license is GPLv3 only`)
**Merge-base:** `8413918` (`Update pydantic for compatibility to python 3.14.0`)
**Diff range used:** `git diff upstream/master..origin/master` against a full clone
**Diff size vs upstream tip:** 9 files, +594 / -175
**Ahead/behind vs upstream:** 21 ahead, 1 behind (only the upstream license-wording clarification `e59576e`)

This document was originally produced as PixeneOS ticket [`ROMCOMPAT-1`](https://github.com/0cwa/PixeneOS/blob/main/docs/tickets/ROMCOMPAT-1.md) — a planning-only ticket allowed because the upstream-vs-fork choice is hard to reverse. Its output unblocks PixeneOS [`META-3`](https://github.com/0cwa/PixeneOS/blob/main/docs/tickets/META-3.md) (upstream PR vs compatible fork) and `ROMCOMPAT-2/3/4`.

## Important note on commit shape

The ticket described `91e49bc` as "a single LineageOS-compat commit (+594/-175)". That framing is misleading and was reinforced by an earlier shallow research clone that only fetched the tip. The true picture:

- The fork branched from upstream at `8413918` and added **21 commits**, ending at `91e49bc`.
- The `+594 / -175` figure is the **cumulative** delta against current upstream tip `e59576e`, not the diff of any single commit.
- `91e49bc` itself is a 500/207 rollup that ships the CIL fallback (`cil_rules.py`, `patch_cil_policy`, `get_cil_rules_for_partition`) plus the formatter run plus a `logging.info(f"Provided arguments: {args}")` line; it touches files already modified by earlier commits in the same branch.
- Three earlier commits in the branch (`d964701`, `3e4cf51`, `65c5bea`) accidentally added AI-generated planning files (`COMPATIBLE_SEPOLICY_ANALYSIS.md`, `FINDINGS.md`, `SELINUX_FILE_CONTEXTS_FIX.md`); `8d1b3e2` and `91e49bc` later removed them. The final tree is clean.

All hunk numbers below are versus upstream `master@e59576e`. Logical hunks are still the right unit for the upstream-vs-fork decision — the 21-commit history is too noisy to upstream commit-by-commit — but the existing commits **do** map well to several logical hunks, which makes assembling clean PR branches by cherry-pick feasible (see "Commit → hunk mapping" below).

## Hunk inventory

Each hunk below is a **logical** unit, not a raw diff hunk. Quote-style/formatter churn is split out as its own hunk so it does not contaminate the upstreamability judgement of substantive changes.

| # | Files touched | ~Lines (+/-) | Summary | Disposition | Rationale | Upstream PR-readiness |
|---|---|---|---|---|---|---|
| 1 | `patch.py`, `lib/modules/__init__.py`, `lib/modules/custota.py`, `lib/modules/msd.py` | ≈ +250 / -160 (mostly reflow) | **Formatter churn.** Single→double quotes, reflowed multi-line `argparse` and `subprocess` calls, ellipsis-on-same-line for abstract methods. ~27 lines are pure quote flips; ~208 added lines contain double-quoted string literals. | **D** (drop) | Mechanical formatter output. Upstream uses single quotes consistently; submitting this would be rejected on style alone and would obscure the substantive changes. | N/A — drop before any upstream slice. |
| 2 | `patch.py` | +5 | **`--compatible-sepolicy` CLI flag.** `argparse` flag with help text "Change sepolicy files to allow patching other selinux partitions and don't fail if selinux is missing." | **F** (fork-only initially); maintainer may consider a narrower **U** later. | The flag bundles three behaviors (graceful sepolicy fallback, ODM handling, CIL fallback). Upstream likely wants either (a) auto-detect rather than a flag, or (b) finer-grained flags. Naming is opinionated — `--compatible-sepolicy` reads as a verb-on-policy rather than a ROM-class switch. | LOW as-is. Could become MEDIUM if split: just the flag plumbing + auto-detect on missing precompiled policy. |
| 3 | `lib/modules/__init__.py`, `lib/modules/alterinstaller.py`, `lib/modules/bcr.py`, `lib/modules/custota.py`, `lib/modules/msd.py`, `lib/modules/oemunlockonboot.py` | +6 / -2 | **`Module.inject()` signature change.** Adds `compatible_sepolicy: bool = False` parameter to the abstract method and threads it through all five module implementations. Three modules accept-and-ignore it; only `custota` and `msd` consume it. | **F** (couples to #2) — or **U** if #2 lands first. | Pure plumbing for #2; meaningless without that flag. The default-false value is backward-compatible, so it would be acceptable upstream once the flag is accepted. | Couples to #2 — judge with #2. |
| 4 | `patch.py`, `lib/modules/__init__.py` | +30 / -2 | **ODM partition handling.** Adds ODM to `need_ext_fs` when `compatible_sepolicy`; checks `odm/etc/selinux/precompiled_sepolicy`; patches `odm_sepolicy.cil` and `odm_seapp_contexts`. | **F** | Device-coupled. ODM is present on Pixel/Samsung/etc. but not all targets, and upstream's design currently treats `vendor` as the canonical secondary partition. Upstream is likely to want a partition-list-driven abstraction (e.g., `--ext-partition odm,oem`) rather than a hard-coded ODM branch. | LOW. Would need redesign as a generic mechanism before upstreaming. |
| 5 | `patch.py` | +20 / -2 | **Partition-specific `file_contexts` lookup.** Replaces the single `system/etc/selinux/plat_file_contexts` load with a per-partition lookup that prepends partition-specific contexts to the plat ones (e.g., `vendor/etc/selinux/vendor_file_contexts` + `plat_file_contexts`). Falls back to plat-only when the partition file is absent. | **U** | This is a correctness fix that benefits *all* ROMs, not just LineageOS. Android's sepolicy model puts partition-specific labels in per-partition `*_file_contexts`; using only `plat_file_contexts` mislabels new files written into vendor/odm trees. Independent of the `--compatible-sepolicy` flag. | **HIGH.** Smallest, least-opinionated PR-able slice. |
| 6 | `patch.py`, `lib/modules/custota.py`, `lib/modules/msd.py` | +25 / -8 | **Sepolicy existence check (graceful fallback).** Wraps `vendor_boot/sepolicy` and `vendor/etc/selinux/precompiled_sepolicy` in `.exists()` checks; modules also skip the `subprocess.check_call` when a sepolicy file is missing. Currently gated behind `compatible_sepolicy=True` in the modules but unconditional in `patch.py`. | **U** (with caveat) | The `patch.py`-side existence checks are pure defensive coding — strictly safer than the current crash. The module-side gating could land too if framed as "auto-skip when target file is absent" rather than as a LineageOS feature. | **HIGH** for the `patch.py` half. **MEDIUM** for the module half — likely needs to drop the `compatible_sepolicy` gate (always check `.exists()`) to be upstream-acceptable. |
| 7a | `lib/modules/__init__.py`, `lib/modules/custota.py`, `lib/modules/msd.py` | +20 / -25 (net negative when isolated) | **Refactor: extract `append_seapp_contexts` helper.** The duplicated `with z.open('plat_seapp_contexts'); system_fs.open(seapp, 'ab')` block in `custota.py` and `msd.py` is hoisted to `lib/modules/__init__.py`. | **U** | Pure deduplication; reduces lines on net; no behavior change in the default path. Independent of the flag. | **HIGH.** Trivially upstream-acceptable on its own. |
| 7b | `lib/modules/__init__.py` | +25 | **Compatible-mode multi-partition seapp_contexts append.** When `compatible_sepolicy=True`, the helper also appends to `vendor/etc/selinux/vendor_seapp_contexts` and `odm/etc/selinux/odm_seapp_contexts` if they exist. | **F** | Couples to #2 and #4. Useful only when ODM/vendor seapp tables are present, which is ROM-specific. Skippable if either filesystem is unmounted. | LOW alone; couples to #2 + #4. |
| 8 | `lib/modules/__init__.py`, `lib/modules/custota.py`, `lib/modules/msd.py` | +60 | **CIL fallback path.** New helpers `patch_cil_policy(path, rules, marker)` and `get_cil_rules_for_partition(ext_fs, partition, rules)`; consumed in `custota.py` and `msd.py` via `if compatible_sepolicy and not sepolicies: ... patch CIL directly`. Idempotent via marker comment. | **F** | Upstream comments explicitly say "We only update the precompiled policies and leave the CIL policies alone." Reversing that policy needs maintainer buy-in and is the most opinionated change in the diff. The marker-comment idempotency is good engineering but does not change the design tension. | LOW. Realistic upstream path is a separate flag (`--patch-cil`) plus a discussion thread, not a drive-by PR. |
| 9 | `lib/modules/cil_rules.py` (new file, 129 lines) | +129 / -0 | **`cil_rules.py`** — module-keyed table of CIL rule strings (`CUSTOTA_CIL_RULES`, `MSD_CIL_RULES`) with a `get_cil_rules(name)` accessor. | **F** (couples to #8). Ticket Note suggests this is "easiest to upstream as a self-contained PR" — see warning below. | The data itself is independent, but it has **no caller** without #8. Submitting it alone produces dead code that upstream will (rightly) reject. The module rule sets also encode SELinux types not present in upstream Android (`custota_app`, `msd_daemon`) and depend on the patcher to declare them — landing it without the consumers is meaningless. | LOW. The ticket's hint that this is the easiest standalone upstream PR is **not supported by the code**: it depends on #8. |
| 10 | `lib/modules/__init__.py`, `lib/modules/custota.py` | +60 | **`patch_vendor_cil_for_ueventd`.** Appends `(allow ueventd vendor_firmware_file …)` rules to `vendor_sepolicy.cil` (and `odm_sepolicy.cil` in compatible mode) so that the rules survive a Custota live update where LineageOS recompiles policy from CIL during the swap. Idempotent via marker. | **F** | Highly specific to a Pixel-class IPA-firmware bootloop scenario when LineageOS recompiles policy from CIL during OTA. Useful and well-targeted, but device/ROM-class-coupled and not something upstream is likely to take without a documented incident pattern. The fact that PixeneOS hit this in the wild is documentation worth keeping in the fork. | LOW. Could be upstreamed later with a written incident report and an opt-in flag. |
| 11 | `README.md` | +1 / -1 | **License wording change.** `GPL-3.0-only` → `GPLv3`. | **D** (drop) | Strictly weakens precision. Upstream just clarified this in `e59576e` to be SPDX-compliant. Reverting it is wrong and would fail review. PixeneOS should match upstream wording. | N/A — drop. |
| 12 | `patch.py` | +1 | **Provenance log line.** `logging.info(f"Provided arguments: {args}")` at start of `main()`. | **D** (or U trivial) | Logs raw `argparse.Namespace`, which can include passphrase env-var names and key paths. As written, leaks more than it should. If reframed (logger.debug with `--input`/`--output` only), could be a nano-PR upstream. | LOW as-is; trivially TINY if reframed. |

Every line of the +594 / -175 delta is accounted for: hunk 1 absorbs the formatter churn (≈ half of the line count), hunks 2–10 are the substantive logical changes, and hunks 11–12 are one-liners.

## Disposition summary

- **Drop (D):** 1, 11, 12 — formatter churn, license-wording regression, leaky log.
- **Upstream (U):** 5, 6 (with scoping), 7a — three small correctness/refactor PRs that stand on their own.
- **Fork-only (F):** 2, 3 (couples to 2), 4, 7b (couples to 2+4), 8, 9 (couples to 8), 10 — the entire `--compatible-sepolicy` feature surface and its CIL fallback.

## Draft upstream-PR descriptions for `U` rows

### PR-A — Hunk 5: load partition-specific `*_file_contexts`

> Currently, all ext partitions inherit only `system/etc/selinux/plat_file_contexts` for SELinux label lookup. New files written into the `vendor` or `odm` trees end up labeled by the platform table, which is wrong for any file path covered by a partition-specific entry. This PR loads `<partition>/etc/selinux/<partition>_file_contexts` when present and prepends it to the platform contexts so partition-specific entries take precedence; falls back to platform-only when the partition file is absent. No new flags. Behavior is unchanged on Pixel-class GrapheneOS targets where the partition file is identical to platform; the change is observable on ROMs that ship distinct partition tables.

### PR-B — Hunk 6 (`patch.py` half): tolerate missing precompiled sepolicy files

> `patch.py` currently fails hard if `vendor_boot/sepolicy` or `vendor/etc/selinux/precompiled_sepolicy` is absent. Some ROMs (notably AOSP-based forks) ship one but not both, and there is no functional reason to require both when the missing file would simply not be patched. This PR wraps both lookups in `.exists()` and only adds present files to `selinux_policies`. When neither is present, downstream module sepolicy patching is skipped — the existing `for sepolicy in sepolicies` loop already handles an empty list correctly. No flag. No new code paths.

### PR-C — Hunk 7a: extract `append_seapp_contexts` helper

> `custota.py` and `msd.py` carry an identical 7-line block that opens `plat_seapp_contexts` from the module zip and appends it to `system/etc/selinux/plat_seapp_contexts` with a trailing newline. This PR hoists that block to `lib/modules/__init__.py` as `append_seapp_contexts(zip, seapp_contexts_name, ext_fs)` and replaces both call sites. Net negative line count, no behavior change.

## Commit → hunk mapping (assembling clean PR branches)

Because the 21-commit fork history happens to isolate several of the upstreamable hunks into their own commits, PR branches can be assembled by cherry-pick rather than reimplemented from scratch. The mapping below is approximate — the exact list should be re-verified at branch-cut time — but it shows there is a viable path.

| Logical hunk | Source commits in `0cwa/my-avbroot-setup` | Notes |
|---|---|---|
| 2 `--compatible-sepolicy` flag | `55695f3` | Adds the `argparse` flag. |
| 3 inject() signature plumbing | `5c65bf2`, `f89133a`, `96d6769`, `9cb2a09`, `96dadf3`, `91dbde3`, `48a1a94`, `b32d683` | Many small "thread the variable" commits; would need squashing. |
| 5 partition-specific `file_contexts` | `d964701`, `3e4cf51`, `65c5bea` | Three commits authored by `cto-new[bot]`; `65c5bea` also drops AI-generated planning notes — cherry-pick will need a `git checkout HEAD~1 -- COMPATIBLE_SEPOLICY_ANALYSIS.md FINDINGS.md SELINUX_FILE_CONTEXTS_FIX.md` cleanup or interactive rebase to elide. |
| 6 sepolicy existence checks | `90946bc`, `8ebbc0b` | Two small commits, one for `patch.py` / `custota.py`, one for `msd.py`. |
| 7a `append_seapp_contexts` extract | (mixed into `91e49bc`) | Not a discrete commit; would need to be hand-extracted. |
| 7b multi-partition seapp append | `02affde` | Discrete. |
| 8 CIL fallback path | (part of `91e49bc`) | Mixed with hunk 1 (formatter) and hunks 7a/9/12 in the same rollup commit. |
| 9 `cil_rules.py` | (part of `91e49bc`) | New file; trivially extractable. |
| 10 `patch_vendor_cil_for_ueventd` | `e590617` | Discrete. |
| 1 formatter churn | (mostly inside `91e49bc`, with smaller bleed in earlier commits) | Mechanical; should be removed before any upstream PR is opened. |
| 12 leaky log line | `0eda560`, `357d448` | Discrete. |

Practical implication for the smallest first integration step: **PR-A can be a `git cherry-pick d964701^..65c5bea` followed by an interactive rebase to drop the AI-planning-file additions**, rather than re-authoring the change. PR-B is similarly assembled from `90946bc^..8ebbc0b`. PR-C must be hand-extracted from `91e49bc`.

## Smallest safe first integration step

**Open PR-A first.** It is the cleanest correctness fix in the diff, requires no flag, no API change, no design discussion, and is independently valuable. It also tests upstream's appetite for accepting work from this fork before any opinionated change is on the table.

If PR-A is accepted, follow with PR-C (pure refactor) and PR-B (defensive coding). After all three land, revisit the `--compatible-sepolicy` flag in a separate design discussion — by that point upstream and PixeneOS will share more code, and the conversation about CIL fallback and ODM handling can happen with shared context.

The hunks marked **F** should *stay in the fork as fork-only* until and unless that design discussion succeeds. Specifically: do not submit hunk 9 (`cil_rules.py`) on its own as the ticket Notes suggested — without hunk 8 it is dead code and will be rejected.

## Validation sources and uncertainty

**Validation sources**

- This repository (`0cwa/my-avbroot-setup`) with `upstream = chenxiaolong/my-avbroot-setup`. The full commit history is what backs every claim below.
- The original PixeneOS-side analysis was performed against `.pi/research/my-avbroot-fork/` (a *shallow* clone, depth=1, which led to an initial "single root commit" misreading) and `.pi/research/my-avbroot-upstream/`. Both are checkouts inside the PixeneOS repo's research area; the shallow-clone error was caught and corrected before the disposition was finalised.
- `git diff --stat upstream/master..origin/master` matched the +594/-175 figure asserted in the ticket.
- `git rev-list --left-right --count upstream/master...origin/master` returned `1   21` (1 behind, 21 ahead). Merge-base verified at `8413918`.
- The ticket's "single LineageOS-compat commit" framing was incorrect; the disposition above corrects it. The original analysis at the *logical-hunk* level remains valid because the +594/-175 cumulative delta is what consumers see, regardless of how it was split across commits.

**Uncertainty / known gaps**

- The line counts in the table are approximate per-hunk attributions; quote-style churn overlaps with several hunks and was assigned to hunk 1 only when it was the *sole* change on a given line. Net per-file figures match `git diff --stat`.
- Upstream-PR-readiness scores assume the maintainer's prior public stance on minimal scope, not direct conversation. Actual receptiveness is unknown until PR-A is opened — which this ticket explicitly does not do.
- The `--compatible-sepolicy` semantics assume LineageOS is the canonical target. CalyxOS, DivestOS, and other AOSP forks may have different precompiled-vs-CIL profiles and would need their own validation before the F hunks are claimed to "support those ROMs".
- Hunk 10 (`patch_vendor_cil_for_ueventd`) is justified by an IPA firmware bootloop scenario; the underlying incident report has not been independently reproduced in this analysis. The code is conservative (idempotent, marker-gated) so the risk of including it in the fork is low even without reproduction.
- Hunk 12 leaks argparse arg names that include `--pass-avb-env-var` / `--pass-ota-env-var` *names* but not their values. The leak is mild but the `D` disposition is conservative.

## Follow-up actions (consumed by PixeneOS tickets and this fork's branches)

The concrete actions implied by this disposition; PixeneOS tracks the planning-side, this repo carries the code-side:

| Action | Owner | Where it lives |
|---|---|---|
| Open PR-A (hunk 5: partition-specific `file_contexts`) against `chenxiaolong/my-avbroot-setup`. | this repo | Branch `pr/partition-file-contexts`, see [`upstream-prs/PR-A-partition-file-contexts.md`](./upstream-prs/PR-A-partition-file-contexts.md). |
| Open PR-C (hunk 7a: `append_seapp_contexts` extract). Sequenced after PR-A. | this repo | Branch `pr/extract-append-seapp-contexts`, see [`upstream-prs/PR-C-extract-append-seapp-contexts.md`](./upstream-prs/PR-C-extract-append-seapp-contexts.md). |
| Open PR-B (hunk 6 `patch.py` half: existence checks). Sequenced after PR-C. | this repo | Branch `pr/sepolicy-existence-check`, see [`upstream-prs/PR-B-sepolicy-existence-check.md`](./upstream-prs/PR-B-sepolicy-existence-check.md). |
| Drop hunks 1, 11, 12 from `master` on next rebase pass (formatter churn, GPLv3-wording revert, leaky log). | this repo | Mechanical; covered by [`upstream-strategy.md`](./upstream-strategy.md) § "What does not live in master". |
| Track PR outcomes and update this document. | this repo | Edit the table marking U rows landed/declined. |
| Ratify this disposition (or amend it). | PixeneOS | Ticket [`META-3`](https://github.com/0cwa/PixeneOS/blob/main/docs/tickets/META-3.md). |
| Design discussion for `--compatible-sepolicy` flag splitting and CIL fallback. | both, deferred | Not opened until U-PRs above have landed or been declined. |
