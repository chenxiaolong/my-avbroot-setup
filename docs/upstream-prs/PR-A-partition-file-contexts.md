# PR-A — Load partition-specific `*_file_contexts`

**Sequencing:** open first. Smallest, least-opinionated, no flag, no API change.
**Source hunk:** disposition hunk 5.
**Source commits in this fork:** `d964701`, `3e4cf51`, `65c5bea` (plus a cleanup of AI-planning-file additions).

## Draft PR description

> Currently, all ext partitions inherit only `system/etc/selinux/plat_file_contexts` for SELinux label lookup. New files written into the `vendor` or `odm` trees end up labeled by the platform table, which is wrong for any file path covered by a partition-specific entry.
>
> This PR loads `<partition>/etc/selinux/<partition>_file_contexts` when present and prepends it to the platform contexts so partition-specific entries take precedence. Falls back to platform-only when the partition file is absent. No new flags. Behavior is unchanged on Pixel-class GrapheneOS targets where the partition file is identical to platform; the change is observable on ROMs that ship distinct partition tables.

## Cherry-pick recipe

```sh
git fetch upstream
git checkout -b pr/partition-file-contexts upstream/master
git cherry-pick d964701 3e4cf51 65c5bea

# Drop the AI-generated planning files that were accidentally
# added in 65c5bea ("feat(selinux): load partition-specific
# file_contexts for --compatible-sepolicy"):
git rm --ignore-unmatch \
  COMPATIBLE_SEPOLICY_ANALYSIS.md \
  FINDINGS.md \
  SELINUX_FILE_CONTEXTS_FIX.md
git commit --amend --no-edit

# Optional: squash into a single commit for review.
git rebase -i upstream/master
```

## Acceptance checks before opening

- `git log` shows a single commit (or three small ones, if the maintainer prefers atomic history).
- `git diff upstream/master..HEAD --stat` shows changes only under `patch.py` (or `lib/`) — no `*_ANALYSIS.md` / `FINDINGS.md` / `*_FIX.md` files.
- The `--compatible-sepolicy` flag is **not** introduced in this branch. If your `git diff` mentions `compatible_sepolicy`, drop those edits before pushing.
- Test against at least one Pixel target (Tensor or earlier) and one Lineage target to confirm partition tables are correctly merged.

## If upstream declines

Move the change back into fork `master` (it is already there as part of the cumulative delta). Update [`../upstream-disposition.md`](../upstream-disposition.md) hunk 5 from **U** to **F** with the maintainer's stated reason.
