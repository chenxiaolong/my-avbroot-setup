# PR-B — Tolerate missing precompiled sepolicy files

**Sequencing:** open after PR-A and PR-C.
**Source hunk:** disposition hunk 6 (`patch.py` half).
**Source commits in this fork:** `90946bc`, `8ebbc0b`.

## Draft PR description

> `patch.py` currently fails hard if `vendor_boot/sepolicy` or `vendor/etc/selinux/precompiled_sepolicy` is absent. Some ROMs (notably AOSP-based forks) ship one but not both, and there is no functional reason to require both when the missing file would simply not be patched.
>
> This PR wraps both lookups in `.exists()` and only adds present files to `selinux_policies`. When neither is present, downstream module sepolicy patching is skipped — the existing `for sepolicy in sepolicies` loop already handles an empty list correctly. No flag. No new code paths.

## Caveat — the module-side gating

The fork also gates the per-module `sepolicy.exists()` check inside `custota.py` and `msd.py` behind `compatible_sepolicy=True`. **For the upstream PR, drop the `compatible_sepolicy` gate**: an unconditional `if not sepolicy.exists(): continue` is strictly safer than the current behaviour and does not require the flag.

If upstream pushes back on the per-module change, narrow the PR to the `patch.py` half only and keep the module-side change fork-local.

## Cherry-pick recipe

```sh
git fetch upstream
git checkout -b pr/sepolicy-existence-check upstream/master
git cherry-pick 90946bc 8ebbc0b

# Remove `compatible_sepolicy` gating from the module-side checks so
# the existence check is unconditional. Easiest path: open the two
# files in `lib/modules/custota.py` and `lib/modules/msd.py`,
# replace `if compatible_sepolicy and not sepolicy.exists():` with
# `if not sepolicy.exists():`, then amend.
git commit --amend --all --no-edit

# Optional: squash.
git rebase -i upstream/master
```

## Acceptance checks before opening

- `git diff upstream/master..HEAD` does **not** introduce or reference `compatible_sepolicy`. If it does, the gating wasn't fully removed.
- The `argparse` surface is unchanged.
- Test against an OTA that provides only `vendor/etc/selinux/precompiled_sepolicy` (no `vendor_boot/sepolicy`) and confirm the run completes.

## If upstream declines

Restore `compatible_sepolicy` gating, move the change back into fork `master`, and update [`../upstream-disposition.md`](../upstream-disposition.md) hunk 6 from **U** to **F**.
