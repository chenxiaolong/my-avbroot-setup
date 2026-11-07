# PR-C — Extract `append_seapp_contexts` helper

**Sequencing:** open after PR-A.
**Source hunk:** disposition hunk 7a (the refactor only — *not* 7b, the multi-partition compatible-mode append).
**Source commits in this fork:** none discrete; the refactor is mixed into `91e49bc`. Must be hand-extracted.

## Draft PR description

> `custota.py` and `msd.py` carry an identical 7-line block that opens `plat_seapp_contexts` from the module zip and appends it to `system/etc/selinux/plat_seapp_contexts` with a trailing newline. This PR hoists that block to `lib/modules/__init__.py` as `append_seapp_contexts(zip, seapp_contexts_name, ext_fs)` and replaces both call sites. Net negative line count, no behavior change.

## What this PR does **not** include

- The `compatible_sepolicy` parameter on the helper.
- The vendor/odm partition fall-throughs (these are part of the fork-only `--compatible-sepolicy` behaviour, hunk 7b).

The helper signature for upstream should be exactly:

```python
def append_seapp_contexts(
    zip: zipfile.ZipFile,
    seapp_contexts_name: str,
    ext_fs: dict[str, ExtFs],
) -> None:
```

— i.e., always-and-only `system/etc/selinux/plat_seapp_contexts`, identical to the inlined behaviour today.

## Recipe (hand extraction, no cherry-pick)

```sh
git fetch upstream
git checkout -b pr/extract-append-seapp-contexts upstream/master

# 1. In lib/modules/__init__.py, add the helper:
#
#    def append_seapp_contexts(zip, seapp_contexts_name, ext_fs):
#        system_fs = ext_fs["system"]
#        seapp = "system/etc/selinux/plat_seapp_contexts"
#        logger.info(f"Adding seapp contexts to: {seapp}")
#        with (
#            zip.open(seapp_contexts_name, "r") as f_in,
#            system_fs.open(seapp, "ab") as f_out,
#        ):
#            shutil.copyfileobj(f_in, f_out)
#            f_out.write(b"\n")
#
# 2. In lib/modules/custota.py, replace the inlined plat_seapp_contexts
#    append block with:
#        modules.append_seapp_contexts(z, "plat_seapp_contexts", ext_fs)
#
# 3. Same for lib/modules/msd.py (the block is identical).
#
# 4. Match upstream's quote style (single quotes) and indentation.
git add -p
git commit -m "lib/modules: extract append_seapp_contexts helper

custota.py and msd.py carried identical seapp_contexts append blocks.
Hoist them to lib/modules/__init__.py as a small helper. No behavior
change."
```

## Acceptance checks before opening

- `git diff upstream/master..HEAD --stat` shows a small net-negative line count.
- The diff touches only `lib/modules/__init__.py`, `lib/modules/custota.py`, `lib/modules/msd.py`.
- Quote style matches upstream (single quotes).
- No new arguments on the helper besides `zip`, `seapp_contexts_name`, `ext_fs`.

## If upstream declines

Unlikely — pure refactor, net-negative LOC, no behaviour change. If declined, mark hunk 7a as **F** in [`../upstream-disposition.md`](../upstream-disposition.md) and keep the inlined version on fork `master`.
