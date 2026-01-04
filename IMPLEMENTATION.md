# Implementation: seapp_contexts Merging for --compatible-sepolicy

## What Was Implemented

Added seapp_contexts merging across partitions to fix functional issues with `--compatible-sepolicy` mode.

## Changes Made

### 1. New Helper Function (`lib/modules/__init__.py`)

Added `append_seapp_contexts()` function that:
- Always appends module seapp_contexts to `/system/etc/selinux/plat_seapp_contexts`
- When `compatible_sepolicy=True`, also appends to:
  - `/vendor/etc/selinux/vendor_seapp_contexts` (if exists)
  - `/odm/etc/selinux/odm_seapp_contexts` (if exists)
- Logs which files are being modified
- Gracefully skips partitions that don't have seapp_contexts files

### 2. Updated Custota Module (`lib/modules/custota.py`)

Replaced manual seapp_contexts appending with call to helper function:
```python
# Before:
with (
    z.open('plat_seapp_contexts', 'r') as f_in,
    system_fs.open(seapp, 'ab') as f_out,
):
    shutil.copyfileobj(f_in, f_out)
    f_out.write(b'\n')

# After:
modules.append_seapp_contexts(z, 'plat_seapp_contexts', ext_fs, compatible_sepolicy)
```

### 3. Updated MSD Module (`lib/modules/msd.py`)

Same change as Custota - now uses the centralized helper function.

## Why This Fixes the Issue

### Problem
In modern Android with Treble architecture:
- SELinux contexts files are split across partitions (system, vendor, odm)
- All seapp_contexts files are **merged at boot time**
- If contexts are inconsistent across partitions, apps may not get correct SELinux domains

### Previous Behavior
- Modules only modified `/system/etc/selinux/plat_seapp_contexts`
- Vendor and ODM partitions had their own seapp_contexts files
- At boot, vendor/odm contexts could override or conflict with plat contexts
- Result: Apps assigned wrong SELinux domain → permission denials

### New Behavior (with --compatible-sepolicy)
- Module contexts are added to ALL partition seapp_contexts files
- Ensures consistent app labeling across the entire system
- All partitions agree on what SELinux domain the app should run in
- Result: Apps get correct permissions

## Behavior

### Default Mode (no --compatible-sepolicy)
- Only modifies `plat_seapp_contexts` (preserves existing working behavior)
- Suitable for ROMs with standard partition layouts

### Compatible Mode (--compatible-sepolicy)
- Modifies `plat_seapp_contexts`, `vendor_seapp_contexts`, `odm_seapp_contexts`
- Ensures compatibility with ROMs that have custom vendor/odm configurations
- Gracefully handles missing files (not all ROMs have vendor_seapp_contexts)

## Testing Recommendations

1. **Test on ROM with standard layout:**
   - Verify modules work without --compatible-sepolicy (regression test)

2. **Test on ROM with custom vendor/odm:**
   - Use --compatible-sepolicy flag
   - Verify modules now function correctly
   - Check logs for "Adding seapp contexts to: vendor/..." messages

3. **Check for SELinux denials:**
   - Before: `adb logcat | grep avc:` should show denials
   - After: No denials related to module apps

## Logging

The implementation provides detailed logging:
- `Adding seapp contexts to: system/etc/selinux/plat_seapp_contexts` (always)
- `Adding seapp contexts to: vendor/etc/selinux/vendor_seapp_contexts (compatible mode)` (if exists)
- `Adding seapp contexts to: odm/etc/selinux/odm_seapp_contexts (compatible mode)` (if exists)
- `Skipping vendor/etc/selinux/vendor_seapp_contexts: file does not exist` (if missing)

## Future Enhancements

If seapp_contexts merging doesn't fully resolve the issue, consider:
1. **file_contexts merging**: Modify file_contexts files across partitions
2. **property_contexts patching**: Update property contexts if modules use system properties
3. **Additional policy patching**: Patch system/system_ext/product policies too

## Related Files

- `lib/modules/__init__.py` - Helper function implementation
- `lib/modules/custota.py` - Custota module update
- `lib/modules/msd.py` - MSD module update
- `COMPATIBLE_SEPOLICY_ANALYSIS.md` - Detailed analysis of the issue
- `FINDINGS.md` - Why file_contexts approach didn't work
