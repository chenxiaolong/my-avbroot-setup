# Findings: file_contexts Change Does NOT Fix --compatible-sepolicy Issue

## Summary
After analysis, I've determined that loading partition-specific file_contexts does **NOT** fix the functional failures you described with --compatible-sepolicy. I've reverted this change.

## Why It Doesn't Help

### What the Change Did:
- Loaded partition-specific file_contexts (vendor_file_contexts, odm_file_contexts) into Python memory
- Used them for labeling NEW files created by ExtFs operations

### Why It's Ineffective:
1. **All modules create files in /system only** - no files created in vendor/odm
2. **Doesn't modify OTA files** - only loads contexts into memory, doesn't change actual file_contexts files in the OTA
3. **System files already use plat_file_contexts** - which is correct for /system paths

## The Likely Real Issue

Based on Android SELinux architecture, the problem is probably **inconsistent seapp_contexts across partitions**.

### Current Behavior:
- Modules append their seapp_contexts to `/system/etc/selinux/plat_seapp_contexts`  
- But `/vendor/etc/selinux/vendor_seapp_contexts` and `/odm/etc/selinux/odm_seapp_contexts` are **NOT modified**

### Why This Causes Failures:
At boot, Android merges all seapp_contexts files from all partitions. If:
- vendor/odm seapp_contexts have conflicting entries, OR
- vendor/odm seapp_contexts override plat entries

Then module apps may not get the correct SELinux domain, causing permission denials even though policies are patched.

## Recommended Fix

Implement seapp_contexts merging for --compatible-sepolicy mode:

```python
# In modules that patch seapp_contexts (custota.py, msd.py):
if compatible_sepolicy:
    # Also append to vendor/odm seapp_contexts if they exist
    for partition in ['vendor', 'odm']:
        if partition in ext_fs:
            seapp_file = f'{partition}/etc/selinux/{partition}_seapp_contexts'
            seapp_path = Path(seapp_file)
            if ext_fs[partition].tree.joinpath(*seapp_path.parts[1:]).exists():
                # Append module's seapp_contexts to this file too
                ...
```

This ensures module app contexts are recognized consistently across all partitions.

## Alternative Possibilities

1. **file_contexts merging**: Actually modify file_contexts files in OTA (not just load them)
2. **Additional policy patching**: Patch system/system_ext/product policies too
3. **Over-patching issue**: Maybe patching odm conflicts with vendor?

## Next Steps

1. Check if typical ROMs have vendor_seapp_contexts and odm_seapp_contexts files
2. Implement seapp_contexts merging for --compatible-sepolicy
3. Test if this fixes module functionality
4. If not, gather SELinux denial logs to understand what's actually being blocked
