# Analysis: --compatible-sepolicy Functional Issues

## Problem Statement
With `--compatible-sepolicy` flag:
- ✓ Modules that require SELinux patching no longer crash
- ✗ Modules still fail to perform their intended functions

## What --compatible-sepolicy Currently Does

### 1. SELinux Policies Patched:
- `vendor_boot/sepolicy`
- `vendor/etc/selinux/precompiled_sepolicy`  
- `odm/etc/selinux/precompiled_sepolicy` (when flag is set)

### 2. SELinux Contexts Modified:
- `system/etc/selinux/plat_seapp_contexts` (appended by modules)

### 3. Partitions Unpacked:
- system (always)
- vendor (when SELinux patching needed)
- odm (only with --compatible-sepolicy flag)

## Why Modules Still Fail

The issue is likely **incomplete SELinux configuration patching across partitions**.

### Android SELinux Architecture
In modern Android (Treble and later):
- SELinux policies are split across partitions:
  - Platform policy in /system
  - Vendor policy in /vendor  
  - ODM policy in /odm
- **All policies are MERGED at boot time**
- **All contexts files are MERGED at boot time**

### Current Gap
We're patching binary policies in vendor/odm, but NOT updating all associated context files:

#### file_contexts Files (per partition):
- `/system/etc/selinux/plat_file_contexts` ← not modified
- `/vendor/etc/selinux/vendor_file_contexts` ← not modified
- `/odm/etc/selinux/odm_file_contexts` ← not modified

Currently: Loaded into Python memory only, not modified in OTA

#### seapp_contexts Files (per partition):
- `/system/etc/selinux/plat_seapp_contexts` ← modules append to this
- `/vendor/etc/selinux/vendor_seapp_contexts` ← **NOT MODIFIED**
- `/odm/etc/selinux/odm_seapp_contexts` ← **NOT MODIFIED**

**This is probably the issue!** At boot, Android merges all seapp_contexts files. If vendor/odm contexts conflict with or override plat contexts, the module apps may not get the correct SELinux domain.

## Potential Solutions to Investigate

### Option 1: Merge seapp_contexts Across Partitions (Most Likely Fix)
When --compatible-sepolicy is enabled, also append module contexts to:
- `vendor/etc/selinux/vendor_seapp_contexts` (if exists)
- `odm/etc/selinux/odm_seapp_contexts` (if exists)

This ensures consistent app labeling across all partitions.

### Option 2: Patch All Policy Files
Currently only patching precompiled binary policies. May need to also patch:
- System partition policies
- CIL source files (if ROM rebuilds policies at boot)

### Option 3: Merge file_contexts Files
Actually modify (not just load) file_contexts files in OTA to ensure consistent file labeling.

### Option 4: Over-patching Issue  
Maybe we're patching too much? Perhaps odm policies conflict with vendor policies?

## Questions to Answer

1. **What specific operations fail?** Need SELinux denial logs
2. **Are there "avc: denied" messages?** Check logcat/dmesg
3. **Which contexts are involved?** Source/target domains/types
4. **Do vendor/odm have their own seapp_contexts?** Check if files exist
5. **Are there conflicting contexts?** Check if vendor/odm override plat

## Recommendation

The most likely issue is **Option 1**: seapp_contexts inconsistency.

We should implement:
```python
if args.compatible_sepolicy:
    # Append module seapp_contexts to vendor/odm files too
    for partition in ['vendor', 'odm']:
        if partition in ext_fs:
            seapp_path = f'{partition}/etc/selinux/{partition}_seapp_contexts'
            # Check if file exists and append module contexts
```

This would ensure modules' app contexts are recognized across all partitions.

## Testing Approach

1. Check if vendor/odm_seapp_contexts files exist in typical ROMs
2. Implement seapp_contexts merging for --compatible-sepolicy
3. Test if module functionality works after this change
4. If not, check SELinux denials and iterate

## Conclusion

The file_contexts loading change does NOT fix the issue because:
- It only loads contexts into Python memory
- Doesn't modify actual OTA files
- All module files go to /system anyway

The real issue is likely **missing seapp_contexts updates in vendor/odm partitions**.
