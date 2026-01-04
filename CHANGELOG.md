# Changelog: --compatible-sepolicy SELinux Context Merging

## Summary

Implemented seapp_contexts merging across partitions to fix functional failures with the `--compatible-sepolicy` flag. This ensures module apps receive consistent SELinux domains across all system partitions.

## Problem

When `--compatible-sepolicy` was enabled:
- ✓ Modules no longer crashed
- ✗ Module functionality still failed due to SELinux permission denials

Root cause: Module seapp_contexts were only added to `plat_seapp_contexts`, but vendor/odm partitions had their own seapp_contexts files that could override or conflict with the platform contexts.

## Solution

Implemented automatic seapp_contexts merging:
1. Created centralized `append_seapp_contexts()` helper function
2. In compatible mode, append module contexts to ALL partition seapp_contexts files
3. Gracefully handle missing vendor/odm seapp_contexts files

## Technical Details

### Files Modified

1. **`lib/modules/__init__.py`**
   - Added `append_seapp_contexts()` function
   - Handles merging contexts across plat/vendor/odm partitions
   - Includes proper logging and error handling

2. **`lib/modules/custota.py`**
   - Replaced manual seapp_contexts appending with helper function call
   - Now supports multi-partition context merging in compatible mode

3. **`lib/modules/msd.py`**
   - Same update as custota.py
   - Centralized logic for consistency

### Behavior Changes

#### Without --compatible-sepolicy (Default)
- **No change** - Only modifies `plat_seapp_contexts` as before
- Preserves existing working behavior

#### With --compatible-sepolicy (New)
- Modifies `plat_seapp_contexts` (always)
- **NEW**: Also modifies `vendor_seapp_contexts` (if exists)
- **NEW**: Also modifies `odm_seapp_contexts` (if exists)
- Logs all operations for debugging

### Code Example

```python
# Old approach (custota.py, msd.py):
seapp = 'system/etc/selinux/plat_seapp_contexts'
with (
    z.open('plat_seapp_contexts', 'r') as f_in,
    system_fs.open(seapp, 'ab') as f_out,
):
    shutil.copyfileobj(f_in, f_out)
    f_out.write(b'\n')

# New approach:
modules.append_seapp_contexts(z, 'plat_seapp_contexts', ext_fs, compatible_sepolicy)
```

## Expected Improvements

### Before (with --compatible-sepolicy)
- SELinux policy patches applied successfully
- But apps still denied permission due to wrong SELinux domain
- Module apps couldn't perform their functions

### After (with --compatible-sepolicy)
- SELinux policy patches applied
- App contexts consistent across all partitions  
- Apps receive correct SELinux domain
- Module functionality should work correctly

## Logging Output

Users will see additional log messages when using --compatible-sepolicy:

```
[INFO] Adding seapp contexts to: system/etc/selinux/plat_seapp_contexts
[INFO] Adding seapp contexts to: vendor/etc/selinux/vendor_seapp_contexts (compatible mode)
[INFO] Adding seapp contexts to: odm/etc/selinux/odm_seapp_contexts (compatible mode)
```

Or if files don't exist:
```
[INFO] Skipping vendor/etc/selinux/vendor_seapp_contexts: file does not exist
```

## Testing

To test the fix:

1. **Use --compatible-sepolicy flag:**
   ```bash
   python3 patch.py --compatible-sepolicy --module-custota ... --module-msd ...
   ```

2. **Check logs for context merging:**
   - Look for "Adding seapp contexts to vendor/odm" messages
   - Verify files are being patched

3. **Verify module functionality:**
   - Install patched OTA
   - Test Custota update functionality
   - Test MSD operations
   - Check for SELinux denials: `adb logcat | grep avc:`

## Backward Compatibility

✅ **Fully backward compatible**
- Default behavior unchanged (no --compatible-sepolicy flag)
- Only affects behavior when --compatible-sepolicy is explicitly enabled
- Gracefully handles ROMs without vendor/odm seapp_contexts files

## Future Work

If issues still occur with --compatible-sepolicy, consider:

1. **file_contexts merging**: Modify file_contexts files across partitions
2. **property_contexts**: Update property contexts if modules use system properties  
3. **service_contexts**: Update service contexts if needed
4. **Additional policy patching**: Patch system/system_ext/product policies

## References

- `IMPLEMENTATION.md` - Detailed implementation notes
- `COMPATIBLE_SEPOLICY_ANALYSIS.md` - Analysis of the issue
- `FINDINGS.md` - Investigation process and conclusions
