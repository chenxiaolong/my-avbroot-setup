# SELinux File Contexts Fix for --compatible-sepolicy Mode

## Problem
When using the `--compatible-sepolicy` flag, SELinux policies may not be granted correctly due to incorrect file labeling in vendor/odm partitions.

## Root Cause
Android uses partition-specific `file_contexts` files to map file paths to SELinux labels:
- `/system/etc/selinux/plat_file_contexts` - patterns for `/system` paths
- `/vendor/etc/selinux/vendor_file_contexts` - patterns for `/vendor` paths  
- `/odm/etc/selinux/odm_file_contexts` - patterns for `/odm` paths
- etc.

Previously, the code loaded only `plat_file_contexts` and used it for ALL partitions, even vendor and odm. This works fine when only modifying /system (the default case), but causes issues in `--compatible-sepolicy` mode where vendor/odm partitions are also involved.

The problem is that `plat_file_contexts` only contains patterns for `/system` paths. If code ever tries to create a file in `/vendor` or `/odm` using `plat_file_contexts`, the path won't match any pattern and will cause an error (StopIteration in `filesystem.py:183`).

## Solution
When `--compatible-sepolicy` is enabled:
1. Load partition-specific `file_contexts` for each unpacked partition
2. Fall back to `plat_file_contexts` if a partition-specific file doesn't exist
3. This ensures files created in any partition get the correct SELinux labels

When `--compatible-sepolicy` is NOT enabled (default):
- Keep the existing behavior: use `plat_file_contexts` for all partitions
- This preserves the current working functionality

## Implementation Details
- Only applies when `--compatible-sepolicy` flag is set
- Loads `vendor_file_contexts` for vendor partition
- Loads `odm_file_contexts` for odm partition  
- Loads partition-specific contexts for system_ext and product if present
- Falls back gracefully to `plat_file_contexts` if partition-specific files are missing

## Current Impact
Currently, no modules create new files in vendor or odm partitions, so this fix is primarily for:
1. **Correctness**: Ensuring the right file_contexts are loaded
2. **Future-proofing**: Supporting future modules that might create files in these partitions
3. **Robustness**: Preventing crashes if code paths change

## Testing
The fix preserves existing behavior when `--compatible-sepolicy` is not used, so there should be no regression for the default use case.
