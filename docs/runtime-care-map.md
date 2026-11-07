# Strict runtime care-map postflight

The `--runtime-care-map` option selects strict runtime care-map verification.
`--allow-source-care-map-mismatch` remains an equivalent compatibility alias. It no longer tolerates a verifier error in the
production patch path. This development interface requires avbroot's
`--expected-care-map` and `--verification-report` implementation; older
avbroot binaries fail before patching. Both independent source trust anchors
remain mandatory in this mode.

The signed source map is checked against the required authenticated partition
set, protected data extents and deterministic payload writes. Each partition
is freshly extracted and its size and SHA-256 must match the successful
cryptographic verifier's report before afsr reads its ext4 build property directly from that exact image.
The ext4 reader uses filesystem geometry and accepts the authenticated AVB
suffix; it does not reverify or repair a second AVB unpack copy.
The canonical Android property paths are `/system/build.prop` for system,
`/build.prop` for vendor and `/etc/build.prop` for the other partitions.
Unsupported filesystems and missing or duplicate properties fail closed.
Property extraction scratch trees are removed after each read, including
failures, and verified partition images are released before the next output.
Only the small successful verifier reports remain for evidence.

Final runtime-mode outputs must enable AVB verification in every verified
header. Authentic source header flags are recorded without relaxing final
output policy.

Unmodified partitions preserve authenticated sparse ranges. Replaced ext4
partitions receive the complete final AVB-protected data extent; avbroot must
prove that the final signed payload deterministically writes every cared
block. The implicit system OTA-certificate patch also receives full protected
data ranges, using its authenticated unchanged data extent; runtime-mode
avbroot recompresses that modified image completely. New microG allocations can therefore extend outside the original
sparse care ranges. Runtime identities must remain unchanged.

Each final output is independently verified with the configured OTA
certificate and the AVB public identity derived from the configured signing
key. Runtime-map mode repeats image hash binding and filesystem property
checks on each output. All outputs pass before Custota assets or the locked
module success report are created, including ordinary mode's signature and
AVB postflight. A secondary failure leaves no new success assets.

These checks establish signed artifact consistency. They do not establish
actual device property loading, enabled verity, slot acceptance, snapuserd
behavior, microG functionality or OTA persistence. Dependency promotion and
publication remain separate from this local development implementation.
