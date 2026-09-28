# Module preparation CLI

`module-tool.py` exposes the deterministic preparation stages used before OTA
mutation. It does not inject files into an OTA and does not execute archive
members or installer hooks.

Run it through the repository's Python environment:

```bash
python3 module-tool.py --help
```

## Network boundary

The checked-in artifact lock is the only input to normal artifact acquisition.
`artifacts fetch` contacts only the immutable HTTPS URLs and redirect origins
recorded in that lock. Catalog listing, lock verification, artifact
verification, archive inspection, and profile resolution are local-only.

Floating release metadata is reserved for:

```bash
python3 module-tool.py lock update <module>
```

Lock-update providers form a reviewed static registry; a module ID can never be
used as a Python import path. The only current provider is the fail-closed
F-Droid privileged-extension provider documented in
`docs/fdroid-lock-provider.md`. Normal build and verification commands never
fall back to a floating endpoint when a lock or cache object is missing or
invalid.

## Catalog

```bash
python3 module-tool.py catalog list
python3 module-tool.py catalog list --format json
```

This reads only `lib/modules/manifests/`, validates the complete catalog, and
prints modules in canonical ID order. JSON is canonical schema v2 even when a
checked-in manifest was deterministically migrated from schema v1. Listing
does not load an executable adapter or select a module.

## Artifact locks

Validate both the strict lock schema and its canonical JSON serialization:

```bash
python3 module-tool.py lock verify --lock locks/artifacts.lock.json
```

On success, the command prints the canonical lock JSON. It does not contact the
network or verify cache objects; those are separate stages. A lock pins each
artifact's immutable URL, permitted redirect origins, version, exact byte size,
SHA-256, role, and any APK or archive identity policy. Artifact roles are
`injection-input`, `corresponding-source`, and `verification-evidence`;
`injection-input` remains the default so existing schema-v1 lock producers keep
loading deterministically.

An archive allowlisted member can include its own nested `apk` identity, using
the same exact package name, versionCode, and signer fields as a top-level APK.
This lets a reviewed provider lock an APK inside an OTA container without
treating the container's signature as the APK's identity.

Artifacts may also carry two independent records:

- `source` pins the HTTPS source URL and revision. Its optional
  `corresponding_source_artifact` names another artifact in the same module.
- `legal` records the SPDX/`LicenseRef`, whether corresponding-source delivery
  is required, and allowed output scopes.

A source-required binary must link to an artifact whose role is exactly
`corresponding-source`; the linked artifact must exist in the same module and
its locked version must equal the declared source revision. Missing, self,
wrong-role, and wrong-revision links fail closed. This supports an Apache-2.0
FPE binary with pinned upstream source metadata and a GPL client whose exact
corresponding-source archive travels as a separately verified lock artifact.

The F-Droid provider requires `--output`, `--client-version-code`, and
`--fpe-ota-version-code`. The older repeatable `--version-code` parser surface
remains available for future providers but is deliberately rejected for
F-Droid because its two roles must not be inferred from argument order.

## Fetch and verify

Populate a content-addressed cache from locked immutable URLs:

```bash
python3 module-tool.py artifacts fetch \
    --lock locks/artifacts.lock.json \
    --cache .artifact-cache
```

Limit either operation to one or more lock modules with repeated `--module`:

```bash
python3 module-tool.py artifacts verify \
    --lock locks/artifacts.lock.json \
    --cache .artifact-cache \
    --module example-module
```

Fetches use bounded temporary files, enforce the locked size while streaming,
verify SHA-256 before placement, fsync, atomically rename, and then reverify the
cache object. An existing cache object is always reverified and is never
silently replaced after a mismatch.

Verification is local-only. It rechecks size and SHA-256, applies the locked
hostile-archive policy, and verifies locked APK package name, versionCode, and
single signer with `apksigner` and `apkanalyzer`. Missing verification tools are
a hard failure. Both commands print a JSON array of content-addressed paths in
canonical lock order.

## Safe archive inspection

Inspect a ZIP-compatible container without extracting or executing it:

```bash
python3 module-tool.py artifacts inspect artifact.zip \
    --allow path/to/required-member \
    --allow another/required-member
```

Every `--allow` name must exist exactly once. Inspection validates every member,
streams file contents to force CRC and truncation checks, and prints sizes,
CRC-32 values, and SHA-256 digests as JSON. It never calls `extractall` or any
installer entry point. The defaults can be reduced with:

- `--max-members`
- `--max-member-size`
- `--max-total-size`
- `--max-expansion-ratio`
- `--max-streamed-bytes`

The inspector rejects absolute or drive-prefixed paths, backslashes, control
characters, unsafe components, duplicate raw or normalized names, non-regular
types, encrypted members, unsupported compression, unsafe physical layout,
excess limits, failed CRCs, truncation, and missing allowlisted members.

## Profile resolution

Resolve an explicit local profile against catalog compatibility and policy:

```bash
python3 module-tool.py resolve \
    --profile profiles/lineage.toml \
    --lock locks/artifacts.lock.json \
    --format json
```

Resolution validates dependencies, conflicts, ROM status, root mode, ABI/API,
declared providers and capabilities, legal output scope, lock-bound critical
acknowledgements, and affirmative consent for every globally experimental
selection. Unknown or ambiguous data fails closed. Output includes the
selected modules, structured decisions and warnings, output scope, and a stable
fingerprint. Resolution does not fetch artifacts or mutate an OTA.

Experimental consent is a per-module structured profile entry; there is no
global `allow_experimental` switch and no consent default. It binds the module
ID, the SHA-256 of the actual canonical lock bytes, the selected output scope,
and the catalog's exact acknowledgement text:

```toml
[[experimental_acknowledgements]]
module = 'example-experimental-module'
lock_sha256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
output_scope = 'local-unpublished'
acknowledgement = 'I accept that this module has not passed supported-status gates.'
```

Changing the lock, scope, or catalog text makes the entry stale. Entries for
unselected or non-experimental modules are rejected. An experimental module
without an `experimental_opt_in` catalog policy cannot be selected. Critical
warnings continue to use the independent `[[acknowledgements]]` entries, so a
module that is both experimental and critical must satisfy both policies.

The resolver consumes the lock digest returned by the canonical lock loader.
That digest covers the actual accepted input bytes, including the supported
pre-extension schema-v1 canonical representation; it is intentionally not
recomputed from the in-memory model's current serialization.

## Failure behavior

Input, policy, cache, archive, and resolution failures exit with status 2 and a
concise diagnostic. The CLI does not reinterpret an unavailable local input as
permission to contact a different endpoint.
