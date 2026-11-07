# Module catalog

`lib/modules/manifests/` is the declarative, data-only catalog for patches
understood by this repository. Manifests are loaded in canonical module-ID
order. An adapter is an opaque identifier resolved through the static internal
registry; it is never a Python import path supplied by a manifest.

List the catalog without loading patch adapters:

```bash
python3 -m lib.modules.catalog
python3 -m lib.modules.catalog --format json
```

Catalog JSON is always emitted in canonical schema v2 form. This catalog does
not fetch, inspect, install, or execute artifacts. In particular, it does not
run `customize.sh`, `update-binary`, `service.sh`, `post-fs-data.sh`, KernelSU
scripts, or recovery installer hooks.

## Schema v2

Every v2 manifest records these independent decisions:

- `lifecycle`: `static-image`, `custom-init`, `root-runtime`,
  `first-boot-provisioned`, `external-reference`, or `user-direct-install`.
- `defaults.helper_enabled` and `defaults.pixene_profile_enabled`: two explicit
  defaults with no implicit inheritance between them.
- `verification.trust_roots`: typed identities. Valid types are
  `x509-cert-sha256`, `apk-signer-sha256`, `openpgp-primary`,
  `openpgp-subkey`, `ssh-key-sha256`, and `github-attestation`. OpenPGP
  verification requires both the pinned primary-key fingerprint and the pinned
  signing-subkey fingerprint.
- `capabilities.requires` and `capabilities.provides`: root and Zygisk
  providers, selective signature spoofing, product privileged-app support,
  custom init/SELinux support, ABI constraints, and minimum/maximum API level.
- `compatibility.roms`: a per-ROM `supported`, `experimental`, or
  `incompatible` status. Experimental and incompatible entries require a
  structured reason.
- `legal`: SPDX/`LicenseRef` identity, source URL and source-offer requirement,
  upstream-only fetch policy, local-only policy, cache policy, output scopes,
  and a permission record. Shared or published scope requires a permission
  record. Local-only entries can only use `local-unpublished` scope.
- structured `dependencies`, `conflicts`, `warnings`, and `reasons`. A
  `critical` warning requires `acknowledgement_required = true`.
- `experimental_opt_in`: explicit catalog consent text for a globally
  experimental module that has a reviewed adapter. Its `required` field must
  be true. The module must remain disabled in both default namespaces. A later
  profile/resolver interface must record affirmative consent to this text;
  merely loading the catalog does not grant it.

The capability and policy fields are declarations for a later resolver. Merely
loading a manifest does not prove the target ROM supplies a capability or grant
permission to publish an artifact.

The following is a complete abbreviated v2 example:

```toml
schema_version = 2
id = 'example-module'
name = 'Example module'
status = 'supported'
adapter = 'example-module'
lifecycle = 'static-image'
acknowledgement_required = false
artifact_kinds = ['apk']
dependencies = []
conflicts = []
warnings = []
reasons = []

[defaults]
helper_enabled = false
pixene_profile_enabled = false

[verification]
schemes = ['sha256', 'apk-signature']
digest_required = true
enforced_by = 'adapter'

[[verification.trust_roots]]
type = 'apk-signer-sha256'
value = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

[compatibility]
root_modes = ['rootless']
architectures = ['arm64-v8a']

[compatibility.roms.lineageos]
status = 'supported'

[compatibility.roms.grapheneos]
status = 'experimental'
reason = { code = 'device-testing-pending', message = 'Device testing is incomplete.' }

[capabilities.requires]
selective_signature_spoofing = false
product_priv_app = true
custom_init_selinux = false
abis = ['arm64-v8a']
min_api = 34
max_api = 36

[capabilities.provides]
root = []
zygisk = []
selective_signature_spoofing = false
product_priv_app = false
custom_init_selinux = false

[legal]
license = 'Apache-2.0'
source_url = 'https://example.invalid/upstream'
source_offer_required = false
upstream_only_fetching = true
local_only = true
cache_policy = 'read-write'
allowed_output_scopes = ['local-unpublished']
```

A globally experimental module may retain a reviewed injection adapter while
device acceptance work is incomplete. Such a manifest adds this block and
keeps both defaults false:

```toml
[experimental_opt_in]
required = true
acknowledgement = 'I accept that this module has not passed supported-status gates.'
```

The block is invalid on globally supported or incompatible modules. It is
optional for descriptive experimental entries that have no adapter. Resolution
nevertheless fails closed for every selected globally experimental module that
lacks this policy. Selection requires a per-module
`[[experimental_acknowledgements]]` profile entry bound to the actual canonical
lock SHA-256, output scope, and this exact acknowledgement text. There is no
global experimental switch or default consent. Critical-warning
`[[acknowledgements]]` remain independent; a module governed by both policies
must provide both entries.

Omit `root_provider` or `zygisk_provider` when a module does not require one;
use `any` when any recognized provider is acceptable. Concrete recognized root
providers are `magisk`, `kernelsu`, and `apatch`; Zygisk providers additionally
include `zygisk-next`. Use `unknown` alone for legacy ABI, architecture, ROM, or
root-mode evidence that has not been established, and `any` alone only when
there is evidence no restriction applies.

## Schema v1 migration

Schema v1 remains valid input. The loader first applies the original strict v1
validation and then deterministically migrates it to v2:

- `planned` becomes `experimental` with a structured migration reason when v1
  supplied none.
- `default_enabled` becomes `defaults.helper_enabled`.
  `defaults.pixene_profile_enabled` is always false because v1 never expressed
  a Pixene profile default.
- legacy signer strings become typed SSH or APK signer roots according to the
  declared verification scheme.
- legacy ROM `unknown` on a supported module becomes experimental with a
  structured reason; explicit incompatibility and explicit ROM families retain
  the module's migrated status.
- absent capability claims remain false/empty and legacy architectures become
  the ABI constraint.
- absent legal evidence becomes `LicenseRef-Legacy-Unspecified` with
  local-unpublished-only output. Migration never creates redistribution
  permission from missing metadata.

The checked-in legacy adapters continue to be checked against their static
verification registrations after migration. The existing
`--module-<name>`/`--module-<name>-sig` options, option order, destinations, and
patch behavior are unchanged.

## Adapter safety rules

Supported executable lifecycles require a reviewed internal adapter. A globally
experimental module may register one only when `experimental_opt_in` is present
and both helper and Pixene profile defaults are false. Incompatible modules
cannot register an adapter. `external-reference` and `user-direct-install`
entries never register an injection adapter. Every registered adapter,
including an experimental one, must exist in the static trusted registry and
its verification schemes, trust-root values, and digest requirement must match
that registration exactly.

Dependencies and conflicts must reference known module IDs, cannot contain the
module itself, and cannot overlap. This permits explicit mutually exclusive
profiles such as GApps versus MicroG without encoding ROM-specific branches in
adapter functions.
