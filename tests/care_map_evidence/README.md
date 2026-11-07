# pdx235 2026-10-09 care-map conformance (Worklane 3)

**Status: TEST-ONLY / NONPUBLISHING / NOT AN OTA APPROVAL.**
Base: `0cwa/my-avbroot-setup@70819893ff91488b4b40a8c6f45fde39854c6c68`.
Blocker: [ModOS #114](https://github.com/0cwa/ModOS/issues/114).
No production implementation, policy digest, signing keys, permanent workflows, output OTAs, or release controls are changed.

## Witness and provenance

- `tests/fixtures/pdx235_20261009.care_map.pb`: **1,086 bytes** of reconstructed original `care_map.pb`. SHA-256 `e903a2c0e4a71aaadf757d7d479a6be2ca80939a084c1832796db61c75e6e147` matches the **independently authenticated** original signed ZIP's logged member hash *exactly*. Unlike a hand-typed example, this is byte-for-byte equivalent to that member. Protobuf wire layout/order and all six entries are checked by tests.
- `tests/fixtures/pdx235_20261009.json`: size/digest pins, exact six source ranges, six `ro.<name>.build.fingerprint` IDs, both actual fingerprint values, avbroot v3.34.1's logged contiguous ranges, and six payload image SHA-256 values. The signed OTA itself, target files, partition filesystems, certs, or keys are **not** bundled.
- Original OTA: `lineage-23.2-20261009-nightly-pdx235-signed.zip`, SHA-256 `b2b4269738df1d3092de49bde6c7d0ffcb62ae19b342213a819187c30b7ab1f8`; 1,232,106,897 bytes. Independently checked official LineageOS release API + publisher signature: [forensic CI 38180526270](https://github.com/0cwa/ModOS/actions/runs/38180526270).
- Historical mismatch: [ModOS CI 38003576753, job 114067106505](https://github.com/0cwa/ModOS/actions/runs/38003576753), original/expected care-map printout. Original signed partition filesystem `ro.<partition>.build.fingerprint` was independently inspected with `debugfs` and is the **Sony Android 15 string**, while the very same signed images' AVB descriptors contain **LineageOS Android 16 string**: [forensic CI 38181164127](https://github.com/0cwa/ModOS/actions/runs/38181164127). The source map matches original filesystem properties on all six partitions.
- Exact AOSP code: [LineageOS build releasetools at `e5aaa621`](https://github.com/LineageOS/android_build/blob/e5aaa62172df0f321e68133fa30f42316376bfe8/tools/releasetools/add_img_to_target_files.py), `GetCareMap` and `AddCareMapForAbOta`; companion `sparse_img.py` handles RAW/FILL/DONT_CARE. Runtime semantics: [LineageOS recovery at `acd99f7c`](https://github.com/LineageOS/android_bootable_recovery/blob/acd99f7c48e0229eaedd40aa3e2adcbabe2dc283/update_verifier/update_verifier.cpp). Legacy reconstruction: [avbroot v3.34.1 `care_map.rs`](https://github.com/chenxiaolong/avbroot/blob/v3.34.1/avbroot/src/format/care_map.rs).

**Provenance boundary:** The synthetic sparse-chunk lists in the reference oracle are built *from the already authenticated, witnessed ranges*. They exercise the AOSP range algorithm but are **not** independently recovered sparse chunk headers from signed filesystem images. Offline reference tests reproduce the **logged avbroot 3.34.1 comparison**, not an actual avbroot executable run. An optional full-OTA nonpublishing harness is separate. A mismatch between those two metadata generation paths **does not imply corrupt source bytes**.

## Coverage matrix

| Condition | Independent reference | Real helper guard with synthetic ZIP (external AVB verification mocked) | Expected |
|---|---|---|---|
| Byte-exact six-entry historical map/hash | Yes | Yes | PASS |
| Original Sony runtime IDs / original fingerprint | Yes | Yes | PASS |
| avbroot v3.34.1 contiguous ranges + AVB fingerprints | Yes | Yes | **FAIL** identity equality, by design |
| Valid RAW+FILL blocks / DONT_CARE holes / AVB filesystem cutoff | Yes | N/A | PASS |
| Non-sparse contiguous ranges; sorting, canonicalization, adjacency | Yes | N/A | PASS |
| Overlap, reversed/zero-length, unaligned, missing chunks, out-of-bounds | Yes | Syntactic checks only | **FAIL** malformed/out-of-bounds |
| Wrong count, noncanonical decimal, truncated/unknown protobuf | Yes | Selected malformed output tests | **FAIL** |
| Missing/removed/duplicate partitions or protobuf fields | Yes | Yes | **FAIL** |
| Wrong property ID / fingerprint substitution | Yes | Yes | **FAIL** |
| Missing, empty, or duplicate ZIP `care_map.pb` | Parser/reference; existing baseline tests | Yes | **FAIL** |
| Rootless output fingerprint preserved | Yes | Yes | PASS after mock strict verification |
| Rootless safe, Magisk secondary identity unsafe | Yes | Yes, real guard | **FAIL** whole operation |
| Both outputs verified against configured expected AVB key + OTA cert | N/A | Yes, command arguments asserted, verifier mocked | PASS wiring only |
| Rebuilt ext4 property agrees with rebuilt care-map identity | Simulated mismatch demonstrates guard gap | **Not inspected by helper** | **BLOCK** until independent inspection |
| Correct ranges within *rebuilt* AVB-original image bounds | Yes, reference | **Not inspected by identity guard** | **BLOCK** until candidate + real output verification |
| Actual v3.34.1 executable on full authenticated source | Optional evidence harness | No | **NOT RUN in offline CI** |
| Worklane 1 corrected care-map generator | Opt-in candidate contract | No | **NOT INTEGRATED yet** |
| Physical first-boot/update_verifier and OTA persistence | No | No | **REQUIRES DEVICE TEST** |

**Existing helper guard gaps (demonstrated, not waived):**

1. `lib/care_map_compat.py` compares source and output `care_map.pb` partition IDs and fingerprints; it does **not** extract/read output partition ext4 `ro.<partition>.build.fingerprint`. Keeping an unchanged map while changing output filesystem properties passes this guard. The test simulates this deliberately; it does not pretend to inspect ext4.
2. Its range check is syntactic and sorted, bounded by `2^63`, **not** by the actual signed output filesystem/verity original-image size or AOSP meaningful sparse blocks. A well-formed but out-of-filesystem range passes this **identity-only** guard. The mandatory separate strict output avbroot verifier may reject such a range; our mocked verifier cannot establish that.
3. The guard is called **only when the caller reports that the source care-map exception actually fired**. It is not a general proof of first-boot runtime safety for every OTA, and says nothing about dm-verity state, snapuserd behavior, or physical boot.
4. The guard intentionally requires identities equal to the original authenticated source. A **legitimate output property change** needs matching output care-map plus independently verified property extraction and an explicitly reviewed policy; merely changing to the AVB fingerprint is unsafe. Exact source equality is necessary for this specific unchanged-property case, but not sufficient in general.
5. A successfully checked *first* rootless output is not authorization to finish a pair. Real helper wiring must reject an unsafe second Magisk output before returning or producing release artefacts. Existing baseline tests additionally assert ordering before sidecars and patch reports.

## Commands

Offline default, no extra dependencies or workflow:
```bash
uv sync --frozen
uv run python -m unittest tests.test_care_map_conformance -v
uv run python -m unittest discover -s tests -v
```

The Worklane 1 adapter is intentionally absent, so `tests.test_care_map_candidate_contract` **skips with an explicit reason**. This must *never* be described as candidate integration passing. Once the implementation exists:
```bash
CARE_MAP_CONFORMANCE_REQUIRE_CANDIDATE=1 \
CARE_MAP_CANDIDATE_CMD='/path/to/independent-adapter --json' \
uv run python -m unittest tests.test_care_map_candidate_contract -v
```
Missing candidate under `CARE_MAP_CONFORMANCE_REQUIRE_CANDIDATE=1` is a hard **ERROR**, not a skip. CI should set the required mode only once Worklane 1 lands.

### Worklane 1 boundary contract: `modos-care-map-conformance-v1`

One JSON object on **stdin**, exactly one JSON response object on **stdout**, invalid requests **nonzero exit** with diagnostic on stderr. CLI path is configured through `CARE_MAP_CANDIDATE_CMD`, parsed into argv with no shell execution. No file writes or network.

Request example:
```json
{
  "schema": "modos-care-map-conformance-v1",
  "name": "odm",
  "block_size": 4096,
  "original_image_size": 1933312,
  "sparse_total_blocks": 472,
  "sparse_chunks": [{"type": "raw", "start": 0, "end": 472}],
  "filesystem_property_id": "ro.odm.build.fingerprint",
  "filesystem_fingerprint": "Sony/XQ-DC72/XQ-DC72:15/68.2.A.3.107/068002A003010700521798587:user/release-keys",
  "avb_fingerprint": "Sony/lineage_pdx235/pdx235:16/BP4A.251205.006/9d767828e9:userdebug/release-keys"
}
```
Output is exactly `{"name":"odm","ranges":"2,0,472","id":"ro.odm.build.fingerprint","fingerprint":"Sony/XQ-DC72/XQ-DC72:15/68.2.A.3.107/068002A003010700521798587:user/release-keys"}` (JSON key order is irrelevant). Ranges are decimal, half-open `count,start,end,...`; adjacent meaningful spans merge; original filesystem size excludes appended hash tree/FEC/footer; raw and fill are meaningful and dontcare is skipped. For unsparsed partitions, both `sparse_total_blocks` and `sparse_chunks` are JSON `null`, and ranges are contiguous within `original_image_size`.

An integration adapter may be a small test-only wrapper around the corrected Worklane 1 algorithm. **Do not modify Worklane 1 implementation solely to satisfy this protocol**, and do not use the reference oracle as the candidate implementation; this would create a circular, falsely green test.

### Optional full-OTA read-only evidence

Run **only** in a separately authorized isolated forensic environment with the original signed ZIP and a pinned verifier checkout. This script reads, hashes, verifies, and invokes `ota verify`; it **never** patches/signs/writes outputs:
```bash
python -m tests.forensics_check_care_map \
  --ota /local/original/lineage-23.2-20261009-nightly-pdx235-signed.zip \
  --lineageos-pubkey /local/LineageOS/update_verifier/lineageos_pubkey \
  --lineageos-update-verifier /local/LineageOS/update_verifier/update_verifier.py \
  --avbroot /local/pinned/avbroot \
  --avb-pkmd /local/reviewed/source-avb-pkmd.bin \
  --ota-cert /local/reviewed/source-ota-cert.pem
```
The separately provisioned **LineageOS publisher public key** must SHA-256 to pinned `07ba6d...` and the update-verifier Git checkout must equal `9ffcf56a0fe152467da2971f0e6b2b79a42f7890`. Use the separately authenticated source bytes. The AVB key and OTA cert are *avbroot internal-verification inputs*, **not publisher trust anchors**. An avbroot `Care map does not match:` result is the expected historical failure; not source corruption or OTA approval. This probe requires local separately verified avbroot executable integrity; testing only its `--version` output is **not** a binary integrity attestation.

## Mandatory release-side gates once Worklane 1 lands

1. Require **all** offline positive/negative reference cases, without fixture replacement or policy digest exceptions. Require live Worklane 1 candidate tests in strict mode; a missing adapter fails.
2. Compare each signed **output** `ro.<partition>.build.fingerprint` read from its actual repacked filesystem with that output's care-map ID/value. Independently derive sparse/contiguous meaningful extents and bounds from the output image and AVB footer. No AVB-only substitution.
3. Strictly verify AVB signatures, OTA certificate, payload/images, dynamic-partition set, and every output map against separately configured output keys; no compatibility waiver on outputs. Fail closed for missing, duplicate, extra, truncated, or inconsistent metadata.
4. Exercise real, separately signed rootless **and** Magisk outputs, with negative mutation on the *second* output. Do not create Custota sidecars, locked reports, successful release status, or OTA publication when either fails.
5. In a **nonpublishing** full-OTA run reproduce source v3.34.1 mismatch with the exact independently authenticated source; rerun corrected strict output verification against real outputs. Follow with dm-verity/snapuserd/first-boot `update_verifier` and subsequent OTA-persistence testing on physical pdx235 before any merge or release authorization.

**None of these tests fills or enables the production source exception SHA-256, merges a PR, or authorizes release.**


## 2026-10-12 addendum — Worklane 1 provenance-preservation proof

[Worklane 1 RFC (test-independent)](https://github.com/0cwa/my-avbroot-setup/pull/11) proposes a **strictly narrower and more useful** algorithm than regenerating sparse ranges from a nonexistent target-files sparse container: retain the independently authenticated original sparse ranges `S_p` only if **every 4096-byte protected block changed from the original signed image to the final signed output** belongs to those ranges, `D_p ⊆ S_p`. The final source and output data extents, AVB footer original-image sizes, and hashtree data sizes must agree; image layout must be preserved. This does NOT prove runtime behavior on physical hardware.

**New independent test files:**

- `tests/care_map_provenance_reference.py` — test-only block-difference/manifest-digest/range/fingerprint oracle. It compares **every** protected block, including holes, and checks a complete six-partition candidate map against independently parsed source content. It requires SHA-256 and whole-image size from **separately verified signed manifests**, matching source/final hashtree and AVB-footer original-image extents, ext4-only scope, and property identities read from the source/final filesystems. The data structure models externally attested evidence; the module **does not** cryptographically verify manifests, extract filesystem props, or perform real AVB verification.
- `tests/test_care_map_preservation.py` — deterministic, entirely synthetic images of ten 4096-byte blocks each, eight protected data blocks plus two trailer blocks. Includes all six original partition names and sparse holes, mutation inside/outside care ranges, altered data/trailer without authenticated hash updates, source/output image size mismatch, AVB footer/hashtree extent drift, property substitution, missing/duplicate partitions, invalid source/candidate maps, changed map fingerprints or ranges, and non-ext4 filesystem rejection. The synthetic images are **not** source OTA filesystem bytes and their digests are **not** signed release digests.
- `tests/test_care_map_provenance_candidate_contract.py` — **opt-in** Worklane 1 provenance-aware candidate integration (separate from the original AOSP synthetic-sparse-range candidate interface). Missing candidate is an explicit skip in normal CI and a hard failure with `CARE_MAP_PROVENANCE_REQUIRED=1`. Do not wire this to an adapter that simply calls the reference oracle.
  
### Worklane 1 test-only provenance candidate contract: `modos-care-map-provenance-v1`

Configure a standalone test adapter that accepts one JSON object on stdin, writes one JSON response on stdout for positive cases, and exits nonzero for invalid cases; no shell expansion, signing, OTA publication, network, or filesystem mutation. Set:
```bash
CARE_MAP_PROVENANCE_REQUIRED=1 \
CARE_MAP_PROVENANCE_CMD='/path/to/worklane1-independent-test-adapter' \
uv run python -m unittest tests.test_care_map_provenance_candidate_contract -v
```
The request schema is `modos-care-map-provenance-v1`: `block_size=4096`, `source_care_map_b64`, `candidate_output_care_map_b64`, `source_care_map_sha256`, two complete manifest dynamic-partition name arrays, and `partitions` containing one record per name. Each record carries test-only `source_image_b64` / `output_image_b64`, their `{source,output}_manifest_sha256` and `{source,output}_manifest_size`, `{source,output}_hashtree_image_size`, `{source,output}_footer_original_size`, filesystem type, property ID and value. The adapter must check the **entire** candidate map, hashes, image layouts, property IDs/values, and all protected changed blocks. The successful response includes `source_care_map_sha256`, `candidate_care_map_matches_source_semantics=true`, and sorted `partitions` with each source/final SHA-256 and byte size, protected extent sizes, `property_id`, source/output fingerprints, unchanged `ranges`, and `changed_protected_blocks`. `tests/test_care_map_provenance_candidate_contract.py` provides the exact JSON codec and assertions.

This is a **test harness exchange format**, not a recommended production verification interface. In a genuine production verifier, expected source/final manifest hashes must be derived exclusively from independently signature-verified payload manifests and the exact authenticated source member, **never** accepted as caller-supplied authority. The test-only use of synthetic digest fields cannot attest signer identity.

### Additional positive and negative proof matrix

| Proof input / mutation | Reference result | Real candidate status |
|---|---|---|
| Six complete unchanged synthetic images and source map | PASS, zero protected changes | Candidate not yet wired |
| One changed protected block inside each authenticated care range | PASS, changes counted per partition | Candidate not yet wired |
| Changed appended AVB/footer/test trailer with final image digest updated | PASS **only for the conditional data-range proof**; separate cryptographic verification still mandatory | Candidate not yet wired |
| Changed protected sparse hole, including newly allocated/zeroed hole | **FAIL** even if revised image digest is syntactically supplied | Candidate not yet wired |
| Changed data or appended trailer with stale final signed-manifest digest | **FAIL** | Candidate not yet wired |
| Wrong original digest, source map hash, missing final digest, different full image size | **FAIL** | Candidate not yet wired |
| Inconsistent source/final AVB original size, hashtree data extent, or 4096-byte alignment | **FAIL** | Candidate not yet wired |
| Wrong/missing source/final ext4 property ID or fingerprint, AVB substituted for runtime prop | **FAIL** | Candidate not yet wired |
| Missing/duplicate/extra manifest partitions; missing map entry | **FAIL** | Candidate not yet wired |
| Output map ranges widened/narrowed or altered identities, even if changed blocks inside original care ranges | **FAIL** | Candidate not yet wired |
| Same records reordered with unchanged all IDs/fingerprints/ranges | PASS semantic equivalence | Candidate not yet wired |
| Non-ext4 or unknown filesystem type | **FAIL** | Candidate not yet wired |
| Previously cached signed output reused without *fresh* complete post-sign verification | **NOT ATTESTABLE** by offline oracle; release-side fail-closed guard required | Worklane 4 blocker |

**Distinct from initial suite:** the original AOSP reference tests verify what *sparse RAW/FILL/DONT_CARE generation* means when an original sparse chunk map is available. The new preservation tests verify the conservative **reuse of authenticated sparse ranges** when only expanded raw signed images and their signed payload metadata are available. These are not interchangeable algorithms. A filesystem allocation map is not a substitute for authenticated sparse chunk provenance.

### New release-side requirement: post-sign and cached-output freshness

A provisional pre-sign proof is **not enough**. After signing, *re-extract the final output images from the independently authenticated output OTA* and repeat the exact manifest SHA/size, footer/hashtree extent, filesystem property, and `D_p ⊆ S_p` proof; independently compare its entire signed care-map protobuf to the computed map. The configured output signer, payload signatures and partition hashes, AVB chain, recovery certificate, and policy flags still need separate strict verification. All checks must run for **both** rootless and Magisk outputs.

[Worklane 4 quarantine draft](https://github.com/0cwa/ModOS/pull/121) identifies `patch_ota`'s existing `outputs_ready` fast path as potentially skipping post-patch verification of stale cached ZIPs. The offline reference oracle cannot tell whether the caller bypassed it entirely. The release-side implementation must **always** reverify reused OTA outputs immediately before publication or forbid reuse altogether. A green offline CI outcome is not acceptance of cached output safety.

**No corrected avbroot code or proof-backed expected-map verifier is currently integrated.** The source pin remains empty, release quarantine in draft, and physical first-boot/OTA-persistence tests remain mandatory. No merge or OTA publication is authorized.

### Reproducible original signed ext4 property-path evidence (separate from normal CI)

Read-only forensic CI [38181164127, job 114593834255](https://github.com/0cwa/ModOS/actions/runs/38181164127) records the exact successfully read `debugfs` filesystem paths for **the original authenticated signed images**:

| Partition | Original ext4 path | Key |
|---|---|---|
| `odm` | `/etc/build.prop` | `ro.odm.build.fingerprint` |
| `product` | `/etc/build.prop` | `ro.product.build.fingerprint` |
| `system` | `/system/build.prop` | `ro.system.build.fingerprint` |
| `system_ext` | `/etc/build.prop` | `ro.system_ext.build.fingerprint` |
| `vendor` | `/build.prop` | `ro.vendor.build.fingerprint` |
| `vendor_dlkm` | `/etc/build.prop` | `ro.vendor_dlkm.build.fingerprint` |

The fixture now records these paths alongside the six published payload image SHA-256s. The new optional `tests/forensics_check_partition_props.py` independently hashes **each of the six original raw images** against the pinned source hashes **before** invoking read-only `debugfs -R 'cat PATH'` (no shell). It requires exactly one matching `ro.<name>.build.fingerprint` assignment equal to the signed original care map, refusing missing, duplicate, wrong-path, non-UTF8, or AVB-only substitute values. It prints only minimal fingerprint provenance metadata; does not publish or mutate images.

```bash
uv run python -m tests.forensics_check_partition_props \
  --original-image-dir /local/publisher-authenticated-original-partitions
```

`tests/test_care_map_signed_property_paths.py` runs the parser and six-image inspector with **mocked debugfs and tiny deterministic fake files** in ordinary offline CI. This is a unit test of exact path and fail-closed hashing/metadata logic, **not** a claim to re-extract/rehash 1.23 GB source images in CI.

**Important limit:** These paths are provenance of the **original signed images**. The patcher may change final filesystem content; Worklane 1/4 must independently inspect **final signed output images** and prove actual effective boot-time properties separately. Original path consistency is not a device runtime getprop attestation.
