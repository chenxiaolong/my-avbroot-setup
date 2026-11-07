# Experimental microG API 37 build qualification

## Decision and scope

The existing locked microG release is eligible for **experimental LineageOS API
36 and 37 builds**, including the existing published output scope. The registry
continues rejecting API 35, API 38 and GrapheneOS. ModOS retains its separate
pdx235/LineageOS 24.0 nightly source and publication restrictions. This is an
explicit correction to the existing API-37 build path, whose generated profile
previously claimed API 36; it is not general device or future-version support.

The source and APK review below supports this narrow build target without
changing the APK lock, signer, restricted spoofing contract, permission XML or
native-library implementation. Fresh outputs must still pass the existing
source publisher, OTA/payload/AVB and runtime care-map verification. A successful
artifact build does not establish all microG functionality or device behavior.

## Evidence and retained limits

The [October 17 ModOS repair record](https://github.com/0cwa/ModOS/blob/main/docs/pdx235-bootloop-20261017.md)
identifies the failed LineageOS 24.0/SDK-37 installation, the specific missing
DUMP accounting, the independently verified repaired rootless candidate and the
owner's subsequent report that it booted and worked well. The owner requested
resumption of normal publication. That is owner-reported repaired rootless boot,
not a new ADB capture, full microG functional test, Magisk boot or subsequent OTA
persistence test. Those limits remain in force.

The machine-readable [qualification receipt](microg-api37-qualification.json)
records the exact source, APK, tooling and test identities. It is review evidence,
not executable authorization. The source snapshot is LineageOS frameworks/base
`1df617a1093e41562fd1f43f27de0cfb4af817e5` (November 5, 2026).

### Restricted spoofing

[MicrogUtils](https://github.com/LineageOS/android_frameworks_base/blob/1df617a1093e41562fd1f43f27de0cfb4af817e5/core/java/com/android/internal/content/MicrogUtils.java)
accepts only `com.google.android.gms` and `com.android.vending`, an exact single
real microG certificate, and the exact Google certificate requested by each
APK's `fake-signature` metadata. Both locked APKs match. The real certificate's
SHA-256 is the existing pinned
`9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165`.
[ComputerEngine](https://github.com/LineageOS/android_frameworks_base/blob/1df617a1093e41562fd1f43f27de0cfb4af817e5/services/core/java/com/android/server/pm/ComputerEngine.java)
uses that result for package signature reporting.

The [native eligibility gate](https://github.com/LineageOS/android_frameworks_base/blob/1df617a1093e41562fd1f43f27de0cfb4af817e5/core/jni/com_android_internal_content_MicrogUtils.cpp)
is compile-time `ANDROID_DEBUGGABLE`. No runtime property toggle or universal
signature-spoofing permission is introduced. The retained XML name
`FAKE_PACKAGE_SIGNATURE` is not itself the authority for this restricted
LineageOS implementation. Arbitrary user-build frameworks are not qualified by
this review.

### Permission accounting

Against the exact API-37 framework permission definitions, Services requests
14 active privileged permissions: the existing policy grants 13 and explicitly
denies DUMP. Companion's three active privileged requests are already granted.
No active core privileged request is unaccounted. The three requested AdServices
permissions are normal permissions in AOSP `android-17.0.0_r1`, not additional
privileged grants.

[AppIdPermissionPolicy](https://github.com/LineageOS/android_frameworks_base/blob/1df617a1093e41562fd1f43f27de0cfb4af817e5/services/permission/java/com/android/server/permission/access/permission/AppIdPermissionPolicy.kt)
uses the product allowlist for product apps, distinguishes an explicit denial
from an absent entry, and raises the observed boot-time error for unaccounted
privileged requests under enforcement. DUMP remains denied. The [AOSP allowlist
contract](https://source.android.com/docs/core/permissions/perms-allowlist)
also requires policy on the app's own partition.

Default grants and app-ops are separate from privileged-permission accounting.
An XML entry alone does not prove a runtime grant for signature-only or
signature/app-op permissions. No defaults or grants are broadened here.

### APK SDK and native libraries

Both exact locked APKs cryptographically verify with one pinned signer and
declare minSdk 19, targetSdk 29 and compileSdk 35. [targetSdk is a compatibility
behavior selector](https://developer.android.com/guide/topics/manifest/uses-sdk-element),
not a maximum device API or proof of API-37 runtime testing. The APKs are not
rewritten or re-signed.

Services contains 24 compressed native libraries, six per supported ABI. The
existing adapter extracts their exact bytes to the ISA-specific `GmsCore/lib/`
directories. This matches [PackageAbiHelperImpl](https://github.com/LineageOS/android_frameworks_base/blob/1df617a1093e41562fd1f43f27de0cfb4af817e5/services/core/java/com/android/server/pm/PackageAbiHelperImpl.java):
bundled cluster apps use adjacent ISA directories, and PackageManager does not
extract libraries from a non-updated system app. Companion has no native libs.
Five of six ARM64 libraries have 4096-byte ELF load alignment; **16 KiB kernel
page compatibility remains unqualified**. Do not infer it from this API range.

## SDK binding and regression coverage

After the existing source verifier succeeds and before mutation/injection,
`patch.py` compares the resolved microG profile's API to the source archive's
`post-sdk-level`. It repeats the comparison after each final output passes
cryptographic verification, before sidecars or a success report. Missing,
malformed, duplicate or oversized metadata fails closed. Other module selections
do not gain a new SDK requirement. A spoofed Sony fingerprint is never used to
infer the SDK.

This binds the profile to the authenticated archive's declared SDK. It does not
independently prove live runtime property loading, the compiled framework's
capabilities or full device functionality. Runtime care-map identity and image
hash checks remain separately enforced by the existing verifier.

The focused regressions use the real catalog and canonical APK lock for API
36/37 experimental acceptance and API 35/38/GrapheneOS rejection. Synthetic ZIP
tests cover SDK ambiguity, authentication order, source mismatch before unpack,
and primary/secondary output mismatch in both verification modes. Mocked
cryptographic boundaries in these ordering tests are not OTA acceptance evidence.

For a fresh real build, retain the actual API-37 profile, exact source digest,
source/output verification receipts and per-output module report. Inspect the
verified product images for the locked APKs, exact native-library bytes, scoped
permission XML and the DUMP denial. Record those artifact checks separately from
microG self-checks, accounts, push, location, Magisk boot and OTA persistence.
