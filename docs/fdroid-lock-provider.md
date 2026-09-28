# F-Droid privileged-extension lock provider

`lock update fdroid-privileged-extension` is the only command allowed to
contact F-Droid's floating repository metadata. It requires both reviewed
selectors and an explicit output path:

```bash
python3 module-tool.py lock update fdroid-privileged-extension \
  --client-version-code 1023052 \
  --fpe-ota-version-code 2130 \
  --output locks/fdroid-privileged-extension.lock.json
```

The provider is registered in a static Python mapping. A module name is never
interpreted as an import path, and normal build, fetch, verify, resolve, and
patch paths cannot fall back to this provider.

## Trust chain and current fail-closed state

The updater downloads bounded temporary copies of
`https://f-droid.org/repo/entry.jar`, `entry.json`, and `entry.json.asc`. It:

1. safely inspects the exact reviewed `entry.jar` layout;
2. requires `jarsigner -strict` verification and pins the single signer X.509
   certificate SHA-256 to
   `43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab`;
3. requires the JAR's `entry.json` bytes to equal the detached bytes;
4. verifies the detached signature with an isolated GnuPG home and the pinned
   primary/subkey pair
   `37D2C98789D8311948394E3E41E7044E1DBA2E89` /
   `802A9799016112346E1FEFF47A029E54DD5DCE7A`;
5. rejects unsafe GnuPG machine statuses including `EXPKEYSIG`, `KEYEXPIRED`,
   `REVKEYSIG`, `BADSIG`, and `ERRSIG`, regardless of the process exit code;
6. fetches only the exact index name, size, and SHA-256 authenticated by the
   doubly verified entry metadata.

As checked on 2026-07-18, F-Droid still signs this metadata with the expired
`802A...CE7A` subkey. GnuPG reports both `KEYEXPIRED` and `EXPKEYSIG`. Therefore
the production command intentionally fails before resolving the index and does
not create a lock. Do not add a production lock, suppress expiration status, or
substitute an unreviewed key. A future trust-key change requires an explicit
security review and updated fixtures.

The checked-in trust asset
`lib/modules/trust/fdroid-admin.asc` was extracted without execution from the
`admin@f-droid.org.asc` member of
`https://f-droid.org/assets/admin@f-droid.org.jar`. Provenance recorded on
2026-07-18:

- container SHA-256:
  `bee76da45328040e01805997192804161c99713c8722b1f316eec92203fbd977`
- container signer X.509 SHA-256:
  `43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab`
- extracted member SHA-256:
  `907afad38d2fc3d9f68cba882c62620fb2cf8dfb8a4b84573f1efa02e2d6620a`

F-Droid documents this repository-certificate-to-OpenPGP-key chain in its
[release-channel and signing-key documentation](https://f-droid.org/en/docs/Release_Channels_and_Signing_Keys/).

## Locked records

The signed index must contain exactly one reviewed version record for each of:

- F-Droid client `org.fdroid.fdroid`, versionCode `1023052`, versionName
  `1.23.2`;
- OTA container `org.fdroid.fdroid.privileged.ota`, versionCode `2130`;
- nested APK identity `org.fdroid.fdroid.privileged`, versionCode `2130`,
  versionName `0.2.13`.

The updater rechecks the researched release sizes and SHA-256 values against
the signed index, downloads every locked object with exact bounds, and verifies
both APK package/version/single-signer identities with `apksigner` and
`apkanalyzer`. Missing `jarsigner`, `openssl`, `gpg`, `apksigner`, or
`apkanalyzer` is a hard, named failure.

The OTA is only a container. Its recovery installer and shell members are
never invoked. The complete raw layout must match the reviewed 2130 layout,
and only these two members are locked for native adapter consumption:

- `F-DroidPrivilegedExtension.apk`
- `permissions_org.fdroid.fdroid.privileged.xml`

The permission XML is parsed before lock creation and must grant exactly
`INSTALL_PACKAGES` and `DELETE_PACKAGES` to
`org.fdroid.fdroid.privileged`.

A successful reviewed update would atomically write four canonical records:
the client APK, its F-Droid-published corresponding-source archive, the FPE OTA
container, and the FPE corresponding-source archive. The GPL client binary
requires its source record; the Apache-2.0 FPE container also links its source.
Every record carries the signed-index digest and the three trust-root types.

Until the patch workflow implements explicit corresponding-source export and
delivery, every artifact permits only the `local-unpublished` output scope.
Keeping source archives in a local cache or naming them in a patch report is
not source delivery for distributed firmware. Private, shared, and published
outputs therefore fail closed at lock resolution.
