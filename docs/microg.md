# microG locked module

The `microg` adapter injects official microG Services and Companion APKs as
privileged product apps. It does not patch Android framework code or execute
installer scripts.

The reviewed experimental build targets are LineageOS API 36 and 37. They rely
on LineageOS's restricted signature spoofing for official microG-signed
`com.google.android.gms` and `com.android.vending`. GrapheneOS and APIs outside
36–37 remain incompatible. The [API-37 qualification](microg-api37-qualification.md)
records exact source/APK review, owner-reported repaired rootless boot and the
remaining runtime limits. Each microG profile's API must match the authenticated
source and every verified output archive's `post-sdk-level`.

## Reviewed release

The checked-in lock pins microG `v0.3.17.252432`:

- `com.google.android.gms` versionCode `252432034`
- `com.android.vending` versionCode `84022634`

Normal locked-artifact fetch/verify checks exact size, SHA-256, package name,
versionCode, and the single official microG APK signer before the adapter sees
the files. The adapter also pins the reviewed module release and package
identities.

The product privileged-permission policy explicitly denies
`android.permission.DUMP`. On the owner's pdx235 LineageOS 24.0 October 16
rootless update, an unaccounted GmsCore request for this permission caused
`AppIdPermissionPolicy.onSystemReady` to abort `system_server` repeatedly.
An explicit denial satisfies permission-policy accounting without granting
microG access to system-service diagnostic dumps. Privileged-permission
enforcement, APK signer checks, and the remaining grants are unchanged.
The regression verifies the XML actually passed to the product installer.
The owner subsequently reported that the repaired Android 17 rootless OTA
booted and worked well. Post-repair ADB diagnostics, complete microG functional
checks, physical Magisk boot and a later OTA persistence cycle remain unobserved;
see the qualification record for that distinction.

Updates intentionally require a code review of the lock, adapter release
constants, and privileged/default-permission policy. ModOS Renovate tracks the reviewed release and proposes updates without
automerge. Generate a candidate lock from the explicit official release with:

```sh
uv run python tools/update_microg_lock.py --release v0.3.17.252432 \
  --cache .cache/microg --output locks/microg-v0.3.17.252432.json
```

The updater verifies both APK signatures against the unchanged official signer,
as well as release SHA-256, size, package name and versionCode, before writing
its output. It selects standard custom-ROM APKs and excludes Huawei/development
variants. Review and update adapter release/version constants, permission policy,
lock regression expectations, and the release-specific license URL together.
Helper CI repeats actual APK verification. Then advance ModOS's release selector,
immutable helper pin and compatibility manifests together; its CI rejects a
selector without the matching helper lock. No floating build-time selection is
introduced.

GsfProxy, F-Droid, Aurora Store, framework patches, Magisk modules, runtime
signature-spoofing hooks, and opinionated microG preference defaults are out of
scope.
