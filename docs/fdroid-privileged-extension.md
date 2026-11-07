# F-Droid Privileged Extension adapter

This reviewed adapter is a default-off, rootless, static-image module. It is
experimental for LineageOS and GrapheneOS and requires profile consent bound to
the exact canonical lock digest and output scope.

The lock supplies four exact artifacts:

- `fdroid-client-apk`: the separately selected stable
  `org.fdroid.fdroid` APK, signed by the pinned F-Droid signer.
- `fdroid-client-source`: the matching GPL-3.0-or-later corresponding source.
- `fdroid-privileged-extension-ota`: the official Apache-2.0 OTA container.
- `fdroid-privileged-extension-source`: the matching Apache-2.0 FPE source
  archive.

The OTA lock allowlists only `F-DroidPrivilegedExtension.apk` and
`permissions_org.fdroid.fdroid.privileged.xml`. The adapter never invokes its
`update-binary`, shell scripts, or other installer hooks, and never uses the
bundled client APK. It installs only:

- `/system/app/F-Droid/F-Droid.apk`
- `/system/priv-app/F-DroidPrivilegedExtension/F-DroidPrivilegedExtension.apk`
- `/system/etc/permissions/permissions_org.fdroid.fdroid.privileged.xml`

The XML is parsed as a closed format: no DTDs, entities, comments, processing
instructions, extra attributes, extra text, extra packages, or permissions are
accepted. Its only grants are `INSTALL_PACKAGES` and `DELETE_PACKAGES` for
`org.fdroid.fdroid.privileged`.

This module currently permits only `local-unpublished` output. Although both
corresponding-source archives are locked and reported, the patch workflow does
not yet export and deliver a source bundle alongside firmware. Private, shared,
and published output must remain rejected until that delivery path exists.
Future distributors must preserve Apache-2.0 notices for the privileged
extension and provide corresponding source for the GPL-3.0-or-later client.
