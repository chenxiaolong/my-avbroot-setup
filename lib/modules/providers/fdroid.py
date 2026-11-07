# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Fail-closed F-Droid Privileged Extension lock-update provider."""

from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Literal
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import xml.etree.ElementTree as ET

from lib.modules.archive import (
    ArchiveError,
    ArchiveLimits,
    inspect_zip,
    read_allowlisted_member,
)
from lib.modules.locks import (
    ApkIdentity,
    ArchiveMember,
    ArchivePolicy,
    ArtifactLegal,
    ArtifactLock,
    ArtifactLockFile,
    ArtifactSource,
    LockError,
    ModuleLock,
    SourceVerification,
    write_lock,
)
from lib.modules.registry import (
    FDROID_OPENPGP_PRIMARY,
    FDROID_OPENPGP_SUBKEY,
    FDROID_REPOSITORY_CERT_SHA256,
)


MODULE_ID = 'fdroid-privileged-extension'
REPOSITORY_ORIGIN = 'https://f-droid.org'
REPOSITORY_URL = f'{REPOSITORY_ORIGIN}/repo/'
ENTRY_JAR_URL = f'{REPOSITORY_URL}entry.jar'
ENTRY_JSON_URL = f'{REPOSITORY_URL}entry.json'
ENTRY_SIGNATURE_URL = f'{REPOSITORY_URL}entry.json.asc'

CLIENT_PACKAGE = 'org.fdroid.fdroid'
CLIENT_VERSION_CODE = 1023052
CLIENT_VERSION_NAME = '1.23.2'
CLIENT_APK_SHA256 = '985f5181d48bb6bafd54083a048b391271e0ab28385881cc41294fb01a222762'
CLIENT_APK_SIZE = 12_426_276
CLIENT_SOURCE_SHA256 = '7b558e8c4ce1520368fdf6705b0dbd40366573fcb9b3313a9bb03fcb3484e3e7'
CLIENT_SOURCE_SIZE = 5_660_476

FPE_PACKAGE = 'org.fdroid.fdroid.privileged'
FPE_OTA_PACKAGE = 'org.fdroid.fdroid.privileged.ota'
FPE_VERSION_CODE = 2130
FPE_VERSION_NAME = '0.2.13'
FPE_OTA_VERSION_NAME = '7d14a91'
FPE_OTA_SHA256 = '7d14a91d750ce4dabd705264f0dee27a6c38f37e36c97194b06d7d1c8ec79c84'
FPE_OTA_SIZE = 5_745_557
FPE_APK_SHA256 = '1008525a17b4f6a93ac690f9c50dcb675b6bebf53d2879dbc98ba65a1cb2e28d'
FPE_APK_SIZE = 45_943
FPE_SOURCE_SHA256 = 'e8073762a5bce0fda65b814f8347cf3f99d819cccfe9053fa084068fd91060d4'
FPE_SOURCE_SIZE = 96_340

FDROID_X509_CERT_SHA256 = FDROID_REPOSITORY_CERT_SHA256.lower()
FDROID_OPENPGP_SIGNING_SUBKEY = FDROID_OPENPGP_SUBKEY
TRUST_KEY_SHA256 = '907afad38d2fc3d9f68cba882c62620fb2cf8dfb8a4b84573f1efa02e2d6620a'
TRUST_KEY_PATH = Path(__file__).parents[1] / 'trust' / 'fdroid-admin.asc'

ENTRY_JAR_LAYOUT = frozenset((
    'META-INF/CIARANG.RSA',
    'META-INF/CIARANG.SF',
    'META-INF/MANIFEST.MF',
    'entry.json',
))
FPE_OTA_LAYOUT = frozenset((
    '80-fdroid.sh',
    'F-Droid.apk',
    'F-DroidPrivilegedExtension.apk',
    'META-INF/',
    'META-INF/com/',
    'META-INF/com/google/',
    'META-INF/com/google/android/',
    'META-INF/com/google/android/update-binary',
    'permissions_org.fdroid.fdroid.privileged.xml',
))
FPE_APK_MEMBER = 'F-DroidPrivilegedExtension.apk'
FPE_PERMISSION_MEMBER = 'permissions_org.fdroid.fdroid.privileged.xml'
FPE_PERMISSION_SHA256 = '3b89e4864796b12e306f320d34356a391f8eb608cb271230141805c1d0f8c88a'

ENTRY_MAX_BYTES = 256 * 1024
ENTRY_JAR_MAX_BYTES = 2 * 1024 * 1024
SIGNATURE_MAX_BYTES = 64 * 1024
INDEX_MAX_BYTES = 128 * 1024 * 1024
ARTIFACT_MAX_BYTES = 512 * 1024 * 1024
LOCAL_ONLY_OUTPUT_SCOPES: tuple[Literal['local-unpublished'], ...] = (
    'local-unpublished',
)

_SHA256 = re.compile(r'^[0-9a-f]{64}$')
_SAFE_REPOSITORY_NAME = re.compile(r'^/[A-Za-z0-9][A-Za-z0-9._+@/-]*$')
_CERTIFICATE_PEM = re.compile(
    br'-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----\r?\n?',
    flags=re.DOTALL,
)
_FORBIDDEN_GPG_STATUS = frozenset((
    'BADARMOR',
    'BADSIG',
    'ERRSIG',
    'EXPKEYSIG',
    'EXPSIG',
    'FAILURE',
    'KEYEXPIRED',
    'KEYREVOKED',
    'NODATA',
    'NO_PUBKEY',
    'REVKEYSIG',
    'SIGEXPIRED',
))


Fetcher = Callable[..., None]


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) != REPOSITORY_ORIGIN:
            raise LockError('F-Droid metadata redirected outside its pinned origin')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    host = (parsed.hostname or '').lower()
    port = parsed.port
    if parsed.scheme != 'https' or not host or parsed.username or parsed.password:
        raise LockError('F-Droid provider URL is not safe HTTPS')
    if (
        parsed.fragment
        or '\\' in url
        or not url.isascii()
        or any(ord(character) <= 0x20 or ord(character) == 0x7f for character in url)
    ):
        raise LockError('F-Droid provider URL is malformed')
    return f'https://{host}' if port in (None, 443) else f'https://{host}:{port}'


def _fetch_https(
    url: str,
    destination: Path,
    *,
    label: str,
    max_bytes: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> None:
    """Fetch one same-origin object through a bounded, fsynced temp file."""

    if _origin(url) != REPOSITORY_ORIGIN:
        raise LockError(f'{label} URL is outside the pinned F-Droid origin')
    if expected_size is not None and expected_size > max_bytes:
        raise LockError(f'{label} exceeds the provider byte limit')
    temporary = destination.with_name(f'.{destination.name}.download')
    try:
        request = Request(url, headers={'User-Agent': 'my-avbroot-setup-lock-update/1'})
        opener = build_opener(_SameOriginRedirectHandler())
        with opener.open(request, timeout=60) as response, temporary.open('xb') as output:
            if _origin(response.geturl()) != REPOSITORY_ORIGIN:
                raise LockError(f'{label} redirected outside the pinned origin')
            if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                raise LockError(f'{label} used a forbidden content encoding')
            declared = response.headers.get('Content-Length')
            if declared is not None:
                try:
                    declared_size = int(declared, 10)
                except ValueError as error:
                    raise LockError(f'{label} returned an invalid Content-Length') from error
                if declared_size < 0 or declared_size > max_bytes:
                    raise LockError(f'{label} exceeds the provider byte limit')
                if expected_size is not None and declared_size != expected_size:
                    raise LockError(f'{label} size differs from signed metadata')
            digest = hashlib.sha256()
            count = 0
            while chunk := response.read(64 * 1024):
                count += len(chunk)
                if count > max_bytes or (
                    expected_size is not None and count > expected_size
                ):
                    raise LockError(f'{label} exceeded its byte limit')
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        if expected_size is not None and count != expected_size:
            raise LockError(f'{label} size differs from signed metadata')
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise LockError(f'{label} SHA-256 differs from signed metadata')
        os.replace(temporary, destination)
    except LockError:
        temporary.unlink(missing_ok=True)
        raise
    except FileExistsError as error:
        temporary.unlink(missing_ok=True)
        raise LockError(f'{label} temporary download already exists') from error
    except Exception as error:
        temporary.unlink(missing_ok=True)
        raise LockError(f'{label} download failed') from error


def _run_tool(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            input=input_bytes,
            capture_output=True,
            check=False,
            env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'},
        )
    except FileNotFoundError as error:
        raise LockError(f'required F-Droid verifier is unavailable: {arguments[0]}') from error
    except OSError as error:
        raise LockError(f'F-Droid verifier failed to start: {arguments[0]}') from error


def _strict_json(data: bytes, *, label: str) -> Mapping[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate key: {key!r}')
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode('UTF-8'),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f'non-finite number: {value}')
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise LockError(f'{label} is not strict JSON') from error
    if not isinstance(value, dict):
        raise LockError(f'{label} root must be an object')
    return value


def _verify_entry_jar(path: Path) -> bytes:
    try:
        inspection = inspect_zip(
            path,
            allowlisted_members=ENTRY_JAR_LAYOUT,
            limits=ArchiveLimits(
                max_members=8,
                max_member_size=ENTRY_MAX_BYTES,
                max_total_size=2 * ENTRY_MAX_BYTES,
                max_expansion_ratio=20,
                max_streamed_bytes=2 * ENTRY_MAX_BYTES,
            ),
        )
    except ArchiveError as error:
        raise LockError('F-Droid entry.jar failed safe archive inspection') from error
    if {member.name for member in inspection.members} != ENTRY_JAR_LAYOUT:
        raise LockError('F-Droid entry.jar has an unreviewed archive layout')

    result = _run_tool(['jarsigner', '-verify', '-strict', '-verbose', '-certs', str(path)])
    combined = result.stdout + result.stderr
    # Exit 4 is the expected strict warning for F-Droid's pinned self-signed
    # repository certificate.  Other bit combinations include verification
    # failures and are rejected.
    if result.returncode not in (0, 4) or b'jar verified' not in combined.lower():
        raise LockError('F-Droid entry.jar signature verification failed')

    signature_block = read_allowlisted_member(
        path,
        'META-INF/CIARANG.RSA',
        allowlisted_members=ENTRY_JAR_LAYOUT,
        limits=ArchiveLimits(
            max_members=8,
            max_member_size=ENTRY_MAX_BYTES,
            max_total_size=2 * ENTRY_MAX_BYTES,
            max_expansion_ratio=20,
            max_streamed_bytes=2 * ENTRY_MAX_BYTES,
        ),
    )
    pkcs7 = _run_tool(
        ['openssl', 'pkcs7', '-inform', 'DER', '-print_certs', '-outform', 'PEM'],
        input_bytes=signature_block,
    )
    if pkcs7.returncode != 0:
        raise LockError('F-Droid entry.jar certificate extraction failed')
    certificates = _CERTIFICATE_PEM.findall(pkcs7.stdout)
    if len(certificates) != 1:
        raise LockError('F-Droid entry.jar must contain exactly one signer certificate')
    certificate = _run_tool(
        ['openssl', 'x509', '-inform', 'PEM', '-outform', 'DER'],
        input_bytes=certificates[0],
    )
    if certificate.returncode != 0:
        raise LockError('F-Droid entry.jar signer certificate is invalid')
    if hashlib.sha256(certificate.stdout).hexdigest() != FDROID_X509_CERT_SHA256:
        raise LockError('F-Droid entry.jar signer certificate is not pinned')
    return read_allowlisted_member(
        path,
        'entry.json',
        allowlisted_members=ENTRY_JAR_LAYOUT,
        limits=ArchiveLimits(
            max_members=8,
            max_member_size=ENTRY_MAX_BYTES,
            max_total_size=2 * ENTRY_MAX_BYTES,
            max_expansion_ratio=20,
            max_streamed_bytes=2 * ENTRY_MAX_BYTES,
        ),
    )


def _gpg_status_lines(output: bytes) -> tuple[tuple[str, tuple[str, ...]], ...]:
    statuses: list[tuple[str, tuple[str, ...]]] = []
    try:
        text = output.decode('UTF-8')
    except UnicodeDecodeError as error:
        raise LockError('gpg returned non-UTF-8 machine status') from error
    for line in text.splitlines():
        if not line.startswith('[GNUPG:] '):
            continue
        fields = line[9:].split()
        if not fields:
            raise LockError('gpg returned an empty machine-status record')
        statuses.append((fields[0], tuple(fields[1:])))
    return tuple(statuses)


def _reject_unsafe_gpg_status(statuses: tuple[tuple[str, tuple[str, ...]], ...]) -> None:
    forbidden = sorted({name for name, _ in statuses} & _FORBIDDEN_GPG_STATUS)
    if forbidden:
        raise LockError(
            f'F-Droid OpenPGP verification reported unsafe status: {", ".join(forbidden)}'
        )


def _verify_openpgp(signature: Path, data: Path, home: Path) -> None:
    key_data = TRUST_KEY_PATH.read_bytes()
    if hashlib.sha256(key_data).hexdigest() != TRUST_KEY_SHA256:
        raise LockError('checked-in F-Droid OpenPGP trust asset is not pinned')
    key_path = home / 'fdroid-admin.asc'
    key_path.write_bytes(key_data)
    os.chmod(key_path, 0o400)
    common = [
        'gpg',
        '--batch',
        '--no-options',
        '--no-auto-key-retrieve',
        '--auto-key-locate',
        'clear',
        '--homedir',
        str(home),
        '--status-fd',
        '1',
    ]
    imported = _run_tool([*common, '--import', str(key_path)])
    import_status = _gpg_status_lines(imported.stdout)
    _reject_unsafe_gpg_status(import_status)
    if imported.returncode != 0 or not any(
        name == 'IMPORT_OK' and fields[-1:] == (FDROID_OPENPGP_PRIMARY,)
        for name, fields in import_status
    ):
        raise LockError('F-Droid OpenPGP trust asset import failed')

    verified = _run_tool([*common, '--verify', str(signature), str(data)])
    statuses = _gpg_status_lines(verified.stdout)
    _reject_unsafe_gpg_status(statuses)
    valid = [fields for name, fields in statuses if name == 'VALIDSIG']
    good = [fields for name, fields in statuses if name == 'GOODSIG']
    if verified.returncode != 0 or len(valid) != 1 or len(good) != 1:
        raise LockError('F-Droid entry.json OpenPGP signature is not uniquely valid')
    valid_fields = valid[0]
    if (
        not valid_fields
        or valid_fields[0] != FDROID_OPENPGP_SIGNING_SUBKEY
        or valid_fields[-1] != FDROID_OPENPGP_PRIMARY
        or not good[0]
        or not FDROID_OPENPGP_SIGNING_SUBKEY.endswith(good[0][0])
    ):
        raise LockError('F-Droid OpenPGP primary key or signing subkey is not pinned')


def _required_mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise LockError(f'{label} must be an object')
    return value


def _required_int(value: object, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LockError(f'{label} must be a positive integer')
    return value


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise LockError(f'{label} must be lowercase SHA-256')
    return value


def _repository_file_url(name: object, *, expected: str, label: str) -> str:
    if not isinstance(name, str) or name != expected:
        raise LockError(f'{label} has an unexpected repository filename')
    if (
        not _SAFE_REPOSITORY_NAME.fullmatch(name)
        or '\\' in name
        or any(component in ('', '.', '..') for component in name[1:].split('/'))
    ):
        raise LockError(f'{label} repository filename is unsafe')
    return f'{REPOSITORY_ORIGIN}/repo{name}'


def _index_reference(entry: Mapping[str, object]) -> tuple[str, int, str]:
    if set(entry) != {'timestamp', 'version', 'maxAge', 'index', 'diffs'}:
        raise LockError('F-Droid entry.json has an unreviewed schema')
    index = _required_mapping(entry['index'], label='entry index')
    if set(index) != {'name', 'sha256', 'size', 'numPackages'}:
        raise LockError('F-Droid entry index has an unreviewed schema')
    url = _repository_file_url(
        index['name'],
        expected='/index-v2.json',
        label='entry index',
    )
    size = _required_int(index['size'], label='entry index size')
    if size > INDEX_MAX_BYTES:
        raise LockError('F-Droid index exceeds the provider byte limit')
    digest = _required_sha256(index['sha256'], label='entry index digest')
    _required_int(index['numPackages'], label='entry package count')
    return url, size, digest


def _version_record(
    index: Mapping[str, object],
    package_name: str,
    version_code: int,
    version_name: str,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    packages = _required_mapping(index.get('packages'), label='index packages')
    package = _required_mapping(packages.get(package_name), label=f'package {package_name}')
    versions = _required_mapping(package.get('versions'), label=f'{package_name} versions')
    matches: list[Mapping[str, object]] = []
    for value in versions.values():
        record = _required_mapping(value, label=f'{package_name} version')
        manifest = _required_mapping(record.get('manifest'), label=f'{package_name} manifest')
        if manifest.get('versionCode') == version_code:
            matches.append(record)
    if len(matches) != 1:
        raise LockError(
            f'index must contain exactly one {package_name} versionCode {version_code}'
        )
    manifest = _required_mapping(matches[0]['manifest'], label=f'{package_name} manifest')
    if manifest.get('versionName') != version_name:
        raise LockError(f'{package_name} versionName does not match its reviewed selector')
    return package, matches[0]


def _file_record(
    record: Mapping[str, object],
    field: str,
    *,
    expected_name: str,
    expected_size: int,
    expected_sha256: str,
    label: str,
) -> tuple[str, int, str]:
    value = _required_mapping(record.get(field), label=label)
    url = _repository_file_url(value.get('name'), expected=expected_name, label=label)
    size = _required_int(value.get('size'), label=f'{label} size')
    digest = _required_sha256(value.get('sha256'), label=f'{label} digest')
    if size != expected_size or digest != expected_sha256:
        raise LockError(f'{label} differs from the reviewed release identity')
    return url, size, digest


def _index_signer(package: Mapping[str, object], record: Mapping[str, object]) -> str:
    metadata = _required_mapping(package.get('metadata'), label='package metadata')
    preferred = _required_sha256(metadata.get('preferredSigner'), label='preferred signer')
    manifest = _required_mapping(record.get('manifest'), label='package manifest')
    signer = _required_mapping(manifest.get('signer'), label='manifest signer')
    values = signer.get('sha256')
    if not isinstance(values, list) or values != [preferred]:
        raise LockError('signed index does not name exactly one preferred APK signer')
    if preferred != FDROID_X509_CERT_SHA256:
        raise LockError('signed index APK signer is not the pinned F-Droid signer')
    return preferred


def _apk_identity(path: Path, package_name: str, version_code: int, signer: str) -> ApkIdentity:
    signature = _run_tool(['apksigner', 'verify', '--verbose', '--print-certs', str(path)])
    if signature.returncode != 0:
        raise LockError('APK signature verification failed during lock update')
    matches = re.findall(
        rb'^Signer #\d+ certificate SHA-256 digest: ([0-9A-Fa-f:]+)$',
        signature.stdout,
        flags=re.MULTILINE,
    )
    actual_signers = tuple(value.replace(b':', b'').decode('ASCII').lower() for value in matches)
    if actual_signers != (signer,):
        raise LockError('APK signer differs from the signed index')
    package = _run_tool(['apkanalyzer', 'manifest', 'application-id', str(path)])
    version = _run_tool(['apkanalyzer', 'manifest', 'version-code', str(path)])
    if package.returncode != 0 or version.returncode != 0:
        raise LockError('APK manifest inspection failed during lock update')
    try:
        actual_package = package.stdout.decode('UTF-8').strip()
        actual_version = int(version.stdout.decode('ASCII').strip(), 10)
    except (UnicodeDecodeError, ValueError) as error:
        raise LockError('APK verifier returned malformed identity output') from error
    if actual_package != package_name or actual_version != version_code:
        raise LockError('APK identity differs from its exact package/version selector')
    return ApkIdentity(
        package_name=package_name,
        version_code=version_code,
        signer_sha256=signer,
    )


def _validate_permission_xml(data: bytes) -> None:
    if data.startswith(b'\xef\xbb\xbf'):
        raise LockError('FPE permission XML contains a byte-order mark')
    try:
        data.decode('UTF-8')
    except UnicodeDecodeError as error:
        raise LockError('FPE permission XML is not UTF-8') from error
    if b'<!' in data or b'&' in data:
        raise LockError('FPE permission XML contains declarations or entities')
    declaration = b'<?xml version="1.0" encoding="utf-8"?>'
    if not data.startswith(declaration) or b'<?' in data[len(declaration):]:
        raise LockError('FPE permission XML has an unreviewed declaration')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise LockError('FPE permission XML is malformed') from error
    if (
        root.tag != 'permissions'
        or root.attrib
        or (root.text or '').strip()
        or (root.tail or '').strip()
    ):
        raise LockError('FPE permission XML has an unreviewed root')
    children = list(root)
    if len(children) != 1:
        raise LockError('FPE permission XML must contain one privileged allowlist')
    allowlist = children[0]
    if allowlist.tag != 'privapp-permissions' or allowlist.attrib != {
        'package': FPE_PACKAGE
    } or (allowlist.text or '').strip() or (allowlist.tail or '').strip():
        raise LockError('FPE permission XML targets an unexpected package')
    permissions = list(allowlist)
    expected = {
        'android.permission.DELETE_PACKAGES',
        'android.permission.INSTALL_PACKAGES',
    }
    actual: set[str] = set()
    for permission in permissions:
        if (
            permission.tag != 'permission'
            or set(permission.attrib) != {'name'}
            or list(permission)
            or (permission.text or '').strip()
            or (permission.tail or '').strip()
        ):
            raise LockError('FPE permission XML contains an unreviewed element')
        actual.add(permission.attrib['name'])
    if len(permissions) != 2 or actual != expected:
        raise LockError('FPE permission XML grants permissions outside the reviewed set')


def _source_verification(index_sha256: str) -> SourceVerification:
    return SourceVerification(
        repository_url=REPOSITORY_URL,
        metadata_name='index-v2.json',
        metadata_sha256=index_sha256,
        signature_types=(
            'x509-cert-sha256',
            'openpgp-primary',
            'openpgp-subkey',
        ),
    )


def update_fdroid_lock(
    *,
    output: Path,
    client_version_code: int,
    fpe_ota_version_code: int,
    fetcher: Fetcher = _fetch_https,
) -> ArtifactLockFile:
    """Resolve and atomically write one reviewed F-Droid module lock."""

    if client_version_code != CLIENT_VERSION_CODE:
        raise LockError(f'unsupported reviewed F-Droid client versionCode: {client_version_code}')
    if fpe_ota_version_code != FPE_VERSION_CODE:
        raise LockError(f'unsupported reviewed FPE OTA versionCode: {fpe_ota_version_code}')
    if output is None:
        raise LockError('F-Droid lock update requires an explicit --output path')

    try:
        with tempfile.TemporaryDirectory(prefix='fdroid-lock-update-') as temporary_name:
            temporary = Path(temporary_name)
            entry_jar = temporary / 'entry.jar'
            entry_json = temporary / 'entry.json'
            entry_signature = temporary / 'entry.json.asc'
            fetcher(ENTRY_JAR_URL, entry_jar, label='entry.jar', max_bytes=ENTRY_JAR_MAX_BYTES)
            fetcher(ENTRY_JSON_URL, entry_json, label='entry.json', max_bytes=ENTRY_MAX_BYTES)
            fetcher(
                ENTRY_SIGNATURE_URL,
                entry_signature,
                label='entry.json signature',
                max_bytes=SIGNATURE_MAX_BYTES,
            )
            embedded_entry = _verify_entry_jar(entry_jar)
            detached_entry = entry_json.read_bytes()
            if embedded_entry != detached_entry:
                raise LockError('embedded and detached F-Droid entry.json differ')

            gpg_home = temporary / 'gnupg'
            gpg_home.mkdir(mode=0o700)
            _verify_openpgp(entry_signature, entry_json, gpg_home)
            entry = _strict_json(detached_entry, label='F-Droid entry.json')
            index_url, index_size, index_sha256 = _index_reference(entry)

            index_path = temporary / 'index-v2.json'
            fetcher(
                index_url,
                index_path,
                label='index-v2.json',
                max_bytes=INDEX_MAX_BYTES,
                expected_size=index_size,
                expected_sha256=index_sha256,
            )
            index = _strict_json(index_path.read_bytes(), label='F-Droid index-v2.json')

            client_package, client_record = _version_record(
                index, CLIENT_PACKAGE, CLIENT_VERSION_CODE, CLIENT_VERSION_NAME
            )
            _ota_package, ota_record = _version_record(
                index, FPE_OTA_PACKAGE, FPE_VERSION_CODE, FPE_OTA_VERSION_NAME
            )
            fpe_package, fpe_record = _version_record(
                index, FPE_PACKAGE, FPE_VERSION_CODE, FPE_VERSION_NAME
            )
            client_url, client_size, client_sha256 = _file_record(
                client_record,
                'file',
                expected_name=f'/{CLIENT_PACKAGE}_{CLIENT_VERSION_CODE}.apk',
                expected_size=CLIENT_APK_SIZE,
                expected_sha256=CLIENT_APK_SHA256,
                label='F-Droid client APK',
            )
            client_source_url, client_source_size, client_source_sha256 = _file_record(
                client_record,
                'src',
                expected_name=f'/{CLIENT_PACKAGE}_{CLIENT_VERSION_CODE}_src.tar.gz',
                expected_size=CLIENT_SOURCE_SIZE,
                expected_sha256=CLIENT_SOURCE_SHA256,
                label='F-Droid client source',
            )
            ota_url, ota_size, ota_sha256 = _file_record(
                ota_record,
                'file',
                expected_name=f'/{FPE_OTA_PACKAGE}_{FPE_VERSION_CODE}.zip',
                expected_size=FPE_OTA_SIZE,
                expected_sha256=FPE_OTA_SHA256,
                label='FPE OTA',
            )
            fpe_file_url, fpe_size, fpe_sha256 = _file_record(
                fpe_record,
                'file',
                expected_name=f'/{FPE_PACKAGE}_{FPE_VERSION_CODE}.apk',
                expected_size=FPE_APK_SIZE,
                expected_sha256=FPE_APK_SHA256,
                label='FPE APK',
            )
            # The standalone APK is not fetched or injected.  Its signed record
            # authenticates the byte-identical member inside the OTA container.
            del fpe_file_url
            fpe_source_url, fpe_source_size, fpe_source_sha256 = _file_record(
                fpe_record,
                'src',
                expected_name=f'/{FPE_PACKAGE}_{FPE_VERSION_CODE}_src.tar.gz',
                expected_size=FPE_SOURCE_SIZE,
                expected_sha256=FPE_SOURCE_SHA256,
                label='FPE source',
            )

            paths = {
                'client': temporary / 'client.apk',
                'client-source': temporary / 'client-source.tar.gz',
                'ota': temporary / 'fpe-ota.zip',
                'fpe-source': temporary / 'fpe-source.tar.gz',
            }
            for url, path, label, size, digest in (
                (client_url, paths['client'], 'F-Droid client APK', client_size, client_sha256),
                (
                    client_source_url,
                    paths['client-source'],
                    'F-Droid client source',
                    client_source_size,
                    client_source_sha256,
                ),
                (ota_url, paths['ota'], 'FPE OTA', ota_size, ota_sha256),
                (
                    fpe_source_url,
                    paths['fpe-source'],
                    'FPE source',
                    fpe_source_size,
                    fpe_source_sha256,
                ),
            ):
                fetcher(
                    url,
                    path,
                    label=label,
                    max_bytes=ARTIFACT_MAX_BYTES,
                    expected_size=size,
                    expected_sha256=digest,
                )

            client_signer = _index_signer(client_package, client_record)
            client_identity = _apk_identity(
                paths['client'], CLIENT_PACKAGE, CLIENT_VERSION_CODE, client_signer
            )
            fpe_signer = _index_signer(fpe_package, fpe_record)

            ota_inspection = inspect_zip(
                paths['ota'],
                allowlisted_members=(FPE_APK_MEMBER, FPE_PERMISSION_MEMBER),
                limits=ArchiveLimits(
                    max_members=16,
                    max_member_size=32 * 1024 * 1024,
                    max_total_size=64 * 1024 * 1024,
                    max_expansion_ratio=20,
                    max_streamed_bytes=64 * 1024 * 1024,
                ),
            )
            if {member.name for member in ota_inspection.members} != FPE_OTA_LAYOUT:
                raise LockError('FPE OTA has an unreviewed archive layout')
            members = {member.name: member for member in ota_inspection.members}
            fpe_member = members[FPE_APK_MEMBER]
            permission_member = members[FPE_PERMISSION_MEMBER]
            if fpe_member.size != fpe_size or fpe_member.sha256 != fpe_sha256:
                raise LockError('FPE OTA nested APK differs from its signed index record')
            if (
                permission_member.size != 289
                or permission_member.sha256 != FPE_PERMISSION_SHA256
            ):
                raise LockError('FPE permission XML differs from the reviewed content')
            fpe_bytes = read_allowlisted_member(
                paths['ota'],
                FPE_APK_MEMBER,
                allowlisted_members=(FPE_APK_MEMBER, FPE_PERMISSION_MEMBER),
                limits=ArchiveLimits(
                    max_members=16,
                    max_member_size=32 * 1024 * 1024,
                    max_total_size=64 * 1024 * 1024,
                    max_expansion_ratio=20,
                    max_streamed_bytes=64 * 1024 * 1024,
                ),
            )
            nested_apk = temporary / 'F-DroidPrivilegedExtension.apk'
            nested_apk.write_bytes(fpe_bytes)
            fpe_identity = _apk_identity(
                nested_apk, FPE_PACKAGE, FPE_VERSION_CODE, fpe_signer
            )
            permission_xml = read_allowlisted_member(
                paths['ota'],
                FPE_PERMISSION_MEMBER,
                allowlisted_members=(FPE_APK_MEMBER, FPE_PERMISSION_MEMBER),
                limits=ArchiveLimits(
                    max_members=16,
                    max_member_size=32 * 1024 * 1024,
                    max_total_size=64 * 1024 * 1024,
                    max_expansion_ratio=20,
                    max_streamed_bytes=64 * 1024 * 1024,
                ),
            )
            _validate_permission_xml(permission_xml)

            verification = _source_verification(index_sha256)
            lock = ArtifactLockFile(
                schema_version=1,
                modules=(ModuleLock(
                    id=MODULE_ID,
                    version=f'fdroid-{CLIENT_VERSION_NAME}+fpe-{FPE_VERSION_NAME}',
                    artifacts=(
                        ArtifactLock(
                            id='fdroid-client-apk',
                            kind='apk',
                            immutable_url=client_url,
                            allowed_origins=(REPOSITORY_ORIGIN,),
                            version=CLIENT_VERSION_NAME,
                            size=client_size,
                            sha256=client_sha256,
                            apk=client_identity,
                            source_verification=verification,
                            source=ArtifactSource(
                                url='https://gitlab.com/fdroid/fdroidclient',
                                revision=CLIENT_VERSION_NAME,
                                corresponding_source_artifact='fdroid-client-source',
                            ),
                            legal=ArtifactLegal(
                                license='GPL-3.0-or-later',
                                source_offer_required=True,
                                allowed_output_scopes=LOCAL_ONLY_OUTPUT_SCOPES,
                            ),
                        ),
                        ArtifactLock(
                            id='fdroid-client-source',
                            kind='other',
                            role='corresponding-source',
                            immutable_url=client_source_url,
                            allowed_origins=(REPOSITORY_ORIGIN,),
                            version=CLIENT_VERSION_NAME,
                            size=client_source_size,
                            sha256=client_source_sha256,
                            source_verification=verification,
                            legal=ArtifactLegal(
                                license='GPL-3.0-or-later',
                                source_offer_required=False,
                                allowed_output_scopes=LOCAL_ONLY_OUTPUT_SCOPES,
                            ),
                        ),
                        ArtifactLock(
                            id='fdroid-privileged-extension-ota',
                            kind='zip',
                            immutable_url=ota_url,
                            allowed_origins=(REPOSITORY_ORIGIN,),
                            version=FPE_VERSION_NAME,
                            size=ota_size,
                            sha256=ota_sha256,
                            archive=ArchivePolicy(
                                members=(
                                    ArchiveMember(
                                        name=FPE_APK_MEMBER,
                                        size=fpe_member.size,
                                        sha256=fpe_member.sha256,
                                        apk=fpe_identity,
                                    ),
                                    ArchiveMember(
                                        name=FPE_PERMISSION_MEMBER,
                                        size=permission_member.size,
                                        sha256=permission_member.sha256,
                                    ),
                                ),
                                max_members=16,
                                max_member_size=32 * 1024 * 1024,
                                max_total_size=64 * 1024 * 1024,
                                max_expansion_ratio=20,
                                max_streamed_bytes=64 * 1024 * 1024,
                            ),
                            source_verification=verification,
                            source=ArtifactSource(
                                url='https://gitlab.com/fdroid/privileged-extension',
                                revision=FPE_VERSION_NAME,
                                corresponding_source_artifact=(
                                    'fdroid-privileged-extension-source'
                                ),
                            ),
                            legal=ArtifactLegal(
                                license='Apache-2.0',
                                source_offer_required=False,
                                allowed_output_scopes=LOCAL_ONLY_OUTPUT_SCOPES,
                            ),
                        ),
                        ArtifactLock(
                            id='fdroid-privileged-extension-source',
                            kind='other',
                            role='corresponding-source',
                            immutable_url=fpe_source_url,
                            allowed_origins=(REPOSITORY_ORIGIN,),
                            version=FPE_VERSION_NAME,
                            size=fpe_source_size,
                            sha256=fpe_source_sha256,
                            source_verification=verification,
                            legal=ArtifactLegal(
                                license='Apache-2.0',
                                source_offer_required=False,
                                allowed_output_scopes=LOCAL_ONLY_OUTPUT_SCOPES,
                            ),
                        ),
                    ),
                ),),
            )
            write_lock(output, lock)
            return lock
    except LockError:
        raise
    except (ArchiveError, OSError, ValueError) as error:
        raise LockError('F-Droid lock update failed closed') from error


__all__ = ('update_fdroid_lock',)
