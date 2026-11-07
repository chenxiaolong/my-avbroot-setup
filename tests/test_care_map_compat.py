# SPDX-FileCopyrightText: 2026 PixeneOS contributors
# SPDX-License-Identifier: GPL-3.0-only

"""Runtime care-map identity guard: exercise real protobuf and ZIP structures."""

from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

from lib import care_map_compat


STOCK = (
    'Sony/XQ-DC72/XQ-DC72:15/68.2.A.3.107/'
    '068002A003010700521798587:user/release-keys'
)
AVB_ONLY = (
    'Sony/lineage_pdx235/pdx235:16/BP4A.251205.006/'
    '9d767828e9:userdebug/release-keys'
)


def _varint(number: int) -> bytes:
    encoded = bytearray()
    while number > 127:
        encoded.append((number & 127) | 128)
        number >>= 7
    return bytes(encoded + bytes([number]))


def _field(number: int, data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    return _varint(number * 8 + 2) + _varint(len(data)) + data


def _partition(
    name: str,
    *,
    fingerprint: str = STOCK,
    ranges: str = '2,0,472',
    property_id: str | None = None,
) -> bytes:
    return b''.join((
        _field(1, name),
        _field(2, ranges),
        _field(3, property_id if property_id is not None
               else f'ro.{name}.build.fingerprint'),
        _field(4, fingerprint),
    ))


def _map(*records: bytes) -> bytes:
    return b''.join(_field(1, record) for record in records)


class SourceFingerprintIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.source = self.root / 'signed-source.zip'
        self.output = self.root / 'regenerated-output.zip'
        self._zip(
            self.source,
            _map(_partition('odm'), _partition('product', ranges='4,0,46,511,600')),
        )

    @staticmethod
    def _zip(path: Path, map_value: bytes | None) -> None:
        with zipfile.ZipFile(path, 'w') as archive:
            if map_value is not None:
                archive.writestr('care_map.pb', map_value)

    def _require_failure(self, pattern: str) -> None:
        with self.assertRaisesRegex(RuntimeError, pattern):
            care_map_compat.verify_fingerprint_identity_preserved(
                self.source, self.output,
            )

    def test_identical_runtime_fingerprints_allow_different_ranges_and_order(self):
        # Sparse source vs complete rebuilt ranges are not blindly equated.
        self._zip(self.output, _map(
            _partition('product', ranges='2,0,616103'),
            _partition('odm', ranges='2,0,472'),
        ))
        care_map_compat.verify_fingerprint_identity_preserved(
            self.source, self.output,
        )

    def test_avb_derived_fingerprint_rejected(self):
        self._zip(self.output, _map(
            _partition('odm', fingerprint=AVB_ONLY),
            _partition('product', fingerprint=STOCK),
        ))
        self._require_failure('runtime fingerprint identity.*odm')

    def test_avb_derived_fingerprints_on_all_partitions_rejected(self):
        self._zip(self.output, _map(
            _partition('odm', fingerprint=AVB_ONLY),
            _partition('product', fingerprint=AVB_ONLY),
        ))
        self._require_failure('runtime fingerprint identity.*odm, product')

    def test_missing_or_added_partition_rejected(self):
        self._zip(self.output, _map(_partition('odm')))
        self._require_failure('runtime fingerprint identity.*product')
        self._zip(self.output, _map(
            _partition('odm'), _partition('product'), _partition('system'),
        ))
        self._require_failure('runtime fingerprint identity.*system')

    def test_conflicting_property_id_rejected(self):
        self._zip(self.output, _map(
            _partition('odm'),
            _partition('product', property_id='ro.system.build.fingerprint'),
        ))
        self._require_failure('unexpected care_map fingerprint property ID')

    def test_empty_runtime_fingerprint_rejected(self):
        self._zip(self.output, _map(
            _partition('odm'),
            _partition('product', fingerprint=''),
        ))
        self._require_failure('invalid care_map fingerprint')

    def test_duplicate_caremap_partitions_rejected(self):
        self._zip(self.output, _map(
            _partition('odm'),
            _partition('product'),
            _partition('product'),
        ))
        self._require_failure('duplicate care_map partition name')

    def test_duplicate_partition_field_rejected(self):
        malformed = _partition('odm') + _field(4, STOCK)
        self._zip(self.output, _map(malformed, _partition('product')))
        self._require_failure('duplicate care_map partition field')

    def test_unexpected_top_level_field_rejected(self):
        self._zip(self.output, _map(_partition('odm')) + _field(2, b'ignored'))
        self._require_failure('unexpected top-level care_map field')

    def test_truncated_protobuf_rejected(self):
        self._zip(self.output, b'\x0a\xff\xff\x7f')
        self._require_failure('outside data')

    def test_missing_empty_or_duplicate_zip_entry_rejected(self):
        self._zip(self.output, None)
        self._require_failure('exactly one bounded, nonempty care_map.pb')
        self._zip(self.output, b'')
        self._require_failure('exactly one bounded, nonempty care_map.pb')
        self._zip(self.output, _map(_partition('odm'), _partition('product')))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.output, 'a') as archive:
                archive.writestr('care_map.pb', b'duplicate')
        self._require_failure('exactly one bounded, nonempty care_map.pb')

    def test_oversized_source_map_rejected(self):
        self._zip(self.source, b'a' * (1024 * 1024 + 1))
        self._zip(self.output, _map(_partition('odm'), _partition('product')))
        self._require_failure('bounded, nonempty care_map.pb')

    def test_missing_source_map_rejected(self):
        self._zip(self.source, None)
        self._zip(self.output, _map(_partition('odm'), _partition('product')))
        self._require_failure('exactly one bounded, nonempty care_map.pb')

    def test_nonascending_ranges_rejected(self):
        self._zip(self.output, _map(
            _partition('odm'),
            _partition('product', ranges='4,0,46,33,55'),
        ))
        self._require_failure('block-range extent')

    def test_wrong_range_count_rejected(self):
        self._zip(self.output, _map(
            _partition('odm'),
            _partition('product', ranges='3,0,46,48'),
        ))
        self._require_failure('block-range count')

    def test_non_zipped_output_rejected(self):
        self.output.write_bytes(b'not-a-zip')
        self._require_failure('cannot establish care_map.pb')

    def test_intact_source_is_read_only(self):
        data = self.source.read_bytes()
        self._zip(self.output, _map(_partition('odm'), _partition('product')))
        care_map_compat.verify_fingerprint_identity_preserved(
            self.source, self.output,
        )
        self.assertEqual(data, self.source.read_bytes())


if __name__ == '__main__':
    unittest.main()
