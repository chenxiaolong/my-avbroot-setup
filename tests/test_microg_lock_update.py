import copy
import unittest
from tools.update_microg_lock import release_lock


class MicroGLockUpdateTest(unittest.TestCase):
    def metadata(self):
        release = 'v0.3.17.252432'
        return {'tag_name': release, 'draft': False, 'prerelease': False, 'assets': [
            {'name': name, 'size': 100, 'digest': 'sha256:' + 'a' * 64,
             'browser_download_url': f'https://github.com/microg/GmsCore/releases/download/{release}/{name}'}
            for name in ['com.android.vending-84022634.apk', 'com.google.android.gms-252432034.apk',
                         'com.google.android.gms-252432034-hw.apk']]}

    def test_only_standard_custom_rom_assets_selected(self):
        lock = release_lock('v0.3.17.252432', self.metadata())
        self.assertEqual(2, len(lock.modules[0].artifacts))
        self.assertTrue(all('-hw' not in a.immutable_url for a in lock.modules[0].artifacts))

    def test_ambiguous_or_untrusted_release_assets_fail(self):
        original = self.metadata()
        cases = []
        bad = copy.deepcopy(original); bad['assets'].append(bad['assets'][0]); cases.append(bad)
        bad = copy.deepcopy(original); bad['assets'][0]['browser_download_url'] = 'https://example.com/a.apk'; cases.append(bad)
        bad = copy.deepcopy(original); bad['assets'][0]['digest'] = None; cases.append(bad)
        bad = copy.deepcopy(original); bad['prerelease'] = True; cases.append(bad)
        for bad in cases:
            with self.subTest(metadata=bad), self.assertRaises(ValueError):
                release_lock('v0.3.17.252432', bad)
