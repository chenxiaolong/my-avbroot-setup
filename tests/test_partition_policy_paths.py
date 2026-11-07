# SPDX-License-Identifier: GPL-3.0-only
"""Policy writes target filesystem roots exposed by real split-partition images."""
from pathlib import Path
import tempfile
import unittest
import zipfile

from lib import modules


class ImageFilesystem:
    def __init__(self, tree):
        self.tree = tree

    def open(self, path, mode):
        return (self.tree / str(path).lstrip('/')).open(mode)


class PartitionPolicyPathsTest(unittest.TestCase):
    def test_split_images_receive_seapp_and_persistent_cil_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            images = {}
            for name in ('system','vendor','odm'):
                tree = root/name
                base = tree/'system' if name == 'system' else tree
                (base/'etc/selinux').mkdir(parents=True)
                label = 'plat' if name == 'system' else name
                (base/f'etc/selinux/{label}_seapp_contexts').write_bytes(b'original\n')
                (base/f'etc/selinux/{name}_sepolicy.cil').write_text('; original\n')
                images[name] = ImageFilesystem(tree)
            archive = root/'module.zip'
            with zipfile.ZipFile(archive,'w') as output:
                output.writestr('seapp_contexts', b'user=_app isPrivApp=true name=com.chiller3.msd domain=msd_app type=app_data_file levelFrom=all')
            with zipfile.ZipFile(archive) as source:
                modules.append_seapp_contexts(source,'seapp_contexts',images,True)
            # Android loads these files together; module selectors must occur once.
            combined = b''
            for name in images:
                base = images[name].tree/'system' if name == 'system' else images[name].tree
                label = 'plat' if name == 'system' else name
                contexts = (base/f'etc/selinux/{label}_seapp_contexts').read_bytes()
                combined += contexts
                if name == 'system':
                    self.assertIn(b'name=com.chiller3.msd', contexts)
                else:
                    self.assertEqual(b'original\n', contexts)
                rules = ['(allow example example (file (read)))']
                modules.patch_partition_cil_policy(images,name,rules,'; test rule')
                modules.patch_partition_cil_policy(images,name,rules,'; test rule')
                self.assertEqual(1,(base/f'etc/selinux/{name}_sepolicy.cil').read_text().count('; test rule'))

            self.assertEqual(1, combined.count(b'name=com.chiller3.msd'))

    def test_noncompatible_mode_needs_only_platform_contexts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            contexts = root/'system/etc/selinux/plat_seapp_contexts'
            contexts.parent.mkdir(parents=True)
            contexts.write_bytes(b'original\n')
            archive = root/'module.zip'
            rule = b'user=_app isPrivApp=true name=com.chiller3.custota domain=custota_app'
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr('seapp_contexts', rule)
            with zipfile.ZipFile(archive) as source:
                modules.append_seapp_contexts(
                    source, 'seapp_contexts', {'system': ImageFilesystem(root)}, False
                )
            self.assertEqual(b'original\n' + rule + b'\n', contexts.read_bytes())
