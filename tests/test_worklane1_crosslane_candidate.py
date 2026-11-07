# SPDX-FileCopyrightText: 2026 ModOS contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Ephemeral branch-only W1/W3 conformance gate. Never merge into production.

Run BOTH separately authored Worklane 3 candidate suites in required mode
against Worklane 1's standalone research adapter, without importing W3 oracle
inside the candidate. Synthetic evidence only, not an OTA verification.
"""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Worklane3RealCandidateIntegrationTest(unittest.TestCase):
    def test_independent_worklane3_suites_run_with_real_candidate_required(self):
        environment = os.environ.copy()
        environment['CARE_MAP_CONFORMANCE_REQUIRE_CANDIDATE'] = '1'
        environment['CARE_MAP_PROVENANCE_REQUIRED'] = '1'
        argv = f'{sys.executable} {ROOT / "research/care_map_candidate.py"} --json'
        environment['CARE_MAP_CANDIDATE_CMD'] = argv
        environment['CARE_MAP_PROVENANCE_CMD'] = argv
        result = subprocess.run(
            [sys.executable, '-m', 'unittest',
             'tests.test_care_map_candidate_contract',
             'tests.test_care_map_provenance_candidate_contract',
             '-v'],
            cwd=ROOT, env=environment, capture_output=True, text=True,
            timeout=180, check=False,
        )
        self.assertEqual(
            0, result.returncode,
            f'Worklane 3 REQUIRED candidate integration failed:\n'
            f'stdout:\n{result.stdout[-2500:]}\n'
            f'stderr:\n{result.stderr[-12000:]}'
        )
        self.assertIn('Ran 11 tests', result.stderr)
        self.assertNotIn('skipped', result.stderr.lower())

if __name__ == '__main__':
    unittest.main()
