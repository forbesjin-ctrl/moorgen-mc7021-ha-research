"""Community sample provenance tests contain synthetic input only."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('community_capture',ROOT/'tools/capture_mc7021_light.py')
capture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class CommunityProvenanceTests(unittest.TestCase):
    def test_direct_python_and_launcher_default_are_separate_household_samples(self):
        for flags in [[], ['--peer-owner']]:
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                replies=iter(['192.0.2.20','00000001-0000000000000001','q'])
                with mock.patch.object(capture,'OUTPUTS',Path(directory)), \
                     mock.patch('builtins.input',side_effect=lambda _:next(replies)), \
                     mock.patch.object(capture.subprocess,'run',side_effect=AssertionError('no tools')), \
                     mock.patch.object(capture.subprocess,'Popen',side_effect=AssertionError('no tools')), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(capture.main(['--demo']+flags),0)
                file=next((Path(directory)/'demo_runs').glob('DEMO_*/session.json'))
                data=json.loads(file.read_text())
                self.assertEqual(data['sample_origin'],'external_owner_household')
                self.assertFalse(data['project_household_verified'])
                self.assertTrue(data['simulation'])
                self.assertFalse((file.parent/'traffic.pcap').exists())


if __name__ == '__main__':
    unittest.main()
