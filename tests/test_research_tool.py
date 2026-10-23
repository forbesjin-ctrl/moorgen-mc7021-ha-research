"""Menu and post-capture hooks tested with local synthetic data and mocks."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import research_tool as menu
import demo_sample as demo
import capture_mc7021_light as capture


class MenuTests(unittest.TestCase):
    def test_complete_demo_requires_no_phone_or_subprocess(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(menu,'ROOT',Path(directory)), \
             mock.patch('subprocess.run',side_effect=AssertionError('no tools')), \
             mock.patch('subprocess.Popen',side_effect=AssertionError('no tools')), \
             mock.patch('socket.socket',side_effect=AssertionError('no network')), \
             mock.patch('webbrowser.open',side_effect=AssertionError('no browser')), \
             contextlib.redirect_stdout(io.StringIO()):
            # analyze_session uses its own default root: override the function
            # with an explicit temporary output destination, not repository data.
            original=menu.analyze_session
            with mock.patch.object(menu,'analyze_session',side_effect=lambda path,**kw:original(path,Path(directory)/'reports',**kw)):
                self.assertEqual(menu.main(['--demo','--no-open']),0)
            self.assertEqual(len(list((Path(directory)/'reports').glob('*/报告.html'))),1)

    def test_existing_sample_analysis_accepts_a_folder_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            sample=demo.create_demo_sample(root/'folder with spaces')
            original=menu.analyze_session
            with mock.patch.object(menu,'analyze_session',side_effect=lambda path:original(path,root/'reports')), \
                 mock.patch('builtins.input',side_effect=['3', "'{}'".format(sample)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(menu.main(['--no-open']),0)

    def test_menu_exit_never_starts_capture(self):
        with mock.patch('builtins.input',return_value='4'), \
             mock.patch.object(capture,'main',side_effect=AssertionError('no capture')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(menu.main([]),0)

    def test_menu_preflight_failure_does_not_start_capture(self):
        with mock.patch('builtins.input',return_value='1'), \
             mock.patch.object(capture.SystemBackend,'prepare',side_effect=capture.CaptureError('missing tool')), \
             mock.patch.object(capture,'main',side_effect=AssertionError('no capture')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(menu.main([]),1)

    def test_auto_analysis_happens_after_capture_has_cleaned_and_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            answers=iter(['192.0.2.20','00000001-0000000000000001','q'])
            seen=[]
            import analyze_capture
            def after(folder):
                import json
                saved=json.loads((folder/'session.json').read_text())
                self.assertTrue(saved['simulation'])
                self.assertNotEqual(saved['status'],'capturing')
                seen.append(saved['rvi_cleanup'])
                return folder, {'summary':{'frame_count':0,'device_count':0}}
            with mock.patch.object(capture,'OUTPUTS',Path(directory)), \
                 mock.patch('builtins.input',side_effect=lambda _:next(answers)), \
                 mock.patch.object(analyze_capture,'analyze_session',side_effect=after), \
                 mock.patch.object(menu,'show_report') as show, \
                 mock.patch('subprocess.run',side_effect=AssertionError('no tools')), \
                 mock.patch('subprocess.Popen',side_effect=AssertionError('no tools')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(capture.main(['--demo','--analyze-after']),0)
                self.assertTrue(seen)
                self.assertEqual(show.call_args.kwargs,{'open_browser':False})

    def test_public_launcher_exposes_menu_and_capture_retains_compatibility(self):
        self.assertIn('research_tool.py',(ROOT/'打开研究工具.command').read_text())
        self.assertIn('--analyze-after',(ROOT/'开始单灯采样.command').read_text())


if __name__ == '__main__':
    unittest.main()
