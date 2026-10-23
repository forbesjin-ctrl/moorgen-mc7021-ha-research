"""HTML rendering tests use synthetic values only; no captures or devices."""
import importlib.util
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('community_report_view', ROOT / 'tools/report_view.py')
view = importlib.util.module_from_spec(spec)
spec.loader.exec_module(view)


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def report_fixture(value='合成测试灯'):
    return {
        'schema_version': value, 'analysis_id': value, 'simulation': True,
        'source': {'file': value, 'size_bytes': 24},
        'quality': {'level': value, 'checks': [{'name': value, 'status': value, 'detail': value}],
                    'warnings': [value]},
        'summary': {'packet_count': 3, 'target_packet_count': 2, 'payload_packets': 2,
                    'frame_count': 2, 'device_count': 1},
        'events': [{'step': value, 'ready_at': value, 'confirmed_at': value,
                    'window_end': value, 'physical_light': value, 'app_display': value,
                    'packet_count': 2, 'frame_indices': [0, 1], 'command_count': 1,
                    'state_count': 1, 'ack_count': 0, 'execution_response_count': 2,
                    'status': value}],
        'flows': [{'id': value, 'transport': value, 'direction': value, 'src': value,
                   'dst': value, 'sport': value, 'dport': value, 'payload_bytes': 68,
                   'frame_count': 2, 'issues': [value], 'payload_classification': value}],
        'frames': [{'index': 0, 'flow_id': value, 'packet_indices': [0, 1],
                    'timestamp_start': value, 'timestamp_end': value, 'direction': value,
                    'kind': value, 'device_identifiers': [value], 'command': value,
                    'states': [{'raw_state': 1, 'untrusted': value}]}],
        'device_candidates': [{'identifier_hex': value, 'command_on_count': 1,
                               'command_off_count': 1, 'state_record_count': 1,
                               'panel_state_windows': [value], 'reopen_state_windows': [value],
                               'ordinary_light_verified': False}],
        'readiness': {'can_start_live_ha': False,
                      'gates': [{'name': value, 'status': value, 'detail': value}]},
        'unknowns': [value], 'next_actions': [value],
    }


class ReportViewTests(unittest.TestCase):
    def test_complete_chinese_utf8_document(self):
        html = view.render_report(report_fixture())
        self.assertTrue(html.startswith('<!doctype html>'))
        self.assertTrue(html.endswith('</html>'))
        self.assertIn('lang="zh-CN"', html)
        self.assertIn('charset="utf-8"', html)
        for label in ['私有报告，不上传', '合成测试灯', '单灯动作时间线', '样本质量',
                      '设备候选与状态线索', '协议帧证据索引', '证据缺口与下一步']:
            self.assertIn(label, html)
        self.assertEqual(html.encode('utf-8').decode('utf-8'), html)

    def test_all_dynamic_text_is_escaped(self):
        payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>&\'bad'
        html = view.render_report(report_fixture(payload))
        self.assertNotIn(payload, html)
        self.assertIn(escape(payload, quote=True), html)
        tags = Tags()
        tags.feed(html)
        self.assertNotIn('img', [tag for tag, _ in tags.tags])
        self.assertNotIn('script', [tag for tag, _ in tags.tags])
        self.assertFalse(any(key.startswith('on') for _, attrs in tags.tags for key in attrs))

    def test_self_contained_no_scripts_assets_forms_or_remote_urls(self):
        html = view.render_report(report_fixture())
        tags = Tags()
        tags.feed(html)
        forbidden = {'script', 'link', 'iframe', 'img', 'video', 'audio', 'object', 'embed', 'form'}
        self.assertFalse(forbidden & {tag for tag, _ in tags.tags})
        for _, attrs in tags.tags:
            self.assertNotIn('src', attrs)
            self.assertNotIn('action', attrs)
            if 'href' in attrs:
                self.assertTrue(attrs['href'].startswith('#'))
        for text in ['http://', 'https://', '@import', 'url(', 'fetch(', 'XMLHttpRequest', 'WebSocket']:
            self.assertNotIn(text, html)
        self.assertIn('default-src \'none\'', html)
        self.assertIn('form-action \'none\'', html)

    def test_hostile_link_is_text_not_navigation(self):
        payload = 'javascript:alert(1)'
        html = view.render_report(report_fixture(payload))
        self.assertIn(payload, html)
        tags = Tags()
        tags.feed(html)
        self.assertFalse(any(payload in value for _, attrs in tags.tags
                             for value in attrs.values() if value))

    def test_simulation_is_prominent_and_real_sample_not_mislabeled(self):
        report = report_fixture()
        html = view.render_report(report)
        self.assertIn('合成演练报告 · 不是住户实际通信', html)
        self.assertLess(html.index('合成演练报告'), html.index('原始包数'))
        report['simulation'] = False
        html = view.render_report(report)
        self.assertNotIn('合成演练报告 · 不是住户实际通信', html)
        self.assertIn('Home Assistant 接入：待人工验证', html)

    def test_missing_and_malformed_optional_data_do_not_look_successful(self):
        for report in [{}, None, {'quality': None, 'events': [None], 'frames': [None],
                                 'flows': 'wrong', 'device_candidates': [None],
                                 'readiness': {'gates': [None]}, 'summary': None}]:
            with self.subTest(report=report):
                html = view.render_report(report)
                self.assertIn('未知', html)
                self.assertIn('样本是否为合成演练：未知', html)
                self.assertIn('Home Assistant 接入：待人工验证', html)
                self.assertNotIn('badge ok', html)

    def test_live_ha_input_flag_cannot_approve_live_control(self):
        report = report_fixture()
        report['simulation'] = False
        report['readiness'] = {'can_start_live_ha': True,
                               'gates': [{'name': '合成门槛', 'status': 'pass', 'detail': '测试'}]}
        report['quality']['level'] = 'pass'
        html = view.render_report(report)
        self.assertIn('Home Assistant 接入：待人工验证', html)
        self.assertIn('本报告不批准实时控制', html)
        self.assertNotIn('Home Assistant 接入：通过', html)

    def test_frame_state_and_source_values_are_preserved_in_native_details(self):
        html = view.render_report(report_fixture())
        self.assertIn('<details>', html)
        self.assertIn('查看本帧原始分析字段', html)
        self.assertIn('&quot;raw_state&quot;: 1', html)
        self.assertIn('&quot;size_bytes&quot;: 24', html)
        self.assertIn('时间邻近仅供关联', html)
        self.assertIn('ACK 不是状态反馈', html)

    def test_render_is_pure_and_deterministic(self):
        report = report_fixture()
        original = repr(report)
        first = view.render_report(report)
        self.assertEqual(first, view.render_report(report))
        self.assertEqual(original, repr(report))

    def test_status_labels_match_analyzer_without_implying_compatibility(self):
        report = report_fixture()
        report['quality']['level'] = 'reviewable'
        report['quality']['checks'][0]['status'] = 'limited'
        report['events'][0]['status'] = 'recorded'
        report['readiness']['gates'][0]['status'] = 'candidate'
        html = view.render_report(report)
        for label in ['可供人工离线复核', '存在限制', '记录完整', '候选']:
            self.assertIn(label, html)
        self.assertIn('Home Assistant 接入：待人工验证', html)

    def test_execution_response_and_ack_counts_are_separate(self):
        html = view.render_report(report_fixture())
        self.assertIn('执行应答：2 · ACK：0', html)

    def test_operator_declaration_is_not_verification(self):
        report = report_fixture()
        report['device_candidates'][0]['ordinary_light_context'] = 'operator_declared'
        html = view.render_report(report)
        self.assertIn('人工声明，尚未验证', html)
        self.assertNotIn('输入标记：普通灯已确认', html)


if __name__ == '__main__':
    unittest.main()
