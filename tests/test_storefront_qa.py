import csv
import hashlib
import io
import json
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import storefront_qa as qa


HTML = b"""<!doctype html><html><head>
<title>Springfield Systems</title>
<link rel="canonical" href="https://example.com/">
<meta name="robots" content="index, follow">
<script type="application/ld+json">{"@type":"Organization"}</script>
<link rel="stylesheet" href="/assets/site.css">
</head><body><main id="content" class="page"><h1>Public QA</h1></main></body></html>"""


def valid_config():
    return {
        "domain": "example.com",
        "timeout_seconds": 5,
        "max_response_bytes": 100000,
        "urls": [{"id": "home", "url": "https://example.com/"}],
        "checks": [
            {"id": "status", "url": "home", "type": "status", "expected": 200},
            {"id": "title", "url": "home", "type": "title", "expected": "Springfield Systems"},
            {"id": "canonical", "url": "home", "type": "canonical", "expected": "https://example.com/"},
            {"id": "robots", "url": "home", "type": "robots-indexability", "expected": "indexable"},
            {"id": "schema", "url": "home", "type": "structured-data-presence", "expected": "present"},
            {"id": "copy", "url": "home", "type": "text", "value": "Public QA", "expected": "present"},
            {"id": "selector", "url": "home", "type": "selector", "value": "main#content.page", "expected": "present"},
            {"id": "asset", "url": "home", "type": "asset-reference", "value": "https://example.com/assets/site.css", "expected": "present"},
        ],
    }


class ConfigSafetyTests(unittest.TestCase):
    def test_accepts_bounded_same_domain_config(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        self.assertEqual(cfg["domain"], "example.com")

    def test_rejects_more_than_six_urls_or_twenty_checks(self):
        cfg = valid_config()
        cfg["urls"] = [{"id": f"p{i}", "url": f"https://example.com/{i}"} for i in range(7)]
        with self.assertRaisesRegex(qa.ConfigError, "at most 6"):
            qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        cfg = valid_config()
        cfg["checks"] = [dict(cfg["checks"][0], id=f"c{i}") for i in range(21)]
        with self.assertRaisesRegex(qa.ConfigError, "at most 20"):
            qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])

    def test_rejects_cross_domain_credentials_queries_private_and_local(self):
        unsafe = [
            "https://other.example/",
            "https://user:pass@example.com/",
            "https://example.com/?token=secret",
            "http://127.0.0.1/",
            "http://localhost/",
        ]
        for url in unsafe:
            cfg = valid_config()
            cfg["urls"][0]["url"] = url
            with self.subTest(url=url), self.assertRaises(qa.ConfigError):
                qa.validate_config(cfg, resolver=lambda host: ["127.0.0.1"] if host in {"localhost", "127.0.0.1"} else ["93.184.216.34"])

    def test_rejects_public_hostname_resolving_to_private_ip(self):
        with self.assertRaisesRegex(qa.ConfigError, "public IP"):
            qa.validate_config(valid_config(), resolver=lambda _host: ["10.0.0.8"])

    def test_rejects_multicast_reserved_unspecified_and_non_unicast(self):
        for address in ("224.0.0.1", "240.0.0.1", "0.0.0.0", "255.255.255.255", "ff02::1", "2001:db8::1"):
            with self.subTest(address=address), self.assertRaises(qa.ConfigError):
                qa.validate_config(valid_config(), resolver=lambda _host, address=address: [address])

    def test_rejects_account_cart_and_checkout_routes(self):
        for path in (
            "/account",
            "/cart",
            "/shop/checkout",
            "/%63heckout",
            "/%2563heckout",
            "/%252563heckout",
            "/shop%252fcheckout",
            "/%EF%BD%83heckout",
            "/shop;checkout/x",
            "/shop\\checkout",
            "/%3Ftoken=hidden",
            "/%2523fragment",
            "/%FFcheckout",
        ):
            cfg = valid_config()
            cfg["urls"][0]["url"] = f"https://example.com{path}"
            with self.subTest(path=path), self.assertRaises(qa.ConfigError):
                qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])

    def test_rejects_empty_query_and_fragment_delimiters(self):
        for suffix in ("?", "#"):
            cfg = valid_config()
            cfg["urls"][0]["url"] = "https://example.com/" + suffix
            with self.subTest(suffix=suffix), self.assertRaises(qa.ConfigError):
                qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])

    def test_rejected_secret_url_is_never_echoed(self):
        secret = "DO_NOT_ECHO_123"
        cfg = valid_config()
        cfg["urls"][0]["url"] = f"https://user:{secret}@example.com/?token={secret}"
        with self.assertRaises(qa.ConfigError) as caught:
            qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        self.assertNotIn(secret, str(caught.exception))

    def test_rejects_unknown_check_and_unbounded_transport_options(self):
        cfg = valid_config()
        cfg["checks"][0]["type"] = "javascript"
        with self.assertRaisesRegex(qa.ConfigError, "unsupported"):
            qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        cfg = valid_config()
        cfg["timeout_seconds"] = 90
        with self.assertRaisesRegex(qa.ConfigError, "timeout_seconds"):
            qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])

    def test_rejects_config_strings_that_cannot_round_trip_through_artifacts(self):
        cases = []
        cfg = valid_config()
        cfg["checks"][1]["expected"] = "x" * (qa.MAX_CONFIG_VALUE_CHARS + 1)
        cases.append(cfg)
        cfg = valid_config()
        cfg["checks"][5]["value"] = "x" * (qa.MAX_CONFIG_VALUE_CHARS + 1)
        cases.append(cfg)
        cfg = valid_config()
        cfg["urls"][0]["url"] = "https://example.com/" + "x" * qa.MAX_URL_CHARS
        cases.append(cfg)
        for cfg in cases:
            with self.subTest(), self.assertRaisesRegex(qa.ConfigError, "too long"):
                qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])

    def test_rejects_escaped_lone_surrogate_as_invalid_unicode(self):
        with self.assertRaisesRegex(qa.ConfigError, "Unicode"):
            qa._strict_json_object(b'{"value":"\\ud800"}', "config")

    def test_pathological_json_numbers_and_depth_fail_as_config_errors(self):
        huge_integer = b'{"value":' + (b"9" * 5_000) + b"}"
        deeply_nested = b'{"value":' + (b"[" * 1_500) + b"0" + (b"]" * 1_500) + b"}"
        for payload in (huge_integer, deeply_nested):
            with self.subTest(size=len(payload)), self.assertRaises(qa.ConfigError):
                qa._strict_json_object(payload, "config")

    def test_unicode_scalar_validation_is_iterative(self):
        value = "safe"
        for _ in range(2_000):
            value = [value]
        qa._validate_unicode_scalar_strings(value, "config")

    def test_bad_json_value_types_fail_as_config_errors(self):
        cases = []
        cfg = valid_config()
        cfg["checks"][0]["url"] = []
        cases.append(cfg)
        cfg = valid_config()
        cfg["checks"][0]["type"] = []
        cases.append(cfg)
        cfg = valid_config()
        cfg["checks"][4]["expected"] = []
        cases.append(cfg)
        for cfg in cases:
            with self.subTest(), self.assertRaises(qa.ConfigError):
                qa.validate_config(cfg, check_dns=False)

    def test_missing_cli_arguments_exit_one_not_capture_exception_two(self):
        for command in ("baseline", "schedule-digest", "month-end-ledger"):
            stderr = io.StringIO()
            with self.subTest(command=command), mock.patch.object(
                sys, "argv", ["storefront_qa.py", command]
            ), redirect_stderr(stderr):
                self.assertEqual(qa.main(), 1)
            self.assertIn("error:", stderr.getvalue())

    def test_canonical_may_explicitly_expect_absence(self):
        cfg = valid_config()
        cfg["checks"][2]["expected"] = "absent"
        clean = qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        self.assertEqual(clean["checks"][2]["expected"], "absent")


class FetchSafetyTests(unittest.TestCase):
    def test_user_agent_uses_release_version(self):
        self.assertIn(f"/{qa.TOOL_VERSION} ", qa.USER_AGENT)

    def test_fetch_pins_the_single_validated_dns_answer_set(self):
        resolver_calls = []

        def resolver(_host):
            resolver_calls.append(True)
            return ["93.184.216.34"] if len(resolver_calls) == 1 else ["10.0.0.8"]

        page = qa.PageResult("https://example.com/", "https://example.com/", 200, {"content-type": "text/html"}, b"ok", None)
        with mock.patch.object(qa, "_fetch_chain_once", return_value=page) as transport:
            result = qa.fetch_page("https://example.com/", "example.com", 5, 1000, resolver=resolver)
        self.assertIsNone(result.error)
        self.assertEqual(len(resolver_calls), 1)
        self.assertEqual(transport.call_args.args[2], ("93.184.216.34",))

    def test_transient_get_is_retried_once_within_same_deadline(self):
        page = qa.PageResult("https://example.com/", "https://example.com/", 200, {"content-type": "text/html"}, b"ok", None)
        with mock.patch.object(qa, "_fetch_chain_once", side_effect=[qa.TransientFetchError("temporary"), page]) as transport:
            result = qa.fetch_page("https://example.com/", "example.com", 5, 1000, resolver=lambda _host: ["93.184.216.34"])
        self.assertIsNone(result.error)
        self.assertEqual(transport.call_count, 2)

    def test_final_transient_html_status_remains_observable_after_retry(self):
        def response():
            item = mock.Mock()
            item.status = 503
            item.getheaders.return_value = [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", "20"),
            ]
            item.read.side_effect = [b"<html>retry</html>", b""]
            return item

        connections = [(mock.Mock(), response()), (mock.Mock(), response())]
        with mock.patch.object(qa, "_open_pinned", side_effect=connections) as transport:
            result = qa.fetch_page(
                "https://example.com/", "example.com", 5, 1000,
                resolver=lambda _host: ["93.184.216.34"],
            )
        self.assertIsNone(result.error)
        self.assertEqual(result.status, 503)
        self.assertEqual(result.body, b"<html>retry</html>")
        self.assertEqual(transport.call_count, 2)

    def test_https_socket_connects_to_pinned_ip_but_uses_domain_sni(self):
        fake_socket = mock.Mock()
        fake_context = mock.Mock()
        fake_context.wrap_socket.return_value = fake_socket
        with mock.patch.object(qa.ssl, "create_default_context", return_value=fake_context), mock.patch.object(
            qa.socket, "create_connection", return_value=fake_socket
        ) as create_connection:
            connection = qa.PinnedHTTPSConnection("example.com", "93.184.216.34", 443, 5)
            connection.connect()
        self.assertEqual(create_connection.call_args.args[0], ("93.184.216.34", 443))
        fake_context.wrap_socket.assert_called_once_with(fake_socket, server_hostname="example.com")

    def test_bounded_reader_rejects_oversized_body(self):
        with self.assertRaisesRegex(qa.FetchError, "maximum"):
            qa.read_bounded(io.BytesIO(b"123456"), 5)

    def test_bounded_reader_enforces_total_deadline(self):
        class SlowStream:
            def read(self, _size):
                time.sleep(0.02)
                return b"x"

        with self.assertRaisesRegex(qa.FetchError, "deadline"):
            qa.read_bounded(SlowStream(), 10, deadline=time.monotonic() + 0.005)

    def test_exact_mime_parsing(self):
        self.assertEqual(qa.parse_content_type('Text/HTML; charset="utf-8"'), ("text/html", "utf-8"))
        self.assertEqual(qa.parse_content_type("text/htmlish"), ("text/htmlish", None))
        self.assertEqual(qa.parse_content_type(""), (None, None))

    def test_header_selected_codec_failure_falls_back_to_utf8_replacement(self):
        self.assertEqual(qa.decode_html(b"plain text", "text/html; charset=idna"), "plain text")

    def test_successful_header_codec_decode_cannot_emit_surrogates(self):
        decoded = qa.decode_html(b"\\ud800", "text/html; charset=unicode_escape")
        decoded.encode("utf-8")
        self.assertNotIn("\ud800", decoded)

    def test_unicode_request_path_is_percent_encoded_at_transport_seam(self):
        connection = mock.Mock()
        response = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(qa, "PinnedHTTPSConnection", return_value=connection):
            returned_connection, returned_response = qa._open_pinned(
                "https://example.com/cafÃ©", "example.com", ("93.184.216.34",),
                time.monotonic() + 1,
            )
        self.assertIs(returned_connection, connection)
        self.assertIs(returned_response, response)
        self.assertEqual(connection.request.call_args.args[:2], ("GET", "/caf%C3%A9"))

    def test_private_dns_rebinding_fails_closed(self):
        with self.assertRaisesRegex(qa.ConfigError, "public IP"):
            qa.fetch_page(
                "https://example.com/", "example.com", 5, 1000,
                resolver=lambda _host: ["10.0.0.8"],
            )

    def test_slow_response_headers_obey_wall_clock_deadline(self):
        class SlowHeaderConnection:
            def __init__(self):
                self.closed = False

            def getresponse(self):
                time.sleep(0.30)
                return object()

            def close(self):
                self.closed = True

        connection = SlowHeaderConnection()
        started = time.monotonic()
        with self.assertRaisesRegex(qa.TransientFetchError, "response headers"):
            qa._call_with_deadline(connection.getresponse, time.monotonic() + 0.03, connection, "response headers")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.15)
        self.assertTrue(connection.closed)

    def test_fetch_returns_near_configured_deadline_when_headers_trickle(self):
        class SlowHeaderConnection:
            sock = None

            def request(self, *_args, **_kwargs):
                return None

            def getresponse(self):
                time.sleep(0.30)
                return object()

            def close(self):
                return×^4ÒÚ$z{-®éÜj×6VÆ–æR"“ ¢ç'Vâ†&w2¢Fç2æ76W'Eöæ÷Eö6ÆÆVB‚¢fWF6‚æ76W'Eöæ÷Eö6ÆÆVB‚¢6VÆbæ76W'DfÇ6R†÷WBæW†—7G2‚’ ¢FVbFW7E÷66†VGVÆUö&÷VæE÷&W'Vå÷&V¦V7G5ö÷WGWEö–ç6–FU÷&W6öÇfVEöÖæ–fW7Eö'VæFÆR‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&VÅö'VæFÆRÂ66†VGVÆU÷F‚Â÷'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢Æ–5ö'VæFÆRÒ&ö÷Bò&Æ–2Ö'VæFÆR ¢Æ–5ö'VæFÆRæÖ¶F—"‚¢†Æ–5ö'VæFÆRò&&6VÆ–æRæ77b"’çw&—FUö'—FW2‚‡&VÅö'VæFÆRò&&6VÆ–æRæ77b"’ç&VEö'—FW2‚’¢†Æ–5ö'VæFÆRò&÷WGWBÖÖæ–fW7Bæ§6öâ"’çw&—FU÷FW‡B‚'7–ÖÆ–æ²Æ6V†öÆFW""ÂVæ6öF–æsÒ'WFbÓ‚"¢÷WBÒ&VÅö'VæFÆRò&æW7FVBÖ÷WGWB ¢&w2ÒæÖW76R€¢6öÖÖæCÒ'66†VGVÆVB×&W'Vâ"Â6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æSÖÆ–5ö'VæFÆRò&&6VÆ–æRæ77b"Â66†VGVÆS×66†VGVÆU÷F‚À¢v–æF÷sÒ'vVV²Ó"Â66†VGVÆVEöf÷#ÔæöæRÂ÷WCÖ÷WBÀ¢¢&VÅ÷&W6öÇfRÒF‚ç&W6öÇfP ¢FVbÖæ–fW7E÷7–ÖÆ–æµ÷&W6öÇfR‡F‚Â§&W6öÇfUö&w2Â¢§&W6öÇfUö·v&w2“ ¢–bF‚‡F‚’æ'6öÇWFR‚’ÓÒ†Æ–5ö'VæFÆRò&÷WGWBÖÖæ–fW7Bæ§6öâ"’æ'6öÇWFR‚“ ¢&WGW&â&VÅö'VæFÆRò&÷WGWBÖÖæ–fW7Bæ§6öâ ¢&WGW&â&VÅ÷&W6öÇfR‡F‚Â§&W6öÇfUö&w2Â¢§&W6öÇfUö·v&w2 ¢v—F‚Öö6²çF6‚æö&¦V7B‡Â&FFWF–ÖR"Âw&3ÖFFWF–ÖR’26Æö6²ÂÖö6²çF6‚æö&¦V7B€¢Â%÷&W6öÇfU÷v—F…öFVFÆ–æR ¢’2Fç2ÂÖö6²çF6‚æö&¦V7B‡Â&fWF6…÷vR"’2fWF6ƒ ¢6Æö6²ææ÷rç&WGW&å÷fÇVRÒFFWF–ÖRƒ##bÂrÂ‚Â"Â3ÂG¦–æfó×F–ÖW¦öæRçWF2¢v—F‚Öö6²çF6‚æö&¦V7B…F‚Â'&W6öÇfR"ÂWF÷7V3ÕG'VRÂ6–FUöVffV7CÖÖæ–fW7E÷7–ÖÆ–æµ÷&W6öÇfR“ ¢v—F‚6VÆbæ76W'E&—6W5&VvW‚‡ä6öæf–tW'&÷"Â&Æ–2F†R&6VÆ–æWÇfW&–f–VBÖæ–fW7B"“ ¢ç'Vâ†&w2¢Fç2æ76W'Eöæ÷Eö6ÆÆVB‚¢fWF6‚æ76W'Eöæ÷Eö6ÆÆVB‚¢6VÆbæ76W'DfÇ6R†÷WBæW†—7G2‚’ ¢FVbFW7E÷66†VGVÆUö&÷VæE÷&W'Våöf–Ç5ö&Vf÷&UöFç5÷VçF–Åö—G5÷v–æF÷uö÷Vç2‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â÷'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢&w2ÒæÖW76R€¢6öÖÖæCÒ'66†VGVÆVB×&W'Vâ"À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æSÖ&6VÆ–æUöF—"ò&&6VÆ–æRæ77b"À¢66†VGVÆS×66†VGVÆU÷F‚À¢v–æF÷sÒ'vVV²Ó"À¢66†VGVÆVEöf÷#ÔæöæRÀ¢÷WC×&ö÷Bò'FöòÖV&Ç’"À¢¢v—F‚Öö6²çF6‚æö&¦V7B‡Â&FFWF–ÖR"Âw&3ÖFFWF–ÖR’26Æö6²ÂÖö6²çF6‚æö&¦V7B€¢Â%÷&W6öÇfU÷v—F…öFVFÆ–æR ¢’2Fç2ÂÖö6²çF6‚æö&¦V7B‡Â&fWF6…÷vR"’2fWF6ƒ ¢6Æö6²ææ÷rç&WGW&å÷fÇVRÒFFWF–ÖRƒ##bÂrÂ‚ÂÂS’ÂS’ÂG¦–æfó×F–ÖW¦öæRçWF2¢v—F‚6VÆbæ76W'E&—6W5&VvW‚‡ä6öæf–tW'&÷"Â'v–æF÷r—2æ÷B÷Vâ"“ ¢ç'Vâ†&w2¢Fç2æ76W'Eöæ÷Eö6ÆÆVB‚¢fWF6‚æ76W'Eöæ÷Eö6ÆÆVB‚¢6VÆbæ76W'DfÇ6R†&w2æ÷WBæW†—7G2‚’ ¢FVbFW7E÷66†VGVÆUö&÷VæE÷&W'Vå÷W'6—7G5÷v–æF÷uöÆ–æVvUö–åöög&W6…ö'VæFÆR‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â÷'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢÷WBÒ&ö÷Bò&6GW&VB×vVV² ¢vRÒåvU&W7VÇB€¢&‡GG3¢òöW†×ÆRæ6öÒò"Â&‡GG3¢òöW†×ÆRæ6öÒò"Â#À¢²&6öçFVçB×G—R#¢'FW‡Bö‡FÖÃ²6†'6WC×WFbÓ‚'ÒÂ…DÔÂÂæöæRÀ¢¢&w2ÒæÖW76R€¢6öÖÖæCÒ'66†VGVÆVB×&W'Vâ"À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æSÖ&6VÆ–æUöF—"ò&&6VÆ–æRæ77b"À¢66†VGVÆS×66†VGVÆU÷F‚À¢v–æF÷sÒ'vVV²Ó"À¢66†VGVÆVEöf÷#ÔæöæRÀ¢÷WCÖ÷WBÀ¢¢v—F‚Öö6²çF6‚æö&¦V7B‡Â&FFWF–ÖR"Âw&3ÖFFWF–ÖR’26Æö6²ÂÖö6²çF6‚æö&¦V7B€¢Â%÷&W6öÇfU÷v—F…öFVFÆ–æR"Â&WGW&å÷fÇVSÒ‚#“2ãƒBã#bã3B"Â¢’ÂÖö6²çF6‚æö&¦V7B‡Â&fWF6…÷vR"Â&WGW&å÷fÇVS×vR“ ¢6Æö6²ææ÷rç&WGW&å÷fÇVRÒFFWF–ÖRƒ##bÂrÂ‚Â"Â3ÂG¦–æfó×F–ÖW¦öæRçWF2¢6VÆbæ76W'DWVÂ‡ç'Vâ†&w2’Â¢ÖWFFFÒ§6öâæÆöG2‚†÷WBò'&W'VâæÖWFæ§6öâ"’ç&VE÷FW‡B†Væ6öF–æsÒ'WFbÓ‚"’¢66†VGVÆRÒ§6öâæÆöG2‡66†VGVÆU÷F‚ç&VE÷FW‡B†Væ6öF–æsÒ'WFbÓ‚"’¢6VÆbæ76W'DWVÂ†ÖWFFF²'66†VGVÆU÷6†#Sb%ÒÂåö6æöæ–6Åö§6öå÷6†#Sb‡66†VGVÆR’¢6VÆbæ76W'DWVÂ†ÖWFFF²'v–æF÷uö–B%ÒÂ'vVV²Ó"¢6VÆbæ76W'DWVÂ†ÖWFFF²'66†VGVÆVEöf÷"%ÒÂ###bÓrÓ…C#££¢"¢6VÆbæ76W'DWVÂ†ÖWFFF²&6GW&VEöB%ÒÂ###bÓrÓ…C#£3£¢"¢ÆöFVBÒåöÆöE÷fW&–f–VEö6GW&R†÷WBò&÷WGWBÖÖæ–fW7Bæ§6öâ"Â'66†VGVÆVB×&W'Vâ"¢6VÆbæ76W'DWVÂ†ÆöFVBçv–æF÷uö–BÂ'vVV²Ó" ¢FVbFW7E÷v–æF÷uö6Æ÷6Uö65öV6…öfWF6…öæE÷7F÷5öÆFW%övWG2‡6VÆb“ ¢&rÒfÆ–Eö6öæf–r‚¢&u²'W&Ç2%ÒæVæB‡²&–B#¢&&÷WB"Â'W&Â#¢&‡GG3¢òöW†×ÆRæ6öÒö&÷WB'Ò¢6frÒçfÆ–FFUö6öæf–r‡&rÂ6†V6µöFç3ÔfÇ6R¢6Æ÷6W5öBÒFFWF–ÖRƒ##bÂrÂ‚Â2ÂG¦–æfó×F–ÖW¦öæRçWF2¢6Æö6²Ò—FW"…°¢FFWF–ÖRƒ##bÂrÂ‚Â"ÂS’ÂS’ÂG¦–æfó×F–ÖW¦öæRçWF2’À¢6Æ÷6W5öBÀ¢Ò¢vRÒåvU&W7VÇB€¢&‡GG3¢òöW†×ÆRæ6öÒò"Â&‡GG3¢òöW†×ÆRæ6öÒò"Â#À¢²&6öçFVçB×G—R#¢'FW‡Bö‡FÖÃ²6†'6WC×WFbÓ‚'ÒÂ…DÔÂÂæöæRÀ¢¢v—F‚Öö6²çF6‚æö&¦V7B‡Â&fWF6…÷vR"Â&WGW&å÷fÇVS×vR’2fWF6ƒ ¢v—F‚6VÆbæ76W'E&—6W5&VvW‚‡ä6öæf–tW'&÷"Â'v–æF÷r6Æ÷6VB"“ ¢åö6GW&U÷vW2€¢6frÂ6Æ÷6W5öCÖ6Æ÷6W5öBÂæ÷u÷&÷f–FW#ÖÆÖ&F¢æW‡B†6Æö6²’À¢¢6VÆbæ76W'DWVÂ†fWF6‚æ6ÆÅö6÷VçBÂ¢6VÆbæ76W'DWVÂ†fWF6‚æ6ÆÅö&w2æ&w5³%ÒÂã ¢FVbFW7E÷66†VGVÆUö&÷VæE÷&W'Vå÷&V6÷&G5÷G&ç6–VçEöFç5öf–ÇW&R‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â÷'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢÷WBÒ&ö÷Bò&Fç2×Væf–Æ&ÆR ¢&w2ÒæÖW76R€¢6öÖÖæCÒ'66†VGVÆVB×&W'Vâ"Â6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æSÖ&6VÆ–æUöF—"ò&&6VÆ–æRæ77b"Â66†VGVÆS×66†VGVÆU÷F‚À¢v–æF÷sÒ'vVV²Ó"Â66†VGVÆVEöf÷#ÔæöæRÂ÷WCÖ÷WBÀ¢¢v—F‚Öö6²çF6‚æö&¦V7B‡Â&FFWF–ÖR"Âw&3ÖFFWF–ÖR’26Æö6²ÂÖö6²çF6‚æö&¦V7B€¢Â%÷fÆ–FFUö†÷7EöFG&W76W2 ¢’2VvW%öFç2ÂÖö6²çF6‚æö&¦V7B€¢Â%÷&W6öÇfU÷v—F…öFVFÆ–æR"Â6–FUöVffV7C×åG&ç6–VçDfWF6„W'&÷"‚$Då2&W6öÇWF–öâf–ÆVB"¢“ ¢6Æö6²ææ÷rç&WGW&å÷fÇVRÒFFWF–ÖRƒ##bÂrÂ‚Â"Â3ÂG¦–æfó×F–ÖW¦öæRçWF2¢6VÆbæ76W'DWVÂ‡ç'Vâ†&w2’Â"¢VvW%öFç2æ76W'Eöæ÷Eö6ÆÆVB‚¢&V6÷&G2Òç&VEö77e÷&V6÷&G2†÷WBò'&W'Vâæ77b"¢6VÆbæ76W'DWVÂ‡&V6÷&G5³Õ²'7FGW2%ÒÂ%Täd”Ä$ÄR"¢6VÆbæ76W'D–â‚$Då2&W6öÇWF–öâf–ÆVB"Â&V6÷&G5³Õ²&Wf–FVæ6R%Ò ¢FVbFW7E÷¦W&õ÷G&ç6—F–öåöÆVFvW%ö†5ö†VFW%ööæÇ•ö77eöæE÷&V6—6Uöæõö6†ævUö6÷’‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢÷WBÒ&ö÷Bò&ÆVFvW" ¢ç'Vâ„æÖW76R€¢6öÖÖæCÒ&ÖöçF‚ÖVæBÖÆVFvW""À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æUöÖæ–fW7CÖ&6VÆ–æUöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"À¢66†VGVÆS×66†VGVÆU÷F‚À¢'VåöÖæ–fW7G3Õ·'VåöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"f÷"'VåöF—"–â'VåöF—'5ÒÀ¢÷WCÖ÷WBÀ¢’¢v—F‚†÷WBò&ÖöçF‚ÖVæBÖÆVFvW"æ77b"’æ÷Vâ†æWvÆ–æSÒ""ÂVæ6öF–æsÒ'WFbÓ‚"’2†æFÆS ¢6VÆbæ76W'DWVÂ†Æ—7B†77bäF–7E&VFW"††æFÆR’’ÂµÒ¢&W÷'BÒ†÷WBò&ÖöçF‚ÖVæBÖÆVFvW"æÖB"’ç&VE÷FW‡B†Væ6öF–æsÒ'WFbÓ‚"¢6VÆbæ76W'D–â‚$æòö'6W'fF–öâG&ç6—F–öç2vW&R&V6÷&FVBÖöærF†Rg&÷¦Vâ6†V6·27&÷72f÷W"6GW&W2â"Â&W÷'B¢6VÆbæ76W'Dæ÷D–â‚'F†RvV'6—FRF–Bæ÷B6†ævRâ"Â&W÷'Bæ66VföÆB‚’ ¢FVbFW7E÷Væf–Æ&–Æ—G•ö—5÷&V6÷&FVEööæ6UöæE÷&V6÷fW'•ö—5ö÷6V6öæE÷G&ç6—F–öâ‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢f÷"'VåöF—"ÂF–ÖW7F×ÂWf–FVæ6R–â€¢‡'VåöF—'5³ÒÂ###bÓrÓUC#££¢"Â'F–ÖV÷WBöæR"’À¢‡'VåöF—'5³%ÒÂ###bÓrÓ#%C#££¢"Â'F–ÖV÷WBGvò"’À¢“ ¢'VffW"Ò–òå7G&–æt”ò†æWvÆ–æSÒ""¢w&—FW"Ò77bäF–7Ew&—FW"†'VffW"Âf–VÆFæÖW3×ä55eôd”TÄE2ÂÆ–æWFW&Ö–æF÷#Ò%Æâ"¢w&—FW"çw&—FV†VFW"‚¢w&—FW"çw&—FW&÷r‡°¢'W&Â#¢&‡GG3¢òöW†×ÆRæ6öÒò"Â'F–ÖW7F×#¢F–ÖW7F×Â&6†V6²#¢'F—FÆR"À¢&W‡V7FVB#¢%7&–ævf–VÆB7—7FV×2"Â&ö'6W'fVB#¢'Væf–Æ&ÆR"À¢'7FGW2#¢%Täd”Ä$ÄR"Â&Wf–FVæ6R#¢Wf–FVæ6RÀ¢Ò¢6VÆbå÷&WÆ6U÷'Våö77eöæE÷&V†6‚‡'VåöF—"Â'VffW"ævWGfÇVR‚’¢÷WBÒ&ö÷Bò&ÆVFvW" ¢ç'Vâ„æÖW76R€¢6öÖÖæCÒ&ÖöçF‚ÖVæBÖÆVFvW""À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æUöÖæ–fW7CÖ&6VÆ–æUöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"À¢66†VGVÆS×66†VGVÆU÷F‚À¢'VåöÖæ–fW7G3Õ·'VåöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"f÷"'VåöF—"–â'VåöF—'5ÒÀ¢÷WCÖ÷WBÀ¢’¢v—F‚†÷WBò&ÖöçF‚ÖVæBÖÆVFvW"æ77b"’æ÷Vâ†æWvÆ–æSÒ""ÂVæ6öF–æsÒ'WFbÓ‚"’2†æFÆS ¢&÷w2ÒÆ—7B†77bäF–7E&VFW"††æFÆR’¢6VÆbæ76W'DWVÂ…·&÷u²&WfVçE÷G—R%Òf÷"&÷r–â&÷w5ÒÂ²$$T4ÔUõTäd”Ä$ÄR"Â$d”Ä$ÄUôt”â%Ò¢6VÆbæ76W'DWVÂ…·&÷u²''Vâ%Òf÷"&÷r–â&÷w5ÒÂ²'vVV²Ó""Â'vVV²ÓB%Ò ¢FVbFW7EöÆVFvW%÷fW&–f–W5÷6÷W&6UöÖ&¶F÷våöÖæ–fW7Eö†6…öæE÷W6W5÷¦W&õöæWGv÷&²‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢‡'VåöF—'5³Òò&W†6WF–öç2æÖB"’çw&—FU÷FW‡B‚'F×W&VB"ÂVæ6öF–æsÒ'WFbÓ‚"¢v—F‚Öö6²çF6‚æö&¦V7B‡Â%÷&W6öÇfU÷v—F…öFVFÆ–æR"’2Fç2ÂÖö6²çF6‚æö&¦V7B‡Â&fWF6…÷vR"’2fWF6ƒ ¢v—F‚6VÆbæ76W'E&—6W5&VvW‚‡ä6öæf–tW'&÷"Â&F–vW7B"“ ¢ç'Vâ„æÖW76R€¢6öÖÖæCÒ&ÖöçF‚ÖVæBÖÆVFvW""À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æUöÖæ–fW7CÖ&6VÆ–æUöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"À¢66†VGVÆS×66†VGVÆU÷F‚À¢'VåöÖæ–fW7G3Õ·'VåöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"f÷"'VåöF—"–â'VåöF—'5ÒÀ¢÷WC×&ö÷Bò&ÆVFvW""À¢’¢Fç2æ76W'Eöæ÷Eö6ÆÆVB‚¢fWF6‚æ76W'Eöæ÷Eö6ÆÆVB‚ ¢FVbFW7EöÆVFvW%÷7Fv–æuöf–ÇW&UöÆVfW5öæõö÷WGWEöF—&V7F÷'’‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢÷WBÒ&ö÷Bò&ÆVFvW" ¢v—F‚Öö6²çF6‚æö&¦V7B‡Â%÷w&—FUöÆVFvW%öÖ&¶F÷vâ"Â6–FUöVffV7CÔõ4W'&÷"‚&F—6²gVÆÂ"’“ ¢v—F‚6VÆbæ76W'E&—6W2„õ4W'&÷"“ ¢ç'Vâ„æÖW76R€¢6öÖÖæCÒ&ÖöçF‚ÖVæBÖÆVFvW""À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æUöÖæ–fW7CÖ&6VÆ–æUöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"À¢66†VGVÆS×66†VGVÆU÷F‚À¢'VåöÖæ–fW7G3Õ·'VåöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"f÷"'VåöF—"–â'VåöF—'5ÒÀ¢÷WCÖ÷WBÀ¢’¢6VÆbæ76W'DfÇ6R†÷WBæW†—7G2‚’ ¢FVbFW7EöÆVFvW%÷&V¦V7G5öGWÆ–6FUö§6öåö¶W—5ö&Vf÷&U÷W6–æu÷6÷W&6W2‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢–ÆöBÒ66†VGVÆU÷F‚ç&VE÷FW‡B†Væ6öF–æsÒ'WFbÓ‚"¢66†VGVÆU÷F‚çw&—FU÷FW‡B€¢–ÆöBç&WÆ6R‚r'W&–öEö–B#¢###bÓr"ÂrÂr'W&–öEö–B#¢'w&öær"Â'W&–öEö–B#¢###bÓr"ÂrÂ’À¢Væ6öF–æsÒ'WFbÓ‚"À¢¢v—F‚6VÆbæ76W'E&—6W5&VvW‚‡ä6öæf–tW'&÷"Â&GWÆ–6FR¥4ôâ¶W’"“ ¢ç'Vâ„æÖW76R€¢6öÖÖæCÒ&ÖöçF‚ÖVæBÖÆVFvW""À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æUöÖæ–fW7CÖ&6VÆ–æUöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"À¢66†VGVÆS×66†VGVÆU÷F‚À¢'VåöÖæ–fW7G3Õ·'VåöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"f÷"'VåöF—"–â'VåöF—'5ÒÀ¢÷WC×&ö÷Bò&ÆVFvW""À¢’ ¢FVbFW7EöÆVFvW%÷&V¦V7G5öÆVv7•÷66†VGVÆVE÷'Vå÷v—F†÷WE÷66†VGVÆUö&–æF–ær‡6VÆb“ ¢v—F‚FV×f–ÆRåFV×÷&'”F—&V7F÷'’‚’2F× ¢&ö÷BÒF‚‡F×¢6öæf–u÷F‚Â&6VÆ–æUöF—"Â66†VGVÆU÷F‚Â'VåöF—'2Ò6VÆbå÷w&—FUöÖöçF‚€¢&ö÷BÂ²%7&–ævf–VÆB7—7FV×2%Ò¢BÀ¢¢&rÒ§6öâæÆöG2†6öæf–u÷F‚ç&VE÷FW‡B†Væ6öF–æsÒ'WFbÓ‚"’¢6frÒçfÆ–FFUö6öæf–r‡&rÂ&W6öÇfW#ÖÆÖ&Fö†÷7C¢²#“2ãƒBã#bã3B%Ò¢ÆöFVBÒåöÆöEö&6VÆ–æR†&6VÆ–æUöF—"ò&&6VÆ–æRæ77b"Âæ6öæf–uöF–vW7B†6fr’¢ÆVv7’Ò&ö÷Bò&ÆVv7’×vVV² ¢&÷rÒä6†V6µ&W7VÇB€¢&‡GG3¢òöW†×ÆRæ6öÒò"Â###bÓrÓ…C#££¢"Â'F—FÆR"À¢%7&–ævf–VÆB7—7FV×2"Â%7&–ævf–VÆB7—7FV×2"Â%52"Â$…DÔÂF—FÆRVÆVÖVçB"À¢¢çw&—FU÷'Våö'F–f7G2†ÆVv7’Â'66†VGVÆVB×&W'Vâ"Â·&÷uÒÂ6frÂ&÷rçF–ÖW7F×ÂÆöFVB¢Öæ–fW7G2Ò¶ÆVv7’ò&÷WGWBÖÖæ–fW7Bæ§6öâ%Ò²°¢'VåöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"f÷"'VåöF—"–â'VåöF—'5³¥Ğ¢Ğ¢v—F‚6VÆbæ76W'E&—6W5&VvW‚‡ä6öæf–tW'&÷"Â'66†VGVÆRÖ&÷VæB"“ ¢ç'Vâ„æÖW76R€¢6öÖÖæCÒ&ÖöçF‚ÖVæBÖÆVFvW""À¢6öæf–sÖ6öæf–u÷F‚À¢&6VÆ–æUöÖæ–fW7CÖ&6VÆ–æUöF—"ò&÷WGWBÖÖæ–fW7Bæ§6öâ"À¢66†VGVÆS×66†VGVÆU÷F‚À¢'VåöÖæ–fW7G3ÖÖæ–fW7G2À¢÷WC×&ö÷Bò&ÆVFvW""À¢’  ¦–bõöæÖUõòÓÒ%õöÖ–åõò# ¢Væ—GFW7BæÖ–â‚ 