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
                "https://example.com/café", "example.com", ("93.184.216.34",),
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
                return None

        started = time.monotonic()
        with mock.patch.object(qa, "PinnedHTTPSConnection", return_value=SlowHeaderConnection()):
            result = qa.fetch_page(
                "https://example.com/",
                "example.com",
                0.03,
                1000,
                resolver=lambda _host: ["93.184.216.34"],
            )
        elapsed = time.monotonic() - started
        self.assertIsNotNone(result.error)
        self.assertLess(elapsed, 0.15)


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.page = qa.PageResult(
            requested_url="https://example.com/",
            final_url="https://example.com/",
            status=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body=HTML,
            error=None,
        )

    def test_all_supported_checks_pass(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        rows = qa.evaluate(cfg, {"home": self.page}, "2026-08-14T12:00:00Z")
        self.assertEqual({row.status for row in rows}, {"PASS"})
        self.assertEqual(len(rows), 8)

    def test_fetch_failure_makes_checks_unavailable(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        page = qa.PageResult("https://example.com/", None, None, {}, b"", "timeout")
        rows = qa.evaluate(cfg, {"home": page}, "2026-08-14T12:00:00Z")
        self.assertEqual({row.status for row in rows}, {"UNAVAILABLE"})
        self.assertTrue(all("timeout" in row.evidence for row in rows))

    def test_rerun_compares_normalized_observation_to_baseline(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        baseline = qa.evaluate(cfg, {"home": self.page}, "2026-08-14T12:00:00Z")
        changed = self.page._replace(body=HTML.replace(b"Springfield Systems", b"Changed Title", 1))
        rows = qa.evaluate(cfg, {"home": changed}, "2026-08-14T13:00:00Z", baseline=qa.baseline_map(baseline))
        by_id = {row.check: row for row in rows}
        self.assertEqual(by_id["title"].status, "DRIFT")
        self.assertEqual(by_id["status"].status, "PASS")
        self.assertEqual(by_id["title"].expected, "Springfield Systems")

    def test_hidden_template_and_head_text_are_not_treated_as_page_text(self):
        body = b"<html><head><title>Hidden title</title></head><body><template>Needle</template><div hidden>Needle</div><div aria-hidden='true'>Needle</div><p>Shown</p></body></html>"
        page = self.page._replace(body=body)
        cfg = valid_config()
        cfg["checks"] = [{"id": "hidden", "url": "home", "type": "text", "value": "Needle", "expected": "absent"}]
        clean = qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        rows = qa.evaluate(clean, {"home": page}, "2026-08-14T12:00:00Z")
        self.assertEqual(rows[0].status, "PASS")

    def test_malformed_canonical_and_href_never_crash(self):
        body = b"<html><head><link rel='canonical' href='https://['></head><body><a href='https://['>x</a></body></html>"
        parser = qa.HTMLSnapshot("https://example.com/")
        parser.feed(body.decode())
        self.assertEqual(parser.canonical, "malformed")
        self.assertEqual(parser.references, set())

    def test_malformed_bounded_html_becomes_unavailable_instead_of_crashing(self):
        cfg = valid_config()
        cfg["checks"] = [cfg["checks"][1]]
        clean = qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        page = qa.PageResult(
            "https://example.com/", "https://example.com/", 200,
            {"content-type": "text/html"}, b"<![foo]>", None,
        )
        rows = qa.evaluate(clean, {"home": page}, "2026-08-14T12:00:00Z")
        self.assertEqual(rows[0].status, "UNAVAILABLE")
        self.assertEqual(rows[0].observed, "unavailable")

    def test_status_observation_does_not_depend_on_html_parsing(self):
        cfg = valid_config()
        cfg["checks"] = [cfg["checks"][0]]
        clean = qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        page = qa.PageResult(
            "https://example.com/", "https://example.com/", 200,
            {"content-type": "text/html"}, b"<![foo]>", None,
        )
        rows = qa.evaluate(clean, {"home": page}, "2026-08-14T12:00:00Z")
        self.assertEqual(rows[0].status, "PASS")
        self.assertEqual(rows[0].observed, "200")
        self.assertNotIn("foo", rows[0].evidence)


class ReportingTests(unittest.TestCase):
    def test_csv_formula_neutralization_is_lossless_and_collision_safe(self):
        values = ["=1+1", "+cmd", "-2", "@name", "\tcmd", "\rcmd", "\ncmd", "'=literal", "''already", "normal"]
        for value in values:
            encoded = qa.safe_csv_cell(value)
            self.assertNotIn(encoded[:1], {"=", "+", "-", "@", "\t", "\r", "\n"})
            self.assertEqual(qa.restore_csv_cell(encoded), value)

    def test_markdown_cells_escape_html_pipes_and_backslashes(self):
        rendered = qa.markdown_cell("<img src=x>|a\\b\nnext & end ![pixel](https://tracker.invalid) `code`")
        self.assertIn("&lt;img src=x&gt;", rendered)
        self.assertIn("\\|", rendered)
        self.assertIn("a\\\\b", rendered)
        self.assertIn("<br>", rendered)
        self.assertIn("&amp;", rendered)
        self.assertNotIn("![pixel](", rendered)
        self.assertIn("\\!\\[pixel\\]\\(", rendered)
        self.assertIn("\\`code\\`", rendered)

    def test_csv_and_markdown_contain_required_fields(self):
        row = qa.CheckResult(
            url="https://example.com/",
            timestamp="2026-08-14T12:00:00Z",
            check="title",
            expected="Expected",
            observed="Actual",
            status="DRIFT",
            evidence="HTML title element",
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            qa.write_csv(out / "baseline.csv", [row])
            qa.write_exceptions(out / "exceptions.md", [row])
            with (out / "baseline.csv").open(newline="", encoding="utf-8") as handle:
                parsed = list(csv.DictReader(handle))
            self.assertEqual(parsed[0]["status"], "DRIFT")
            report = (out / "exceptions.md").read_text(encoding="utf-8")
            for field in ["URL", "Timestamp", "Check", "Expected", "Observed", "Status", "Evidence"]:
                self.assertIn(field, report)

    def test_staged_pair_does_not_replace_old_outputs_when_second_write_fails(self):
        row = qa.CheckResult("https://example.com/", "2026-08-14T12:00:00Z", "title", "x", "x", "PASS", "ok")
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "baseline.csv").write_text("old csv", encoding="utf-8")
            (out / "exceptions.md").write_text("old md", encoding="utf-8")
            with mock.patch.object(qa, "write_exceptions", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    qa.write_run_artifacts(out, "baseline", [row], cfg, row.timestamp)
            self.assertEqual((out / "baseline.csv").read_text(encoding="utf-8"), "old csv")
            self.assertEqual((out / "exceptions.md").read_text(encoding="utf-8"), "old md")


class BaselineProvenanceTests(unittest.TestCase):
    def test_release_metadata_records_version_and_exact_baseline_lineage(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        baseline_row = qa.CheckResult("https://example.com/", "2026-08-14T12:00:00Z", "status", "200", "200", "PASS", "ok")
        rerun_row = baseline_row._replace(timestamp="2026-08-14T13:00:00Z")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            baseline_metadata = qa.write_run_artifacts(out, "baseline", [baseline_row], cfg, baseline_row.timestamp)
            baseline_manifest = json.loads((out / "output-manifest.json").read_text(encoding="utf-8"))
            baseline_digest = hashlib.sha256((out / "baseline.csv").read_bytes()).hexdigest()
            loaded = qa._load_baseline(out / "baseline.csv", qa.config_digest(cfg))

            self.assertEqual(baseline_metadata["tool_version"], qa.TOOL_VERSION)
            self.assertEqual(baseline_manifest["tool_version"], qa.TOOL_VERSION)
            self.assertEqual(loaded.csv_sha256, baseline_digest)
            self.assertEqual(loaded.captured_at, baseline_row.timestamp)

            rerun_metadata = qa.write_run_artifacts(
                out, "rerun", [rerun_row], cfg, rerun_row.timestamp, loaded
            )
            rerun_manifest = json.loads((out / "output-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(rerun_metadata["tool_version"], qa.TOOL_VERSION)
            self.assertEqual(rerun_metadata["baseline_csv_sha256"], baseline_digest)
            self.assertEqual(rerun_metadata["baseline_captured_at"], baseline_row.timestamp)
            self.assertEqual(rerun_manifest["tool_version"], qa.TOOL_VERSION)

    def test_rerun_artifacts_require_loaded_baseline_provenance(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        row = qa.CheckResult("https://example.com/", "2026-08-14T13:00:00Z", "status", "200", "200", "PASS", "ok")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(qa.ConfigError, "baseline provenance"):
                qa.write_run_artifacts(Path(tmp), "rerun", [row], cfg, row.timestamp)

    def test_baseline_is_bound_to_full_normalized_config_digest(self):
        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        row = qa.CheckResult("https://example.com/", "2026-08-14T12:00:00Z", "status", "200", "200", "PASS", "ok")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            qa.write_run_artifacts(out, "baseline", [row], cfg, row.timestamp)
            loaded = qa.load_baseline(out / "baseline.csv", qa.config_digest(cfg))
            self.assertEqual(loaded[(row.url, row.check)], "200")
            changed = dict(cfg)
            changed["timeout_seconds"] = 6.0
            with self.assertRaisesRegex(qa.ConfigError, "config digest"):
                qa.load_baseline(out / "baseline.csv", qa.config_digest(changed))

    def test_baseline_schema_status_and_timestamp_are_validated(self):
        qa.validate_timestamp("2026-08-14T12:00:00Z")
        with self.assertRaises(qa.ConfigError):
            qa.validate_timestamp("yesterday")
        with self.assertRaises(qa.ConfigError):
            qa.validate_baseline_records([{"url": "x", "timestamp": "yesterday", "check": "x", "expected": "x", "observed": "x", "status": "MAYBE", "evidence": "x"}])

    def test_scheduled_evidence_gate_cannot_be_time_traveled(self):
        baseline = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
        scheduled = datetime(2026, 8, 17, 12, tzinfo=timezone.utc)
        with self.assertRaisesRegex(qa.ConfigError, "not open"):
            qa.enforce_scheduled_evidence_gate(baseline, scheduled, datetime(2026, 8, 15, 12, tzinfo=timezone.utc), 72)
        qa.enforce_scheduled_evidence_gate(baseline, scheduled, datetime(2026, 8, 17, 12, tzinfo=timezone.utc), 72)

    def test_baseline_age_overflow_fails_as_a_config_error(self):
        extreme = qa.validate_timestamp("9999-12-31T23:59:59Z")
        with self.assertRaisesRegex(qa.ConfigError, "time range"):
            qa.enforce_scheduled_evidence_gate(extreme, extreme, extreme, 72)

        cfg = qa.validate_config(valid_config(), resolver=lambda _host: ["93.184.216.34"])
        row = qa.CheckResult(
            "https://example.com/", "9999-12-31T23:59:59Z", "status",
            "200", "200", "PASS", "HTTP GET returned 200",
        )
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(qa.ConfigError, "time range"):
            qa.write_run_artifacts(Path(tmp) / "baseline", "baseline", [row], cfg, row.timestamp)

    def test_legacy_baseline_seams_reject_duplicate_metadata_keys(self):
        raw = valid_config()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = qa.validate_config(raw, resolver=lambda _host: ["93.184.216.34"])
            row = qa.CheckResult(
                "https://example.com/", "2026-07-01T12:00:00Z", "status",
                "200", "200", "PASS", "HTTP GET returned 200",
            )
            qa.write_run_artifacts(root, "baseline", [row], cfg, row.timestamp)
            metadata_path = root / "baseline.meta.json"
            payload = metadata_path.read_text(encoding="utf-8")
            metadata_path.write_text(
                payload.replace('"mode": "baseline",', '"mode": "wrong", "mode": "baseline",', 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(qa.ConfigError, "duplicate JSON key"):
                qa._load_baseline(root / "baseline.csv", qa.config_digest(cfg))
            with self.assertRaisesRegex(qa.ConfigError, "duplicate JSON key"):
                qa._scheduled_preflight(
                    raw, root / "baseline.csv", "2026-07-04T12:00:00Z",
                    now=datetime(2026, 7, 4, 12, tzinfo=timezone.utc),
                )

    def test_premature_scheduled_run_performs_zero_dns_or_network_events(self):
        raw = valid_config()
        raw["scheduled_evidence_minimum_hours"] = 72
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            baseline_path = root / "baseline.csv"
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            baseline_path.write_text("not read before gate", encoding="utf-8")
            (root / "baseline.meta.json").write_text(
                json.dumps(
                    {
                        "schema": qa.BASELINE_SCHEMA,
                        "mode": "baseline",
                        "config_digest": "unused-before-gate",
                        "csv_sha256": "unused-before-gate",
                        "fields": qa.CSV_FIELDS,
                        "row_count": 1,
                        "captured_at": "2099-01-01T00:00:00Z",
                        "earliest_scheduled_evidence_at": "2099-01-04T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            args = Namespace(
                command="scheduled-rerun",
                config=config_path,
                baseline=baseline_path,
                out=root / "out",
                scheduled_for="2099-01-04T00:00:00Z",
            )
            with mock.patch.object(qa.socket, "getaddrinfo") as dns, mock.patch.object(qa, "_open_pinned") as network:
                with self.assertRaisesRegex(qa.ConfigError, "not open"):
                    qa.run(args)
            dns.assert_not_called()
            network.assert_not_called()
            self.assertFalse(args.out.exists())


class MonthEndLedgerTests(unittest.TestCase):
    def _write_month(self, root: Path, observations: list[str]):
        raw = valid_config()
        raw["checks"] = [raw["checks"][1]]
        config_path = root / "frozen.json"
        config_path.write_text(json.dumps(raw), encoding="utf-8")
        cfg = qa.validate_config(raw, resolver=lambda _host: ["93.184.216.34"])
        baseline_dir = root / "baseline"
        baseline_row = qa.CheckResult(
            "https://example.com/", "2026-07-01T12:00:00Z", "title",
            "Springfield Systems", "Springfield Systems", "PASS", "HTML title element",
        )
        qa.write_run_artifacts(baseline_dir, "baseline", [baseline_row], cfg, baseline_row.timestamp)
        loaded = qa._load_baseline(baseline_dir / "baseline.csv", qa.config_digest(cfg))
        schedule = {
            "schema": qa.MONTH_SCHEDULE_SCHEMA,
            "period_id": "2026-07",
            "period_starts_at": "2026-07-07T00:00:00Z",
            "period_ends_at": "2026-07-30T00:00:00Z",
            "config_digest": qa.config_digest(cfg),
            "baseline_csv_sha256": loaded.csv_sha256,
            "baseline_captured_at": loaded.captured_at,
            "windows": [
                {"id": "week-1", "opens_at": "2026-07-07T00:00:00Z", "scheduled_for": "2026-07-08T12:00:00Z", "closes_at": "2026-07-09T00:00:00Z"},
                {"id": "week-2", "opens_at": "2026-07-14T00:00:00Z", "scheduled_for": "2026-07-15T12:00:00Z", "closes_at": "2026-07-16T00:00:00Z"},
                {"id": "week-3", "opens_at": "2026-07-21T00:00:00Z", "scheduled_for": "2026-07-22T12:00:00Z", "closes_at": "2026-07-23T00:00:00Z"},
                {"id": "week-4", "opens_at": "2026-07-28T00:00:00Z", "scheduled_for": "2026-07-29T12:00:00Z", "closes_at": "2026-07-30T00:00:00Z"},
            ],
        }
        schedule_path = root / "monthly-schedule.json"
        schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
        schedule_digest = qa._canonical_json_sha256(schedule)
        run_dirs = []
        for day, observation in zip((8, 15, 22, 29), observations, strict=True):
            run_dir = root / f"week-{day}"
            row = qa.CheckResult(
                baseline_row.url,
                f"2026-07-{day:02d}T12:00:00Z",
                baseline_row.check,
                baseline_row.observed,
                observation,
                "PASS" if observation == baseline_row.observed else "DRIFT",
                "HTML title element",
            )
            qa.write_run_artifacts(
                run_dir, "scheduled-rerun", [row], cfg, row.timestamp, loaded,
                {
                    "schedule_sha256": schedule_digest,
                    "window_id": f"week-{len(run_dirs) + 1}",
                    "scheduled_for": row.timestamp,
                },
            )
            run_dirs.append(run_dir)
        return config_path, baseline_dir, schedule_path, run_dirs

    def _replace_run_csv_and_rehash(self, run_dir: Path, payload: str):
        csv_path = run_dir / "rerun.csv"
        csv_path.write_text(payload, encoding="utf-8")
        metadata_path = run_dir / "rerun.meta.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["csv_sha256"] = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        manifest_path = run_dir / "output-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["rerun.csv"] = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        manifest["files"]["rerun.meta.json"] = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def _rehash_baseline_bundle(self, baseline_dir: Path):
        metadata_path = baseline_dir / "baseline.meta.json"
        csv_path = baseline_dir / "baseline.csv"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["csv_sha256"] = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        manifest_path = baseline_dir / "output-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["baseline.csv"] = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        manifest["files"]["baseline.meta.json"] = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_cli_writes_only_observation_transitions_with_verified_lineage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems", "Changed", "Changed", "Restored"],
            )
            out = root / "ledger"
            result = qa.run(Namespace(
                command="month-end-ledger",
                config=config_path,
                baseline_manifest=baseline_dir / "output-manifest.json",
                schedule=schedule_path,
                run_manifests=list(reversed([run_dir / "output-manifest.json" for run_dir in run_dirs])),
                out=out,
            ))

            self.assertEqual(result, 0)
            with (out / "month-end-ledger.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["observed"] for row in rows], ["Changed", "Restored"])
            self.assertEqual(
                [row["previous_observed"] for row in rows],
                ["Springfield Systems", "Changed"],
            )
            self.assertEqual(
                [row["captured_at"] for row in rows],
                ["2026-07-15T12:00:00Z", "2026-07-29T12:00:00Z"],
            )
            metadata = json.loads((out / "month-end-ledger.meta.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["schema"], qa.LEDGER_SCHEMA)
            self.assertEqual(metadata["run_count"], 4)
            self.assertEqual(metadata["row_count"], 2)
            self.assertEqual(metadata["baseline_csv_sha256"], hashlib.sha256(
                (baseline_dir / "baseline.csv").read_bytes()
            ).hexdigest())
            self.assertEqual([item["captured_at"] for item in metadata["source_runs"]], [
                "2026-07-08T12:00:00Z", "2026-07-15T12:00:00Z",
                "2026-07-22T12:00:00Z", "2026-07-29T12:00:00Z",
            ])
            self.assertTrue(all(item["capture_complete"] is True for item in metadata["source_runs"]))
            manifest = json.loads((out / "output-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(set(manifest["files"]), {
                "month-end-ledger.csv", "month-end-ledger.md", "month-end-ledger.meta.json",
            })

    def test_schedule_digest_can_be_verified_before_window_one_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            output = io.StringIO()
            with mock.patch.object(qa, "_resolve_with_deadline") as dns, mock.patch.object(
                qa, "fetch_page"
            ) as fetch, redirect_stdout(output):
                self.assertEqual(qa.run(Namespace(
                    command="schedule-digest",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                )), 0)
            dns.assert_not_called()
            fetch.assert_not_called()
            result = json.loads(output.getvalue())
            schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
            self.assertEqual(result["schedule_sha256"], qa._canonical_json_sha256(schedule))
            self.assertEqual(result["period_id"], "2026-07")
            self.assertEqual([window["id"] for window in result["windows"]], [
                "week-1", "week-2", "week-3", "week-4",
            ])

    def test_schedule_digest_recomputes_baseline_eligibility_from_frozen_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            metadata_path = baseline_dir / "baseline.meta.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["earliest_scheduled_evidence_at"] = metadata["captured_at"]
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            self._rehash_baseline_bundle(baseline_dir)
            with self.assertRaisesRegex(qa.ConfigError, "scheduled evidence"):
                qa.run(Namespace(
                    command="schedule-digest",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                ))

    def test_baseline_pass_must_match_its_expected_observation(self):
        record = {
            "url": "https://example.com/", "timestamp": "2026-07-01T12:00:00Z",
            "check": "title", "expected": "Wrong", "observed": "Springfield Systems",
            "status": "PASS", "evidence": "HTML title element",
        }
        with self.assertRaisesRegex(qa.ConfigError, "PASS"):
            qa.validate_baseline_records([record])

    def test_schedule_digest_rejects_self_consistent_baseline_expectation_not_in_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            with (baseline_dir / "baseline.csv").open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
            row["expected"] = "Wrong"
            row["observed"] = "Wrong"
            buffer = io.StringIO(newline="")
            writer = csv.DictWriter(buffer, fieldnames=qa.CSV_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
            (baseline_dir / "baseline.csv").write_text(buffer.getvalue(), encoding="utf-8")
            self._rehash_baseline_bundle(baseline_dir)
            schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
            schedule["baseline_csv_sha256"] = hashlib.sha256(
                (baseline_dir / "baseline.csv").read_bytes()
            ).hexdigest()
            schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
            with self.assertRaisesRegex(qa.ConfigError, "frozen config"):
                qa.run(Namespace(
                    command="schedule-digest",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                ))

    def test_verified_capture_accepts_a_generated_large_csv_field(self):
        evidence = "x" * 200_000
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=qa.CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerow({
            "url": "https://example.com/", "timestamp": "2026-07-01T12:00:00Z",
            "check": "title", "expected": "Springfield Systems",
            "observed": "Springfield Systems", "status": "PASS", "evidence": evidence,
        })
        records = qa._read_csv_records_bytes(buffer.getvalue().encode("utf-8"))
        self.assertEqual(records[0]["evidence"], evidence)

    def test_ledger_rejects_output_nested_inside_any_source_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = baseline_dir / "ledger"
            with self.assertRaisesRegex(qa.ConfigError, "alias an input"):
                qa.run(Namespace(
                    command="month-end-ledger",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                    run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                    out=out,
                ))
            self.assertFalse(out.exists())

    def test_ledger_rejects_self_consistent_csv_with_a_missing_cell_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            self._replace_run_csv_and_rehash(
                run_dirs[0],
                ",".join(qa.CSV_FIELDS) + "\n"
                + "https://example.com/,2026-07-08T12:00:00Z,title,Springfield Systems,Springfield Systems,PASS\n",
            )
            with self.assertRaises(qa.ConfigError):
                qa.run(Namespace(
                    command="month-end-ledger",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                    run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                    out=root / "ledger",
                ))

    def test_ledger_cannot_be_committed_before_the_agreed_period_ends(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            with mock.patch.object(qa, "datetime", wraps=datetime) as clock:
                clock.now.return_value = datetime(2026, 7, 29, 13, tzinfo=timezone.utc)
                with self.assertRaisesRegex(qa.ConfigError, "period has not ended"):
                    qa.run(Namespace(
                        command="month-end-ledger",
                        config=config_path,
                        baseline_manifest=baseline_dir / "output-manifest.json",
                        schedule=schedule_path,
                        run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                        out=root / "ledger",
                    ))

    def test_schedule_bound_rerun_failure_leaves_no_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = root / "failed-week"
            page = qa.PageResult(
                "https://example.com/", "https://example.com/", 200,
                {"content-type": "text/html; charset=utf-8"}, HTML, None,
            )
            args = Namespace(
                command="scheduled-rerun",
                config=config_path,
                baseline=baseline_dir / "baseline.csv",
                schedule=schedule_path,
                window="week-1",
                scheduled_for=None,
                out=out,
            )
            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_resolve_with_deadline", return_value=("93.184.216.34",)
            ), mock.patch.object(qa, "fetch_page", return_value=page), mock.patch.object(
                qa, "write_exceptions", side_effect=OSError("disk full")
            ):
                clock.now.return_value = datetime(2026, 7, 8, 12, 30, tzinfo=timezone.utc)
                with self.assertRaises(OSError):
                    qa.run(args)
            self.assertFalse(out.exists())

    def test_schedule_bound_rerun_rejects_output_inside_baseline_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = baseline_dir / "week-1-copy"
            args = Namespace(
                command="scheduled-rerun",
                config=config_path,
                baseline=baseline_dir / "baseline.csv",
                schedule=schedule_path,
                window="week-1",
                scheduled_for=None,
                out=out,
            )
            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_resolve_with_deadline"
            ) as dns, mock.patch.object(qa, "fetch_page") as fetch:
                clock.now.return_value = datetime(2026, 7, 8, 12, 30, tzinfo=timezone.utc)
                with self.assertRaisesRegex(qa.ConfigError, "alias the baseline"):
                    qa.run(args)
            dns.assert_not_called()
            fetch.assert_not_called()
            self.assertFalse(out.exists())

    def test_schedule_bound_rerun_rejects_output_inside_symlinked_manifest_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            target = elsewhere / "baseline.csv"
            out = baseline_dir / "nested-output"
            args = Namespace(
                command="scheduled-rerun", config=config_path,
                baseline=baseline_dir / "baseline.csv", schedule=schedule_path,
                window="week-1", scheduled_for=None, out=out,
            )
            real_resolve = Path.resolve

            def symlink_aware_resolve(path, *resolve_args, **resolve_kwargs):
                if Path(path).absolute() == (baseline_dir / "baseline.csv").absolute():
                    return target
                return real_resolve(path, *resolve_args, **resolve_kwargs)

            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_resolve_with_deadline"
            ) as dns, mock.patch.object(qa, "fetch_page") as fetch:
                clock.now.return_value = datetime(2026, 7, 8, 12, 30, tzinfo=timezone.utc)
                with mock.patch.object(Path, "resolve", autospec=True, side_effect=symlink_aware_resolve):
                    with self.assertRaisesRegex(qa.ConfigError, "alias the baseline"):
                        qa.run(args)
            dns.assert_not_called()
            fetch.assert_not_called()
            self.assertFalse(out.exists())

    def test_schedule_bound_rerun_rejects_output_inside_resolved_manifest_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, real_bundle, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            alias_bundle = root / "alias-bundle"
            alias_bundle.mkdir()
            (alias_bundle / "baseline.csv").write_bytes((real_bundle / "baseline.csv").read_bytes())
            (alias_bundle / "output-manifest.json").write_text("symlink placeholder", encoding="utf-8")
            out = real_bundle / "nested-output"
            args = Namespace(
                command="scheduled-rerun", config=config_path,
                baseline=alias_bundle / "baseline.csv", schedule=schedule_path,
                window="week-1", scheduled_for=None, out=out,
            )
            real_resolve = Path.resolve

            def manifest_symlink_resolve(path, *resolve_args, **resolve_kwargs):
                if Path(path).absolute() == (alias_bundle / "output-manifest.json").absolute():
                    return real_bundle / "output-manifest.json"
                return real_resolve(path, *resolve_args, **resolve_kwargs)

            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_resolve_with_deadline"
            ) as dns, mock.patch.object(qa, "fetch_page") as fetch:
                clock.now.return_value = datetime(2026, 7, 8, 12, 30, tzinfo=timezone.utc)
                with mock.patch.object(Path, "resolve", autospec=True, side_effect=manifest_symlink_resolve):
                    with self.assertRaisesRegex(qa.ConfigError, "alias the baseline|verified manifest"):
                        qa.run(args)
            dns.assert_not_called()
            fetch.assert_not_called()
            self.assertFalse(out.exists())

    def test_schedule_bound_rerun_fails_before_dns_until_its_window_opens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            args = Namespace(
                command="scheduled-rerun",
                config=config_path,
                baseline=baseline_dir / "baseline.csv",
                schedule=schedule_path,
                window="week-1",
                scheduled_for=None,
                out=root / "too-early",
            )
            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_resolve_with_deadline"
            ) as dns, mock.patch.object(qa, "fetch_page") as fetch:
                clock.now.return_value = datetime(2026, 7, 8, 11, 59, 59, tzinfo=timezone.utc)
                with self.assertRaisesRegex(qa.ConfigError, "window is not open"):
                    qa.run(args)
            dns.assert_not_called()
            fetch.assert_not_called()
            self.assertFalse(args.out.exists())

    def test_schedule_bound_rerun_persists_window_lineage_in_a_fresh_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = root / "captured-week"
            page = qa.PageResult(
                "https://example.com/", "https://example.com/", 200,
                {"content-type": "text/html; charset=utf-8"}, HTML, None,
            )
            args = Namespace(
                command="scheduled-rerun",
                config=config_path,
                baseline=baseline_dir / "baseline.csv",
                schedule=schedule_path,
                window="week-1",
                scheduled_for=None,
                out=out,
            )
            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_resolve_with_deadline", return_value=("93.184.216.34",)
            ), mock.patch.object(qa, "fetch_page", return_value=page):
                clock.now.return_value = datetime(2026, 7, 8, 12, 30, tzinfo=timezone.utc)
                self.assertEqual(qa.run(args), 0)
            metadata = json.loads((out / "rerun.meta.json").read_text(encoding="utf-8"))
            schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["schedule_sha256"], qa._canonical_json_sha256(schedule))
            self.assertEqual(metadata["window_id"], "week-1")
            self.assertEqual(metadata["scheduled_for"], "2026-07-08T12:00:00Z")
            self.assertEqual(metadata["captured_at"], "2026-07-08T12:30:00Z")
            loaded = qa._load_verified_capture(out / "output-manifest.json", "scheduled-rerun")
            self.assertEqual(loaded.window_id, "week-1")

    def test_window_close_caps_each_fetch_and_stops_later_gets(self):
        raw = valid_config()
        raw["urls"].append({"id": "about", "url": "https://example.com/about"})
        cfg = qa.validate_config(raw, check_dns=False)
        closes_at = datetime(2026, 7, 8, 13, tzinfo=timezone.utc)
        clock = iter([
            datetime(2026, 7, 8, 12, 59, 59, tzinfo=timezone.utc),
            closes_at,
        ])
        page = qa.PageResult(
            "https://example.com/", "https://example.com/", 200,
            {"content-type": "text/html; charset=utf-8"}, HTML, None,
        )
        with mock.patch.object(qa, "fetch_page", return_value=page) as fetch:
            with self.assertRaisesRegex(qa.ConfigError, "window closed"):
                qa._capture_pages(
                    cfg, closes_at=closes_at, now_provider=lambda: next(clock),
                )
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(fetch.call_args.args[2], 1.0)

    def test_schedule_bound_rerun_records_transient_dns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, _run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = root / "dns-unavailable"
            args = Namespace(
                command="scheduled-rerun", config=config_path,
                baseline=baseline_dir / "baseline.csv", schedule=schedule_path,
                window="week-1", scheduled_for=None, out=out,
            )
            with mock.patch.object(qa, "datetime", wraps=datetime) as clock, mock.patch.object(
                qa, "_validate_host_addresses"
            ) as eager_dns, mock.patch.object(
                qa, "_resolve_with_deadline", side_effect=qa.TransientFetchError("DNS resolution failed")
            ):
                clock.now.return_value = datetime(2026, 7, 8, 12, 30, tzinfo=timezone.utc)
                self.assertEqual(qa.run(args), 2)
            eager_dns.assert_not_called()
            records = qa.read_csv_records(out / "rerun.csv")
            self.assertEqual(records[0]["status"], "UNAVAILABLE")
            self.assertIn("DNS resolution failed", records[0]["evidence"])

    def test_zero_transition_ledger_has_header_only_csv_and_precise_no_change_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = root / "ledger"
            qa.run(Namespace(
                command="month-end-ledger",
                config=config_path,
                baseline_manifest=baseline_dir / "output-manifest.json",
                schedule=schedule_path,
                run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                out=out,
            ))
            with (out / "month-end-ledger.csv").open(newline="", encoding="utf-8") as handle:
                self.assertEqual(list(csv.DictReader(handle)), [])
            report = (out / "month-end-ledger.md").read_text(encoding="utf-8")
            self.assertIn("No observation transitions were recorded among the frozen checks across four captures.", report)
            self.assertNotIn("the website did not change.", report.casefold())

    def test_unavailability_is_recorded_once_and_recovery_is_a_second_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            for run_dir, timestamp, evidence in (
                (run_dirs[1], "2026-07-15T12:00:00Z", "timeout one"),
                (run_dirs[2], "2026-07-22T12:00:00Z", "timeout two"),
            ):
                buffer = io.StringIO(newline="")
                writer = csv.DictWriter(buffer, fieldnames=qa.CSV_FIELDS, lineterminator="\n")
                writer.writeheader()
                writer.writerow({
                    "url": "https://example.com/", "timestamp": timestamp, "check": "title",
                    "expected": "Springfield Systems", "observed": "unavailable",
                    "status": "UNAVAILABLE", "evidence": evidence,
                })
                self._replace_run_csv_and_rehash(run_dir, buffer.getvalue())
            out = root / "ledger"
            qa.run(Namespace(
                command="month-end-ledger",
                config=config_path,
                baseline_manifest=baseline_dir / "output-manifest.json",
                schedule=schedule_path,
                run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                out=out,
            ))
            with (out / "month-end-ledger.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["event_type"] for row in rows], ["BECAME_UNAVAILABLE", "AVAILABLE_AGAIN"])
            self.assertEqual([row["run"] for row in rows], ["week-2", "week-4"])

    def test_ledger_verifies_source_markdown_manifest_hash_and_uses_zero_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            (run_dirs[0] / "exceptions.md").write_text("tampered", encoding="utf-8")
            with mock.patch.object(qa, "_resolve_with_deadline") as dns, mock.patch.object(qa, "fetch_page") as fetch:
                with self.assertRaisesRegex(qa.ConfigError, "digest"):
                    qa.run(Namespace(
                        command="month-end-ledger",
                        config=config_path,
                        baseline_manifest=baseline_dir / "output-manifest.json",
                        schedule=schedule_path,
                        run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                        out=root / "ledger",
                    ))
            dns.assert_not_called()
            fetch.assert_not_called()

    def test_ledger_staging_failure_leaves_no_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            out = root / "ledger"
            with mock.patch.object(qa, "_write_ledger_markdown", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    qa.run(Namespace(
                        command="month-end-ledger",
                        config=config_path,
                        baseline_manifest=baseline_dir / "output-manifest.json",
                        schedule=schedule_path,
                        run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                        out=out,
                    ))
            self.assertFalse(out.exists())

    def test_ledger_rejects_duplicate_json_keys_before_using_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            payload = schedule_path.read_text(encoding="utf-8")
            schedule_path.write_text(
                payload.replace('"period_id": "2026-07",', '"period_id": "wrong", "period_id": "2026-07",', 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(qa.ConfigError, "duplicate JSON key"):
                qa.run(Namespace(
                    command="month-end-ledger",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                    run_manifests=[run_dir / "output-manifest.json" for run_dir in run_dirs],
                    out=root / "ledger",
                ))

    def test_ledger_rejects_legacy_scheduled_run_without_schedule_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path, baseline_dir, schedule_path, run_dirs = self._write_month(
                root, ["Springfield Systems"] * 4,
            )
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            cfg = qa.validate_config(raw, resolver=lambda _host: ["93.184.216.34"])
            loaded = qa._load_baseline(baseline_dir / "baseline.csv", qa.config_digest(cfg))
            legacy = root / "legacy-week"
            row = qa.CheckResult(
                "https://example.com/", "2026-07-08T12:00:00Z", "title",
                "Springfield Systems", "Springfield Systems", "PASS", "HTML title element",
            )
            qa.write_run_artifacts(legacy, "scheduled-rerun", [row], cfg, row.timestamp, loaded)
            manifests = [legacy / "output-manifest.json"] + [
                run_dir / "output-manifest.json" for run_dir in run_dirs[1:]
            ]
            with self.assertRaisesRegex(qa.ConfigError, "schedule-bound"):
                qa.run(Namespace(
                    command="month-end-ledger",
                    config=config_path,
                    baseline_manifest=baseline_dir / "output-manifest.json",
                    schedule=schedule_path,
                    run_manifests=manifests,
                    out=root / "ledger",
                ))


if __name__ == "__main__":
    unittest.main()
