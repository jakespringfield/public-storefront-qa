import csv
import io
import json
import tempfile
import time
import unittest
from argparse import Namespace
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

    def test_canonical_may_explicitly_expect_absence(self):
        cfg = valid_config()
        cfg["checks"][2]["expected"] = "absent"
        clean = qa.validate_config(cfg, resolver=lambda _host: ["93.184.216.34"])
        self.assertEqual(clean["checks"][2]["expected"], "absent")


class FetchSafetyTests(unittest.TestCase):
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


class ReportingTests(unittest.TestCase):
    def test_csv_formula_neutralization_is_lossless_and_collision_safe(self):
        values = ["=1+1", "+cmd", "-2", "@name", "\tcmd", "\rcmd", "\ncmd", "'=literal", "''already", "normal"]
        for value in values:
            encoded = qa.safe_csv_cell(value)
            self.assertNotIn(encoded[:1], {"=", "+", "-", "@", "\t", "\r", "\n"})
            self.assertEqual(qa.restore_csv_cell(encoded), value)

    def test_markdown_cells_escape_html_pipes_and_backslashes(self):
        rendered = qa.markdown_cell("<img src=x>|a\\b\nnext & end")
        self.assertIn("&lt;img src=x&gt;", rendered)
        self.assertIn("\\|", rendered)
        self.assertIn("a\\\\b", rendered)
        self.assertIn("<br>", rendered)
        self.assertIn("&amp;", rendered)

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


if __name__ == "__main__":
    unittest.main()

