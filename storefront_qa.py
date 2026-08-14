#!/usr/bin/env python3
"""Read-only, bounded checks for a configured set of public HTML pages."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import http.client
import ipaddress
import io
import json
import os
import queue
import re
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Iterable, NamedTuple
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


MAX_URLS = 6
MAX_CHECKS = 20
MAX_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 2_000_000
MAX_ARTIFACT_CELL_CHARS = MAX_RESPONSE_BYTES * 4
MAX_URL_CHARS = 4_096
MAX_CONFIG_VALUE_CHARS = 16_384
MAX_REDIRECTS = 5
MAX_GET_ATTEMPTS = 2
TOOL_VERSION = "1.1.0"
USER_AGENT = f"Springfield-Public-Storefront-QA/{TOOL_VERSION} (+read-only; public GET)"
BASELINE_SCHEMA = "public-storefront-qa/baseline-v1"
RUN_SCHEMA = "public-storefront-qa/run-v1"
MANIFEST_SCHEMA = "public-storefront-qa/commit-v1"
LEDGER_SCHEMA = "public-storefront-qa/month-end-ledger-v1"
MONTH_SCHEDULE_SCHEMA = "public-storefront-qa/monthly-schedule-v1"
CSV_FIELDS = ["url", "timestamp", "check", "expected", "observed", "status", "evidence"]
LEDGER_FIELDS = [
    "run", "captured_at", "previous_captured_at", "url", "check", "baseline_observed",
    "previous_observed", "previous_status", "observed", "status", "event_type", "evidence",
    "source_csv_sha256",
]
ALLOWED_STATUSES = {"PASS", "DRIFT", "UNAVAILABLE"}
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
CHECK_TYPES = {
    "status", "title", "canonical", "robots-indexability",
    "structured-data-presence", "text", "selector", "asset-reference",
}
FORBIDDEN_ROUTE_SEGMENTS = {
    "account", "accounts", "auth", "cart", "checkout", "login", "oauth",
    "sign-in", "sign-up", "signin", "signup",
}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
HOST_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SELECTOR_PATTERN = re.compile(
    r"^(?P<tag>[A-Za-z][A-Za-z0-9-]*)?(?:#(?P<id>[A-Za-z][A-Za-z0-9_-]*))?(?:\.(?P<class>[A-Za-z][A-Za-z0-9_-]*))?$"
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
TRANSIENT_STATUSES = {408, 425, 429, 500, 502, 503, 504}
SURROGATE_PATTERN = re.compile(r"[\uD800-\uDFFF]")

# Generated observation/evidence fields can legitimately approach the bounded
# response size. Python's much smaller platform default would reject our own
# valid artifacts during verification.
csv.field_size_limit(MAX_ARTIFACT_CELL_CHARS)


class ConfigError(ValueError):
    pass


class UnsafeDestinationError(ConfigError):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ConfigError("invalid command line; use --help for required arguments")


class FetchError(RuntimeError):
    pass


class TransientFetchError(FetchError):
    pass


class PageResult(NamedTuple):
    requested_url: str
    final_url: str | None
    status: int | None
    headers: dict[str, str]
    body: bytes
    error: str | None


class CheckResult(NamedTuple):
    url: str
    timestamp: str
    check: str
    expected: str
    observed: str
    status: str
    evidence: str


class LoadedBaseline(NamedTuple):
    observations: dict[tuple[str, str], str]
    csv_sha256: str
    captured_at: str


class VerifiedCapture(NamedTuple):
    mode: str
    rows: list[dict[str, str]]
    csv_sha256: str
    manifest_sha256: str
    captured_at: str
    config_digest: str
    baseline_csv_sha256: str | None
    baseline_captured_at: str | None
    earliest_scheduled_evidence_at: str | None
    tool_version: str
    schedule_sha256: str | None
    window_id: str | None
    scheduled_for: str | None


class LoadedSchedule(NamedTuple):
    value: dict
    sha256: str
    windows_by_id: dict[str, dict]


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        raise ConfigError("timestamp must use UTC RFC 3339 seconds, for example 2026-08-14T12:00:00Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ConfigError("timestamp is not a valid UTC calendar time") from exc


def _checked_add_hours(value: datetime, hours: int) -> datetime:
    try:
        return value + timedelta(hours=hours)
    except (OverflowError, ValueError) as exc:
        raise ConfigError("timestamp arithmetic exceeds the supported time range") from exc


def resolve_addresses(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise ConfigError("configured domain could not be resolved") from exc


def _is_public_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_global and not address.is_multicast and not address.is_unspecified
        and not address.is_reserved and not address.is_loopback and not address.is_link_local
        and not address.is_private
    )


def _validated_addresses(host: str, addresses: Iterable[str]) -> tuple[str, ...]:
    clean = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UnsafeDestinationError("resolver returned a non-IP destination") from exc
        if not _is_public_unicast(parsed):
            raise UnsafeDestinationError("configured domain must resolve only to public IP unicast addresses")
        clean.append(str(parsed))
    if not clean:
        raise UnsafeDestinationError("configured domain did not resolve to an address")
    return tuple(sorted(set(clean), key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item).packed)))


def _validate_host_addresses(host: str, resolver: Callable[[str], list[str]]) -> tuple[str, ...]:
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        addresses = resolver(host)
    return _validated_addresses(host, addresses)


def _resolve_with_deadline(host: str, resolver: Callable[[str], list[str]], deadline: float) -> tuple[str, ...]:
    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put((True, resolver(host)))
        except BaseException as exc:
            result_queue.put((False, exc))

    threading.Thread(target=worker, name="storefront-qa-dns", daemon=True).start()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransientFetchError("end-to-end deadline expired during DNS resolution")
    try:
        succeeded, result = result_queue.get(timeout=remaining)
    except queue.Empty as exc:
        raise TransientFetchError("end-to-end deadline expired during DNS resolution") from exc
    if not succeeded:
        raise TransientFetchError("DNS resolution failed") from result
    return _validated_addresses(host, result)


def _decode_route(path: str) -> str:
    current = unicodedata.normalize("NFKC", path)
    for _ in range(8):
        if "%" in current and "%" in PERCENT_ESCAPE.sub("", current):
            raise ConfigError("URL path contains invalid or ambiguous percent encoding")
        try:
            decoded = unicodedata.normalize("NFKC", unquote(current, errors="strict"))
        except UnicodeError as exc:
            raise ConfigError("URL path contains invalid UTF-8 percent encoding") from exc
        if decoded == current:
            return decoded
        current = decoded
    raise ConfigError("URL path encoding did not stabilize")


def _validate_route(path: str) -> None:
    decoded = _decode_route(path)
    if "\\" in decoded or ";" in decoded or "?" in decoded or "#" in decoded:
        raise ConfigError("account/cart/checkout routes are outside scope")
    segments = [segment.casefold().strip(". ") for segment in decoded.split("/") if segment]
    if any(segment in {"", ".", ".."} for segment in segments) or set(segments) & FORBIDDEN_ROUTE_SEGMENTS:
        raise ConfigError("account/cart/checkout routes are outside scope")


def normalize_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        hostname = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except (TypeError, ValueError) as exc:
        raise ConfigError("URL is malformed") from exc
    default_port = (parts.scheme.lower() == "https" and port == 443) or (parts.scheme.lower() == "http" and port == 80)
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", "", ""))


def validate_public_url(
    url: str,
    domain: str,
    resolver: Callable[[str], list[str]] = resolve_addresses,
    *, check_dns: bool = True,
) -> str:
    if not isinstance(url, str) or not url:
        raise ConfigError("URL must be a non-empty string")
    if len(url) > MAX_URL_CHARS:
        raise ConfigError(f"URL is too long; maximum is {MAX_URL_CHARS} characters")
    if "?" in url or "#" in url:
        raise ConfigError("URL query and fragment delimiters are forbidden")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ConfigError("URL is malformed") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise ConfigError("URL must use http or https")
    if not parts.hostname:
        raise ConfigError("URL must have a hostname")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("URL credentials are forbidden")
    if port not in {None, 80, 443}:
        raise ConfigError("URL may use only ports 80 or 443")
    host = parts.hostname.rstrip(".").lower()
    if host != domain:
        raise ConfigError("URL must use the configured exact domain")
    if host == "localhost" or host.endswith(".localhost"):
        raise ConfigError("localhost is forbidden")
    _validate_route(parts.path)
    if check_dns:
        _validate_host_addresses(host, resolver)
    return normalize_url(url)


def _require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ConfigError(f"{label} has an invalid identifier")
    return value


def _expected_string(check: dict) -> str:
    kind = check["type"]
    value = check.get("expected")
    if kind == "status":
        if not isinstance(value, int) or not 100 <= value <= 599:
            raise ConfigError(f"check {check['id']} expected must be an HTTP status integer")
        return str(value)
    if kind in {"structured-data-presence", "text", "selector", "asset-reference"}:
        if not isinstance(value, str) or value not in {"present", "absent"}:
            raise ConfigError(f"check {check['id']} expected must be present or absent")
        return value
    if kind == "robots-indexability":
        if not isinstance(value, str) or value not in {"indexable", "noindex"}:
            raise ConfigError(f"check {check['id']} expected must be indexable or noindex")
        return value
    if not isinstance(value, str):
        raise ConfigError(f"check {check['id']} expected must be a string")
    if len(value) > MAX_CONFIG_VALUE_CHARS:
        raise ConfigError(f"check {check['id']} expected is too long")
    return value


def validate_config(
    raw: dict,
    resolver: Callable[[str], list[str]] = resolve_addresses,
    *,
    check_dns: bool = True,
) -> dict:
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    _validate_unicode_scalar_strings(raw, "config")
    domain = raw.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        raise ConfigError("domain must be a non-empty hostname")
    domain = domain.rstrip(".").lower()
    if not HOST_PATTERN.fullmatch(domain) or domain == "localhost" or domain.endswith(".localhost"):
        raise ConfigError("domain must be a valid public hostname")
    timeout = raw.get("timeout_seconds", 10)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ConfigError(f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")
    if check_dns:
        try:
            _resolve_with_deadline(domain, resolver, time.monotonic() + float(timeout))
        except FetchError as exc:
            raise ConfigError(str(exc)) from exc
    max_bytes = raw.get("max_response_bytes", 1_000_000)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_RESPONSE_BYTES:
        raise ConfigError(f"max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}")
    minimum_age = raw.get("scheduled_evidence_minimum_hours", 72)
    if not isinstance(minimum_age, int) or isinstance(minimum_age, bool) or not 1 <= minimum_age <= 720:
        raise ConfigError("scheduled_evidence_minimum_hours must be an integer between 1 and 720")
    urls = raw.get("urls")
    if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_URLS:
        raise ConfigError(f"config must contain 1 to at most {MAX_URLS} URLs")
    clean_urls = []
    url_ids: set[str] = set()
    for entry in urls:
        if not isinstance(entry, dict):
            raise ConfigError("each URL entry must be an object")
        url_id = _require_id(entry.get("id"), "URL id")
        if url_id in url_ids:
            raise ConfigError(f"duplicate URL id: {url_id}")
        url_ids.add(url_id)
        clean_urls.append({"id": url_id, "url": validate_public_url(entry.get("url"), domain, check_dns=False)})
    checks = raw.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        raise ConfigError(f"config must contain 1 to at most {MAX_CHECKS} checks")
    clean_checks = []
    check_ids: set[str] = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ConfigError("each check must be an object")
        check_id = _require_id(check.get("id"), "check id")
        if check_id in check_ids:
            raise ConfigError(f"duplicate check id: {check_id}")
        check_ids.add(check_id)
        url_id = _require_id(check.get("url"), f"check {check_id} URL id")
        if url_id not in url_ids:
            raise ConfigError(f"check {check_id} references an unknown URL id")
        kind = check.get("type")
        if not isinstance(kind, str) or kind not in CHECK_TYPES:
            raise ConfigError(f"check {check_id} has an unsupported type")
        clean = {"id": check_id, "url": url_id, "type": kind, "expected": _expected_string(check)}
        if kind in {"text", "selector", "asset-reference"}:
            value = check.get("value")
            if not isinstance(value, str) or not value:
                raise ConfigError(f"check {check_id} requires a non-empty value")
            if len(value) > MAX_CONFIG_VALUE_CHARS:
                raise ConfigError(f"check {check_id} value is too long")
            if kind == "selector" and not SELECTOR_PATTERN.fullmatch(value):
                raise ConfigError(f"check {check_id} uses unsupported selector syntax")
            if kind == "asset-reference":
                value = validate_public_url(value, domain, check_dns=False)
            clean["value"] = value
        if kind == "canonical" and clean["expected"] != "absent":
            clean["expected"] = validate_public_url(clean["expected"], domain, check_dns=False)
        clean_checks.append(clean)
    return {
        "domain": domain,
        "timeout_seconds": float(timeout),
        "max_response_bytes": max_bytes,
        "scheduled_evidence_minimum_hours": minimum_age,
        "urls": clean_urls,
        "checks": clean_checks,
    }


def config_digest(config: dict) -> str:
    payload = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, logical_host: str, connect_ip: str, port: int, timeout: float):
        super().__init__(logical_host, port=port, timeout=timeout)
        self.connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self.connect_ip, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, logical_host: str, connect_ip: str, port: int, timeout: float):
        super().__init__(logical_host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.connect_ip = connect_ip

    def connect(self) -> None:
        raw = socket.create_connection((self.connect_ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransientFetchError("end-to-end deadline expired")
    return remaining


def _call_with_deadline(operation, deadline: float, connection, phase: str):
    """Run a blocking socket phase against the shared wall-clock deadline."""
    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put((True, operation()))
        except BaseException as exc:
            result_queue.put((False, exc))

    remaining = _remaining(deadline)
    threading.Thread(target=worker, name=f"storefront-qa-{phase.replace(' ', '-')}", daemon=True).start()
    try:
        succeeded, result = result_queue.get(timeout=remaining)
    except queue.Empty as exc:
        connection.close()
        raise TransientFetchError(f"end-to-end deadline expired during {phase}") from exc
    if time.monotonic() > deadline:
        connection.close()
        raise TransientFetchError(f"end-to-end deadline expired during {phase}")
    if not succeeded:
        raise result
    return result


def parse_content_type(value: str) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, None
    message = Message()
    message["content-type"] = value
    mime = message.get_content_type().lower()
    charset = message.get_content_charset()
    return mime, charset.lower() if charset else None


def read_bounded(stream, max_bytes: int, *, deadline: float | None = None, connection=None) -> bytes:
    chunks = []
    size = 0
    while True:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchError("end-to-end deadline expired while reading response body")
            sock = getattr(connection, "sock", None)
            if sock is not None:
                sock.settimeout(remaining)
        chunk = stream.read(min(65_536, max_bytes + 1 - size))
        if deadline is not None and time.monotonic() > deadline:
            raise FetchError("end-to-end deadline expired while reading response body")
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > max_bytes:
            raise FetchError(f"response exceeded maximum of {max_bytes} bytes")
    return b"".join(chunks)


def _headers_dict(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in items:
        lowered = key.lower()
        result[lowered] = f"{result[lowered]}, {value.strip()}" if lowered in result else value.strip()
    return result


def _open_pinned(url: str, domain: str, addresses: tuple[str, ...], deadline: float):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    last_error: BaseException | None = None
    for address in addresses:
        connection = None
        try:
            cls = PinnedHTTPSConnection if parts.scheme == "https" else PinnedHTTPConnection
            connection = cls(domain, address, port, _remaining(deadline))
            request_target = quote(parts.path or "/", safe="/%:@!$&'()*+,-._~")
            _call_with_deadline(
                lambda: connection.request("GET", request_target, headers={
                    "Accept": "text/html,application/xhtml+xml;q=0.9",
                    "User-Agent": USER_AGENT,
                    "Connection": "close",
                }),
                deadline,
                connection,
                "connection and request",
            )
            response = _call_with_deadline(connection.getresponse, deadline, connection, "response headers")
            return connection, response
        except TransientFetchError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            last_error = exc
            if connection is not None:
                connection.close()
    raise TransientFetchError("connection to the validated public destination failed") from last_error


def _fetch_chain_once(
    safe_url: str,
    domain: str,
    addresses: tuple[str, ...],
    deadline: float,
    max_bytes: int,
    *,
    retry_transient_status: bool = True,
) -> PageResult:
    current = safe_url
    for redirect_count in range(MAX_REDIRECTS + 1):
        connection, response = _open_pinned(current, domain, addresses, deadline)
        try:
            headers = _headers_dict(response.getheaders())
            status = int(response.status)
            if retry_transient_status and status in TRANSIENT_STATUSES:
                raise TransientFetchError(f"transient HTTP status {status}")
            if 300 <= status <= 399 and "location" in headers:
                if redirect_count >= MAX_REDIRECTS:
                    raise FetchError("redirect limit exceeded")
                try:
                    candidate = urljoin(current, headers["location"])
                except ValueError as exc:
                    raise FetchError("redirect target was malformed") from exc
                try:
                    current = validate_public_url(candidate, domain, check_dns=False)
                except ConfigError as exc:
                    raise FetchError(f"unsafe redirect blocked: {exc}") from exc
                continue
            content_length = headers.get("content-length")
            if content_length:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise FetchError("response Content-Length was invalid") from exc
                if declared < 0 or declared > max_bytes:
                    raise FetchError(f"response Content-Length exceeded maximum of {max_bytes} bytes")
            mime, _charset = parse_content_type(headers.get("content-type", ""))
            if mime not in {"text/html", "application/xhtml+xml"}:
                raise FetchError(f"response was not HTML (parsed MIME: {mime or 'missing'})")
            try:
                body = read_bounded(response, max_bytes, deadline=deadline, connection=connection)
            except (socket.timeout, TimeoutError) as exc:
                raise TransientFetchError("end-to-end deadline expired while reading response body") from exc
            return PageResult(safe_url, current, status, headers, body, None)
        finally:
            connection.close()
    raise FetchError("redirect limit exceeded")


def fetch_page(url: str, domain: str, timeout: float, max_bytes: int, resolver: Callable[[str], list[str]] = resolve_addresses) -> PageResult:
    deadline = time.monotonic() + timeout
    try:
        safe_url = validate_public_url(url, domain, check_dns=False)
    except ConfigError as exc:
        return PageResult("[rejected-url]", None, None, {}, b"", str(exc))
    try:
        addresses = _resolve_with_deadline(domain, resolver, deadline)
        last_error: BaseException | None = None
        for attempt in range(MAX_GET_ATTEMPTS):
            try:
                return _fetch_chain_once(
                    safe_url,
                    domain,
                    addresses,
                    deadline,
                    max_bytes,
                    retry_transient_status=attempt < MAX_GET_ATTEMPTS - 1,
                )
            except TransientFetchError as exc:
                last_error = exc
                _remaining(deadline)
        raise TransientFetchError("GET failed after bounded retry") from last_error
    except UnsafeDestinationError:
        raise
    except (ConfigError, FetchError, OSError) as exc:
        reason = str(exc).replace("\r", " ").replace("\n", " ")[:500]
        return PageResult(safe_url, None, None, {}, b"", reason)


def _safe_reference(base_url: str, value: str) -> str | None:
    try:
        joined = urljoin(base_url, value)
        parts = urlsplit(joined)
        _ = parts.port
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        return normalize_url(joined)
    except (ConfigError, TypeError, ValueError):
        return None


class HTMLSnapshot(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self._title_depth = 0
        self._stack: list[tuple[str, bool]] = []
        self.text_parts: list[str] = []
        self.canonical: str | None = None
        self.robots_values: list[str] = []
        self.structured_data_present = False
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.references: set[str] = set()

    def _parent_suppressed(self) -> bool:
        return self._stack[-1][1] if self._stack else False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        self.elements.append((tag, attr_map))
        if tag == "title":
            self._title_depth += 1
        style = re.sub(r"\s+", "", attr_map.get("style", "").lower())
        suppressed = bool(
            self._parent_suppressed() or tag in {"head", "script", "style", "noscript", "template"}
            or "hidden" in attr_map or attr_map.get("aria-hidden", "").lower() == "true"
            or "display:none" in style or "visibility:hidden" in style
        )
        if tag not in VOID_TAGS:
            self._stack.append((tag, suppressed))
        if tag == "link" and "canonical" in attr_map.get("rel", "").lower().split() and self.canonical is None:
            href = attr_map.get("href")
            if href:
                self.canonical = _safe_reference(self.base_url, href) or "malformed"
        if tag == "meta" and attr_map.get("name", "").lower() == "robots":
            self.robots_values.append(attr_map.get("content", "").lower())
        if tag == "script" and attr_map.get("type", "").split(";", 1)[0].strip().lower() == "application/ld+json":
            self.structured_data_present = True
        for name in ("href", "src"):
            value = attr_map.get(name)
            if value:
                reference = _safe_reference(self.base_url, value)
                if reference:
                    self.references.add(reference)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title" and self._title_depth:
            self._title_depth -= 1
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                del self._stack[index:]
                break

    def handle_data(self, data: str) -> None:
        if self._title_depth:
            self.title_parts.append(data)
        if not self._parent_suppressed():
            self.text_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(" ".join(self.title_parts).split())

    @property
    def text(self) -> str:
        return " ".join(" ".join(self.text_parts).split())

    def has_selector(self, selector: str) -> bool:
        parsed = SELECTOR_PATTERN.fullmatch(selector)
        if not parsed:
            return False
        wanted_tag, wanted_id, wanted_class = parsed.group("tag", "id", "class")
        wanted_tag = wanted_tag.lower() if wanted_tag else None
        for tag, attrs in self.elements:
            if wanted_tag and tag != wanted_tag:
                continue
            if wanted_id and attrs.get("id") != wanted_id:
                continue
            if wanted_class and wanted_class not in attrs.get("class", "").split():
                continue
            return True
        return False


def decode_html(body: bytes, content_type: str) -> str:
    _mime, charset = parse_content_type(content_type)
    try:
        decoded = body.decode(charset or "utf-8", errors="replace")
    except (LookupError, UnicodeError):
        decoded = body.decode("utf-8", errors="replace")
    return SURROGATE_PATTERN.sub("\uFFFD", decoded)


def _snapshot(page: PageResult) -> HTMLSnapshot:
    parser = HTMLSnapshot(page.final_url or page.requested_url)
    parser.feed(decode_html(page.body, page.headers.get("content-type", "")))
    parser.close()
    return parser


def _observe(check: dict, page: PageResult, snapshot: HTMLSnapshot) -> tuple[str, str]:
    kind = check["type"]
    if kind == "status":
        return str(page.status), f"HTTP GET returned {page.status}; final URL {page.final_url}"
    if kind == "title":
        return snapshot.title, "HTML title element, whitespace normalized"
    if kind == "canonical":
        return snapshot.canonical or "absent", "first HTML link rel=canonical, resolved absolute; malformed is explicit"
    if kind == "robots-indexability":
        values = snapshot.robots_values + [page.headers.get("x-robots-tag", "").lower()]
        noindex = any("noindex" in re.split(r"[,;\s]+", value) for value in values)
        return ("noindex" if noindex else "indexable"), "HTML meta robots plus X-Robots-Tag; no robots.txt crawl"
    if kind == "structured-data-presence":
        return ("present" if snapshot.structured_data_present else "absent"), "HTML script[type=application/ld+json] presence only; JSON was not executed"
    if kind == "text":
        return ("present" if check["value"] in snapshot.text else "absent"), f"literal static non-hidden HTML text match for {check['value']!r}"
    if kind == "selector":
        return ("present" if snapshot.has_selector(check["value"]) else "absent"), f"static HTML selector match for {check['value']!r}"
    if kind == "asset-reference":
        return ("present" if check["value"] in snapshot.references else "absent"), f"static href/src reference for {check['value']}; asset was not fetched"
    raise AssertionError(f"unhandled check type: {kind}")


def baseline_map(rows: Iterable[CheckResult]) -> dict[tuple[str, str], str]:
    return {(row.url, row.check): row.observed for row in rows}


def evaluate(config: dict, pages: dict[str, PageResult], timestamp: str, baseline: dict[tuple[str, str], str] | None = None) -> list[CheckResult]:
    validate_timestamp(timestamp)
    url_by_id = {entry["id"]: entry["url"] for entry in config["urls"]}
    snapshots: dict[str, HTMLSnapshot] = {}
    parse_failures: set[str] = set()
    rows = []
    for check in config["checks"]:
        url = url_by_id[check["url"]]
        page = pages[check["url"]]
        expected = baseline.get((url, check["id"])) if baseline is not None else check["expected"]
        if expected is None:
            raise ConfigError("baseline has no observation for a configured URL/check")
        if page.error is not None:
            rows.append(CheckResult(url, timestamp, check["id"], expected, "unavailable", "UNAVAILABLE", f"GET unavailable: {page.error}"))
            continue
        if check["type"] == "status":
            observed = str(page.status)
            evidence = f"HTTP GET returned {page.status}; final URL {page.final_url}"
            rows.append(CheckResult(
                url, timestamp, check["id"], expected, observed,
                "PASS" if observed == expected else "DRIFT", evidence,
            ))
            continue
        if check["url"] not in snapshots and check["url"] not in parse_failures:
            try:
                snapshots[check["url"]] = _snapshot(page)
            except Exception:
                parse_failures.add(check["url"])
        if check["url"] in parse_failures:
            rows.append(CheckResult(
                url, timestamp, check["id"], expected, "unavailable", "UNAVAILABLE",
                "HTML response could not be parsed safely",
            ))
            continue
        try:
            observed, evidence = _observe(check, page, snapshots[check["url"]])
        except Exception:
            rows.append(CheckResult(
                url, timestamp, check["id"], expected, "unavailable", "UNAVAILABLE",
                "static observation could not be evaluated safely",
            ))
            continue
        rows.append(CheckResult(url, timestamp, check["id"], expected, observed, "PASS" if observed == expected else "DRIFT", evidence))
    return rows


def safe_csv_cell(value: object) -> str:
    text = str(value)
    return "'" + text if text.startswith("'") or text.startswith(FORMULA_PREFIXES) else text


def restore_csv_cell(value: str) -> str:
    if value.startswith("''") or (value.startswith("'") and value[1:].startswith(FORMULA_PREFIXES)):
        return value[1:]
    return value


def write_csv(path: Path, rows: Iterable[CheckResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: safe_csv_cell(value) for key, value in row._asdict().items()})


def read_csv_records(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != CSV_FIELDS:
                raise ConfigError("baseline CSV schema does not exactly match the required fields")
            return [_restore_csv_row(row) for row in reader]
    except csv.Error as exc:
        raise ConfigError("baseline CSV is malformed or exceeds the artifact cell bound") from exc


def _restore_csv_row(row: dict) -> dict[str, str]:
    if set(row) != set(CSV_FIELDS) or any(not isinstance(row.get(key), str) for key in CSV_FIELDS):
        raise ConfigError("CSV row does not contain exactly one text cell for every required field")
    return {key: restore_csv_cell(row[key]) for key in CSV_FIELDS}


def _read_csv_records_bytes(payload: bytes) -> list[dict[str, str]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError("baseline CSV is not valid UTF-8") from exc
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if reader.fieldnames != CSV_FIELDS:
            raise ConfigError("baseline CSV schema does not exactly match the required fields")
        return [_restore_csv_row(row) for row in reader]
    except csv.Error as exc:
        raise ConfigError("baseline CSV is malformed or exceeds the artifact cell bound") from exc


def markdown_cell(value: object) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    escaped = html.escape(text, quote=True).replace("\\", "\\\\")
    for character in "`![]()":
        escaped = escaped.replace(character, "\\" + character)
    escaped = escaped.replace("|", "\\|")
    return escaped.replace("\n", "<br>")


def write_exceptions(path: Path, rows: Iterable[CheckResult]) -> None:
    exceptions = [row for row in rows if row.status != "PASS"]
    lines = [
        "# Public Storefront QA exceptions", "",
        "Only DRIFT and UNAVAILABLE rows appear below. Full PASS evidence is retained in the CSV.", "",
        "| URL | Timestamp | Check | Expected | Observed | Status | Evidence |",
        "|---|---|---|---|---|---|---|",
    ]
    if exceptions:
        lines.extend("| " + " | ".join(markdown_cell(value) for value in row) + " |" for row in exceptions)
    else:
        lines.append("| - | - | - | - | - | PASS | No exceptions. See CSV for full evidence. |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _validate_unicode_scalar_strings(value: object, label: str) -> None:
    pending = [value]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ConfigError(f"{label} contains invalid Unicode") from exc
            continue
        if isinstance(current, (dict, list)):
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
        if isinstance(current, dict):
            for key, item in current.items():
                pending.extend((key, item))
        elif isinstance(current, list):
            pending.extend(current)


def _strict_json_object(payload: bytes, label: str) -> dict:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ConfigError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ConfigError(f"{label} contains a nonstandard JSON constant")),
        )
    except ConfigError:
        raise
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{label} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{label} is not valid JSON") from exc
    except (ValueError, RecursionError) as exc:
        raise ConfigError(f"{label} is structurally outside the supported JSON bounds") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a JSON object")
    _validate_unicode_scalar_strings(value, label)
    return value


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_run_records(records: list[dict[str, str]]) -> None:
    if not 1 <= len(records) <= MAX_CHECKS:
        raise ConfigError("rerun row count is outside the supported scope")
    seen = set()
    timestamps = set()
    for record in records:
        if list(record.keys()) != CSV_FIELDS:
            raise ConfigError("rerun row schema is invalid")
        if record["status"] not in ALLOWED_STATUSES:
            raise ConfigError("rerun contains an invalid status")
        if record["status"] == "PASS" and record["observed"] != record["expected"]:
            raise ConfigError("rerun PASS row does not match its expected observation")
        if record["status"] == "DRIFT" and record["observed"] == record["expected"]:
            raise ConfigError("rerun DRIFT row matches its expected observation")
        if record["status"] == "UNAVAILABLE" and record["observed"] != "unavailable":
            raise ConfigError("rerun UNAVAILABLE row has an invalid observation")
        validate_timestamp(record["timestamp"])
        timestamps.add(record["timestamp"])
        key = (record["url"], record["check"])
        if key in seen:
            raise ConfigError("rerun contains a duplicate URL/check row")
        seen.add(key)
    if len(timestamps) != 1:
        raise ConfigError("rerun rows must share one timestamp")


def _load_verified_capture(manifest_path: Path, mode: str) -> VerifiedCapture:
    if mode not in {"baseline", "scheduled-rerun"}:
        raise ConfigError("unsupported capture mode")
    if manifest_path.name != "output-manifest.json":
        raise ConfigError(f"{mode} input must name output-manifest.json")
    csv_name = "baseline.csv" if mode == "baseline" else "rerun.csv"
    meta_name = "baseline.meta.json" if mode == "baseline" else "rerun.meta.json"
    expected_files = {csv_name, "exceptions.md", meta_name}
    manifest_path = manifest_path.resolve()
    directory = manifest_path.parent
    try:
        manifest_payload = manifest_path.read_bytes()
        payloads = {name: (directory / name).read_bytes() for name in expected_files}
    except OSError as exc:
        raise ConfigError(f"{mode} artifact bundle is missing or unreadable") from exc
    manifest = _strict_json_object(manifest_payload, f"{mode} manifest")
    if set(manifest) != {"schema", "mode", "tool_version", "committed_at", "files"}:
        raise ConfigError(f"{mode} manifest schema is invalid")
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("mode") != mode:
        raise ConfigError(f"{mode} manifest identity is invalid")
    manifest_version = manifest.get("tool_version")
    if not isinstance(manifest_version, str) or re.fullmatch(r"\d+\.\d+\.\d+", manifest_version) is None:
        raise ConfigError(f"{mode} manifest tool version is invalid")
    validate_timestamp(manifest.get("committed_at"))
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected_files or not all(_valid_sha256(value) for value in files.values()):
        raise ConfigError(f"{mode} manifest file set is invalid")
    for name, payload in payloads.items():
        if hashlib.sha256(payload).hexdigest() != files[name]:
            raise ConfigError(f"{mode} artifact digest does not match its manifest")

    metadata = _strict_json_object(payloads[meta_name], f"{mode} metadata")
    common = {"schema", "mode", "tool_version", "config_digest", "csv_sha256", "fields", "row_count", "captured_at"}
    if mode == "baseline":
        expected_metadata = common | {"earliest_scheduled_evidence_at"}
        schema = BASELINE_SCHEMA
    else:
        legacy_metadata = common | {
            "evidence_class", "qualifies_as_scheduled_evidence",
            "baseline_csv_sha256", "baseline_captured_at",
        }
        schedule_metadata = legacy_metadata | {"schedule_sha256", "window_id", "scheduled_for"}
        expected_metadata = legacy_metadata if set(metadata) == legacy_metadata else schedule_metadata
        schema = RUN_SCHEMA
    if set(metadata) != expected_metadata or metadata.get("schema") != schema or metadata.get("mode") != mode:
        raise ConfigError(f"{mode} metadata schema is invalid")
    if metadata.get("tool_version") != manifest_version:
        raise ConfigError(f"{mode} metadata and manifest tool versions do not match")
    if not _valid_sha256(metadata.get("config_digest")) or not _valid_sha256(metadata.get("csv_sha256")):
        raise ConfigError(f"{mode} metadata digest is invalid")
    if metadata.get("fields") != CSV_FIELDS:
        raise ConfigError(f"{mode} metadata fields are invalid")
    if not isinstance(metadata.get("row_count"), int) or isinstance(metadata.get("row_count"), bool):
        raise ConfigError(f"{mode} metadata row count is invalid")
    captured_at = metadata.get("captured_at")
    validate_timestamp(captured_at)
    csv_sha256 = hashlib.sha256(payloads[csv_name]).hexdigest()
    if metadata["csv_sha256"] != csv_sha256:
        raise ConfigError(f"{mode} CSV digest does not match its metadata")
    records = _read_csv_records_bytes(payloads[csv_name])
    if metadata["row_count"] != len(records):
        raise ConfigError(f"{mode} row count does not match its metadata")
    if {record["timestamp"] for record in records} != {captured_at}:
        raise ConfigError(f"{mode} row timestamps do not match its metadata")

    baseline_csv_sha256 = None
    baseline_captured_at = None
    earliest_scheduled_evidence_at = None
    schedule_sha256 = None
    window_id = None
    scheduled_for = None
    if mode == "baseline":
        validate_baseline_records(records)
        earliest_scheduled_evidence_at = metadata.get("earliest_scheduled_evidence_at")
        validate_timestamp(earliest_scheduled_evidence_at)
    else:
        _validate_run_records(records)
        if metadata.get("evidence_class") != "scheduled-change-evidence" or metadata.get("qualifies_as_scheduled_evidence") is not True:
            raise ConfigError("rerun is not scheduled change evidence")
        baseline_csv_sha256 = metadata.get("baseline_csv_sha256")
        baseline_captured_at = metadata.get("baseline_captured_at")
        if not _valid_sha256(baseline_csv_sha256):
            raise ConfigError("scheduled-rerun baseline digest is invalid")
        validate_timestamp(baseline_captured_at)
        if "schedule_sha256" in metadata:
            schedule_sha256 = metadata.get("schedule_sha256")
            window_id = metadata.get("window_id")
            scheduled_for = metadata.get("scheduled_for")
            if not _valid_sha256(schedule_sha256):
                raise ConfigError("scheduled-rerun schedule digest is invalid")
            _require_id(window_id, "scheduled-rerun window id")
            validate_timestamp(scheduled_for)

    return VerifiedCapture(
        mode=mode,
        rows=records,
        csv_sha256=csv_sha256,
        manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        captured_at=captured_at,
        config_digest=metadata["config_digest"],
        baseline_csv_sha256=baseline_csv_sha256,
        baseline_captured_at=baseline_captured_at,
        earliest_scheduled_evidence_at=earliest_scheduled_evidence_at,
        tool_version=manifest_version,
        schedule_sha256=schedule_sha256,
        window_id=window_id,
        scheduled_for=scheduled_for,
    )


def _canonical_json_sha256(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_month_schedule(
    path: Path,
    config: dict,
    baseline: VerifiedCapture,
) -> LoadedSchedule:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ConfigError("monthly schedule is missing or unreadable") from exc
    value = _strict_json_object(payload, "monthly schedule")
    required = {
        "schema", "period_id", "period_starts_at", "period_ends_at", "config_digest",
        "baseline_csv_sha256", "baseline_captured_at", "windows",
    }
    if set(value) != required or value.get("schema") != MONTH_SCHEDULE_SCHEMA:
        raise ConfigError("monthly schedule schema is invalid")
    _require_id(value.get("period_id"), "monthly schedule period id")
    expected_config_digest = config_digest(config)
    if value.get("config_digest") != expected_config_digest or value.get("config_digest") != baseline.config_digest:
        raise ConfigError("monthly schedule config digest does not match the frozen config")
    if value.get("baseline_csv_sha256") != baseline.csv_sha256 or value.get("baseline_captured_at") != baseline.captured_at:
        raise ConfigError("monthly schedule baseline lineage does not match the frozen baseline")
    period_start = validate_timestamp(value.get("period_starts_at"))
    period_end = validate_timestamp(value.get("period_ends_at"))
    if period_start >= period_end:
        raise ConfigError("monthly schedule period is invalid")
    windows = value.get("windows")
    if not isinstance(windows, list) or len(windows) != 4:
        raise ConfigError("monthly schedule requires exactly four windows")
    recorded_earliest = validate_timestamp(baseline.earliest_scheduled_evidence_at)
    calculated_earliest = _checked_add_hours(
        validate_timestamp(baseline.captured_at), config["scheduled_evidence_minimum_hours"],
    )
    if recorded_earliest != calculated_earliest:
        raise ConfigError("baseline scheduled evidence time does not match the frozen config")
    earliest = calculated_earliest
    windows_by_id: dict[str, dict] = {}
    previous_close = None
    for window in windows:
        if not isinstance(window, dict) or set(window) != {"id", "opens_at", "scheduled_for", "closes_at"}:
            raise ConfigError("monthly schedule window schema is invalid")
        window_id = _require_id(window.get("id"), "monthly schedule window id")
        if window_id in windows_by_id:
            raise ConfigError("monthly schedule window ids must be unique")
        opens_at = validate_timestamp(window.get("opens_at"))
        scheduled_for = validate_timestamp(window.get("scheduled_for"))
        closes_at = validate_timestamp(window.get("closes_at"))
        if not opens_at <= scheduled_for < closes_at:
            raise ConfigError("monthly schedule window times are invalid")
        if opens_at < earliest:
            raise ConfigError("monthly schedule window opens before baseline eligibility")
        if previous_close is not None and previous_close > opens_at:
            raise ConfigError("monthly schedule windows overlap or are out of order")
        previous_close = closes_at
        windows_by_id[window_id] = window
    if validate_timestamp(windows[0]["opens_at"]) != period_start or validate_timestamp(windows[-1]["closes_at"]) != period_end:
        raise ConfigError("monthly schedule period must exactly bound its four windows")
    return LoadedSchedule(value=value, sha256=_canonical_json_sha256(value), windows_by_id=windows_by_id)


def validate_baseline_records(records: list[dict[str, str]]) -> None:
    if not 1 <= len(records) <= MAX_CHECKS:
        raise ConfigError("baseline row count is outside the supported scope")
    seen = set()
    timestamps = set()
    for record in records:
        if list(record.keys()) != CSV_FIELDS:
            raise ConfigError("baseline row schema is invalid")
        if record["status"] not in ALLOWED_STATUSES:
            raise ConfigError("baseline contains an invalid status")
        if record["status"] == "UNAVAILABLE":
            raise ConfigError("baseline contains an unavailable observation")
        if record["status"] == "PASS" and record["observed"] != record["expected"]:
            raise ConfigError("baseline PASS row does not match its expected observation")
        if record["status"] == "DRIFT" and record["observed"] == record["expected"]:
            raise ConfigError("baseline DRIFT row matches its expected observation")
        validate_timestamp(record["timestamp"])
        timestamps.add(record["timestamp"])
        key = (record["url"], record["check"])
        if key in seen:
            raise ConfigError("baseline contains a duplicate URL/check row")
        seen.add(key)
    if len(timestamps) != 1:
        raise ConfigError("baseline rows must share one timestamp")


def _baseline_metadata(csv_path: Path, rows: list[CheckResult], config: dict, timestamp: str) -> dict:
    baseline_time = validate_timestamp(timestamp)
    earliest = _checked_add_hours(baseline_time, config["scheduled_evidence_minimum_hours"])
    return {
        "schema": BASELINE_SCHEMA, "mode": "baseline", "tool_version": TOOL_VERSION,
        "config_digest": config_digest(config),
        "csv_sha256": _sha256_file(csv_path), "fields": CSV_FIELDS, "row_count": len(rows),
        "captured_at": timestamp, "earliest_scheduled_evidence_at": earliest.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write_run_artifacts(
    out: Path,
    mode: str,
    rows: list[CheckResult],
    config: dict,
    timestamp: str,
    baseline_provenance: LoadedBaseline | None = None,
    schedule_binding: dict[str, str] | None = None,
) -> dict:
    if mode not in {"baseline", "rerun", "scheduled-rerun"}:
        raise ConfigError("unsupported run mode")
    validate_timestamp(timestamp)
    fresh_output = schedule_binding is not None
    if fresh_output:
        if out.exists():
            raise ConfigError("schedule-bound rerun requires a fresh output directory")
        out.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=f".{out.name}.stage-", dir=out.parent))
    else:
        out.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".storefront-qa-stage-", dir=out))
    csv_name = "baseline.csv" if mode == "baseline" else "rerun.csv"
    meta_name = "baseline.meta.json" if mode == "baseline" else "rerun.meta.json"
    try:
        csv_stage, md_stage, meta_stage = stage / csv_name, stage / "exceptions.md", stage / meta_name
        write_csv(csv_stage, rows)
        write_exceptions(md_stage, rows)
        if mode == "baseline":
            metadata = _baseline_metadata(csv_stage, rows, config, timestamp)
        else:
            if baseline_provenance is None:
                raise ConfigError("rerun baseline provenance is required")
            metadata = {
                "schema": RUN_SCHEMA, "mode": mode, "tool_version": TOOL_VERSION,
                "evidence_class": "scheduled-change-evidence" if mode == "scheduled-rerun" else "immediate-mechanics-proof",
                "qualifies_as_scheduled_evidence": mode == "scheduled-rerun",
                "config_digest": config_digest(config), "csv_sha256": _sha256_file(csv_stage),
                "fields": CSV_FIELDS, "row_count": len(rows), "captured_at": timestamp,
                "baseline_csv_sha256": baseline_provenance.csv_sha256,
                "baseline_captured_at": baseline_provenance.captured_at,
            }
            if schedule_binding is not None:
                if mode != "scheduled-rerun" or set(schedule_binding) != {"schedule_sha256", "window_id", "scheduled_for"}:
                    raise ConfigError("scheduled rerun binding is invalid")
                if not _valid_sha256(schedule_binding["schedule_sha256"]):
                    raise ConfigError("scheduled rerun schedule digest is invalid")
                _require_id(schedule_binding["window_id"], "schedule window id")
                validate_timestamp(schedule_binding["scheduled_for"])
                metadata.update(schedule_binding)
        _write_json(meta_stage, metadata)
        manifest = {
            "schema": MANIFEST_SCHEMA, "mode": mode, "tool_version": TOOL_VERSION,
            "committed_at": utc_timestamp(),
            "files": {csv_name: _sha256_file(csv_stage), "exceptions.md": _sha256_file(md_stage), meta_name: _sha256_file(meta_stage)},
        }
        _write_json(stage / "output-manifest.json", manifest)
        targets = [csv_name, "exceptions.md", meta_name, "output-manifest.json"]
        if fresh_output:
            if out.exists():
                raise ConfigError("schedule-bound output directory appeared during staging")
            os.rename(stage, out)
            return metadata
        backups: dict[str, Path] = {}
        committed: list[str] = []
        try:
            for name in targets:
                target = out / name
                if target.exists():
                    backup = stage / f"backup-{name}"
                    os.replace(target, backup)
                    backups[name] = backup
                os.replace(stage / name, target)
                committed.append(name)
        except BaseException:
            for name in reversed(committed):
                target = out / name
                if target.exists():
                    target.unlink()
            for name, backup in backups.items():
                if backup.exists():
                    os.replace(backup, out / name)
            raise
        return metadata
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _load_baseline(
    path: Path,
    expected_config_digest: str,
    expected_keys: set[tuple[str, str]] | None = None,
    expected_values: dict[tuple[str, str], str] | None = None,
) -> LoadedBaseline:
    try:
        metadata = _strict_json_object(
            path.with_name("baseline.meta.json").read_bytes(), "baseline metadata",
        )
    except OSError as exc:
        raise ConfigError("baseline metadata is missing or invalid") from exc
    required = {"schema", "mode", "config_digest", "csv_sha256", "fields", "row_count", "captured_at", "earliest_scheduled_evidence_at"}
    metadata_fields = set(metadata)
    if metadata_fields not in (required, required | {"tool_version"}) or metadata.get("schema") != BASELINE_SCHEMA or metadata.get("mode") != "baseline":
        raise ConfigError("baseline metadata schema is invalid")
    if metadata["config_digest"] != expected_config_digest:
        raise ConfigError("baseline config digest does not match the current normalized config")
    if metadata["fields"] != CSV_FIELDS:
        raise ConfigError("baseline metadata fields are invalid")
    validate_timestamp(metadata["captured_at"])
    validate_timestamp(metadata["earliest_scheduled_evidence_at"])
    try:
        csv_payload = path.read_bytes()
    except OSError as exc:
        raise ConfigError("baseline CSV is missing or unreadable") from exc
    csv_sha256 = hashlib.sha256(csv_payload).hexdigest()
    if csv_sha256 != metadata["csv_sha256"]:
        raise ConfigError("baseline CSV digest does not match its metadata")
    records = _read_csv_records_bytes(csv_payload)
    validate_baseline_records(records)
    if metadata["row_count"] != len(records):
        raise ConfigError("baseline row count does not match its metadata")
    if {record["timestamp"] for record in records} != {metadata["captured_at"]}:
        raise ConfigError("baseline timestamps do not match metadata")
    result = {(record["url"], record["check"]): record["observed"] for record in records}
    if expected_keys is not None and set(result) != expected_keys:
        raise ConfigError("baseline rows do not exactly match the configured URL/check set")
    if expected_values is not None:
        record_map = {(record["url"], record["check"]): record for record in records}
        if set(record_map) != set(expected_values) or any(
            record_map[key]["expected"] != expected
            for key, expected in expected_values.items()
        ):
            raise ConfigError("baseline expected values do not match the normalized config")
    return LoadedBaseline(result, csv_sha256, metadata["captured_at"])


def load_baseline(
    path: Path,
    expected_config_digest: str,
    expected_keys: set[tuple[str, str]] | None = None,
    expected_values: dict[tuple[str, str], str] | None = None,
) -> dict[tuple[str, str], str]:
    return _load_baseline(path, expected_config_digest, expected_keys, expected_values).observations


def enforce_scheduled_evidence_gate(baseline_time: datetime, scheduled_for: datetime, now: datetime, minimum_age_hours: int) -> None:
    earliest = _checked_add_hours(baseline_time, minimum_age_hours)
    if scheduled_for < earliest:
        raise ConfigError("scheduled date is earlier than the required baseline age")
    if now < scheduled_for or now < earliest:
        raise ConfigError("scheduled evidence gate is not open")


def _config_keys(config: dict) -> set[tuple[str, str]]:
    urls = {entry["id"]: entry["url"] for entry in config["urls"]}
    return {(urls[check["url"]], check["id"]) for check in config["checks"]}


def _config_expectations(config: dict) -> dict[tuple[str, str], str]:
    urls = {entry["id"]: entry["url"] for entry in config["urls"]}
    return {
        (urls[check["url"]], check["id"]): check["expected"]
        for check in config["checks"]
    }


def _require_verified_baseline_matches_config(
    baseline: VerifiedCapture,
    config: dict,
    error_message: str,
) -> None:
    expectations = _config_expectations(config)
    rows = {(row["url"], row["check"]): row for row in baseline.rows}
    if (
        baseline.config_digest != config_digest(config)
        or set(rows) != set(expectations)
        or any(rows[key]["expected"] != expected for key, expected in expectations.items())
    ):
        raise ConfigError(error_message)


def _scheduled_preflight(raw: dict, baseline_path: Path, scheduled_for: str, now: datetime | None = None) -> None:
    """Evaluate the local time gate before config validation can resolve DNS."""
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    minimum_age = raw.get("scheduled_evidence_minimum_hours", 72)
    if not isinstance(minimum_age, int) or isinstance(minimum_age, bool) or not 1 <= minimum_age <= 720:
        raise ConfigError("scheduled_evidence_minimum_hours must be an integer between 1 and 720")
    try:
        metadata = _strict_json_object(
            baseline_path.with_name("baseline.meta.json").read_bytes(), "baseline metadata",
        )
    except OSError as exc:
        raise ConfigError("baseline metadata is missing or invalid") from exc
    if not isinstance(metadata, dict) or metadata.get("schema") != BASELINE_SCHEMA or metadata.get("mode") != "baseline":
        raise ConfigError("baseline metadata schema is invalid")
    baseline_time = validate_timestamp(metadata.get("captured_at"))
    recorded_earliest = validate_timestamp(metadata.get("earliest_scheduled_evidence_at"))
    calculated_earliest = _checked_add_hours(baseline_time, minimum_age)
    if recorded_earliest != calculated_earliest:
        raise ConfigError("baseline scheduled evidence time does not match the local config gate")
    enforce_scheduled_evidence_gate(
        baseline_time,
        validate_timestamp(scheduled_for),
        now or datetime.now(timezone.utc),
        minimum_age,
    )


def _monthly_scheduled_preflight(
    raw: dict,
    baseline_path: Path,
    schedule_path: Path,
    window_id: str,
    out: Path,
    now: datetime | None = None,
) -> tuple[dict, VerifiedCapture, LoadedSchedule, dict]:
    lexical_baseline = Path(os.path.abspath(baseline_path))
    if lexical_baseline.name != "baseline.csv":
        raise ConfigError("monthly scheduled rerun requires the baseline.csv sibling of its verified manifest")
    manifest_path = lexical_baseline.with_name("output-manifest.json")
    resolved_manifest = manifest_path.resolve()
    supplied_baseline = baseline_path.resolve()
    verified_baseline = (resolved_manifest.parent / "baseline.csv").resolve()
    if supplied_baseline != verified_baseline:
        raise ConfigError("monthly scheduled rerun baseline is not the sibling of its verified manifest")
    baseline_directories = {
        lexical_baseline.parent,
        lexical_baseline.parent.resolve(),
        supplied_baseline.parent,
        resolved_manifest.parent,
        verified_baseline.parent,
    }
    out_resolved = out.resolve()
    out_lexical = Path(os.path.abspath(out))
    if any(
        candidate == directory or directory in candidate.parents
        for candidate in (out_lexical, out_resolved)
        for directory in baseline_directories
    ):
        raise ConfigError("monthly scheduled rerun output must not alias the baseline bundle")
    if out.exists():
        raise ConfigError("monthly scheduled rerun requires a fresh output directory")
    config = validate_config(raw, check_dns=False)
    baseline = _load_verified_capture(manifest_path, "baseline")
    _require_verified_baseline_matches_config(
        baseline, config, "monthly scheduled rerun baseline does not match the frozen config",
    )
    schedule = _load_month_schedule(schedule_path, config, baseline)
    if window_id not in schedule.windows_by_id:
        raise ConfigError("monthly schedule does not contain the requested window")
    window = schedule.windows_by_id[window_id]
    current = now or datetime.now(timezone.utc)
    scheduled_for = validate_timestamp(window["scheduled_for"])
    closes_at = validate_timestamp(window["closes_at"])
    if current < scheduled_for or current >= closes_at:
        raise ConfigError("monthly scheduled rerun window is not open")
    return config, baseline, schedule, window


def _build_month_end_ledger(
    baseline: VerifiedCapture,
    runs: list[VerifiedCapture],
    schedule: LoadedSchedule,
    now: datetime | None = None,
) -> list[dict[str, str]]:
    if len(runs) != 4:
        raise ConfigError("month-end ledger requires exactly four scheduled reruns")
    by_window = {run.window_id: run for run in runs}
    window_ids = [window["id"] for window in schedule.value["windows"]]
    if None in by_window or len(by_window) != 4 or set(by_window) != set(window_ids):
        raise ConfigError("month-end ledger requires one schedule-bound rerun for each window")
    runs = [by_window[window_id] for window_id in window_ids]
    current_time = now or datetime.now(timezone.utc)
    if current_time < validate_timestamp(schedule.value["period_ends_at"]):
        raise ConfigError("month-end ledger period has not ended")
    manifests = [run.manifest_sha256 for run in runs]
    csv_hashes = [run.csv_sha256 for run in runs]
    captures = [run.captured_at for run in runs]
    if len(set(manifests)) != 4 or len(set(csv_hashes)) != 4 or len(set(captures)) != 4:
        raise ConfigError("month-end ledger source runs must have unique manifests, CSVs, and timestamps")

    baseline_by_key = {(row["url"], row["check"]): row for row in baseline.rows}
    baseline_keys = set(baseline_by_key)
    if not baseline_keys:
        raise ConfigError("month-end ledger baseline is empty")
    state = {
        key: {
            "captured_at": baseline.captured_at,
            "observed": row["observed"],
            "status": "PASS",
        }
        for key, row in baseline_by_key.items()
    }
    ledger_rows: list[dict[str, str]] = []
    previous_capture = validate_timestamp(baseline.captured_at)
    for window, run in zip(schedule.value["windows"], runs, strict=True):
        if run.config_digest != baseline.config_digest:
            raise ConfigError("scheduled rerun config digest does not match the frozen baseline")
        if run.baseline_csv_sha256 != baseline.csv_sha256 or run.baseline_captured_at != baseline.captured_at:
            raise ConfigError("scheduled rerun baseline lineage does not match the frozen baseline")
        if run.schedule_sha256 != schedule.sha256 or run.window_id != window["id"] or run.scheduled_for != window["scheduled_for"]:
            raise ConfigError("scheduled rerun does not match its frozen monthly schedule window")
        captured_at = validate_timestamp(run.captured_at)
        if captured_at <= previous_capture:
            raise ConfigError("scheduled rerun capture timestamps must increase in schedule order")
        if captured_at > current_time:
            raise ConfigError("scheduled rerun capture timestamp is in the future")
        if not validate_timestamp(window["scheduled_for"]) <= captured_at < validate_timestamp(window["closes_at"]):
            raise ConfigError("scheduled rerun capture is outside its agreed schedule window")
        previous_capture = captured_at
        by_key = {(row["url"], row["check"]): row for row in run.rows}
        if set(by_key) != baseline_keys:
            raise ConfigError("scheduled rerun rows do not match the frozen baseline scope")
        for key in sorted(baseline_keys):
            row = by_key[key]
            if row["expected"] != baseline_by_key[key]["observed"]:
                raise ConfigError("scheduled rerun expected value does not match the frozen baseline")
            previous = state[key]
            event_type = None
            if previous["status"] != "UNAVAILABLE" and row["status"] == "UNAVAILABLE":
                event_type = "BECAME_UNAVAILABLE"
            elif previous["status"] == "UNAVAILABLE" and row["status"] != "UNAVAILABLE":
                event_type = "AVAILABLE_AGAIN"
            elif (previous["observed"], previous["status"]) != (row["observed"], row["status"]):
                event_type = "OBSERVATION_CHANGED"
            if event_type is not None:
                ledger_rows.append({
                    "run": run.window_id,
                    "captured_at": run.captured_at,
                    "previous_captured_at": previous["captured_at"],
                    "url": row["url"],
                    "check": row["check"],
                    "baseline_observed": baseline_by_key[key]["observed"],
                    "previous_observed": previous["observed"],
                    "observed": row["observed"],
                    "previous_status": previous["status"],
                    "status": row["status"],
                    "event_type": event_type,
                    "evidence": row["evidence"],
                    "source_csv_sha256": run.csv_sha256,
                })
            state[key] = {
                "captured_at": run.captured_at,
                "observed": row["observed"],
                "status": row["status"],
            }
    return ledger_rows


def _write_ledger_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: safe_csv_cell(row[key]) for key in LEDGER_FIELDS})


def _write_ledger_markdown(
    path: Path,
    rows: list[dict[str, str]],
    baseline: VerifiedCapture,
    runs: list[VerifiedCapture],
    schedule: LoadedSchedule,
) -> None:
    by_window = {run.window_id: run for run in runs}
    ordered_runs = [by_window[window["id"]] for window in schedule.value["windows"]]
    lines = [
        "# Public Storefront QA month-end change ledger", "",
        "Four verified, schedule-bound reruns of one frozen baseline are inventoried below. Only observation or availability transitions appear in the change table.", "",
        "Absence of a row means no transition was recorded among the frozen checks at these captures. It does not prove that the website did not change, or establish uptime, causation, correctness, conversion effect, or whole-site coverage.", "",
        f"- Service period: `{markdown_cell(schedule.value['period_starts_at'])}` through `{markdown_cell(schedule.value['period_ends_at'])}`",
        f"- Schedule SHA-256: `{schedule.sha256}`",
        f"- Baseline captured: `{markdown_cell(baseline.captured_at)}`",
        f"- Baseline CSV SHA-256: `{baseline.csv_sha256}`",
        f"- Frozen config SHA-256: `{baseline.config_digest}`", "",
        "## Capture inventory", "",
        "| Window | Opens | Scheduled | Closes | Captured | PASS | DRIFT | UNAVAILABLE | Rerun CSV SHA-256 | Manifest SHA-256 |",
        "|---|---|---|---|---|---:|---:|---:|---|---|",
    ]
    for window, run in zip(schedule.value["windows"], ordered_runs, strict=True):
        counts = {status: sum(row["status"] == status for row in run.rows) for status in ALLOWED_STATUSES}
        lines.append(
            f"| {markdown_cell(window['id'])} | {markdown_cell(window['opens_at'])} | {markdown_cell(window['scheduled_for'])} | "
            f"{markdown_cell(window['closes_at'])} | {markdown_cell(run.captured_at)} | {counts['PASS']} | {counts['DRIFT']} | "
            f"{counts['UNAVAILABLE']} | `{run.csv_sha256}` | `{run.manifest_sha256}` |"
        )
    lines.extend([
        "", "## Recorded transitions", "",
        "| Run | Current capture | Previous capture | URL | Check | Baseline observation | Previous observation | Previous status | Observation | Status | Event | Evidence | Source rerun SHA-256 |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ])
    if rows:
        for row in rows:
            values = [
                row["run"], row["captured_at"], row["previous_captured_at"], row["url"], row["check"],
                row["baseline_observed"], row["previous_observed"], row["previous_status"], row["observed"],
                row["status"], row["event_type"], row["evidence"], row["source_csv_sha256"],
            ]
            lines.append("| " + " | ".join(markdown_cell(value) for value in values) + " |")
    else:
        lines.append("| - | - | - | - | - | - | - | - | - | - | NONE | No observation transitions were recorded among the frozen checks across four captures. | - |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_month_end_ledger(
    out: Path,
    config: dict,
    baseline: VerifiedCapture,
    runs: list[VerifiedCapture],
    schedule: LoadedSchedule,
    now: datetime | None = None,
) -> dict:
    if out.exists():
        raise ConfigError("month-end ledger requires a fresh output directory")
    rows = _build_month_end_ledger(baseline, runs, schedule, now=now)
    by_window = {run.window_id: run for run in runs}
    ordered_runs = [by_window[window["id"]] for window in schedule.value["windows"]]
    out.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{out.name}.stage-", dir=out.parent))
    targets = ["month-end-ledger.csv", "month-end-ledger.md", "month-end-ledger.meta.json", "output-manifest.json"]
    try:
        csv_stage = stage / targets[0]
        md_stage = stage / targets[1]
        meta_stage = stage / targets[2]
        _write_ledger_csv(csv_stage, rows)
        _write_ledger_markdown(md_stage, rows, baseline, ordered_runs, schedule)
        metadata = {
            "schema": LEDGER_SCHEMA,
            "mode": "month-end-ledger",
            "tool_version": TOOL_VERSION,
            "evidence_class": "four-scheduled-run-change-only-ledger",
            "generated_at": utc_timestamp(),
            "domain": config["domain"],
            "config_digest": baseline.config_digest,
            "schedule_sha256": schedule.sha256,
            "period_id": schedule.value["period_id"],
            "period_starts_at": schedule.value["period_starts_at"],
            "period_ends_at": schedule.value["period_ends_at"],
            "baseline_csv_sha256": baseline.csv_sha256,
            "baseline_manifest_sha256": baseline.manifest_sha256,
            "baseline_captured_at": baseline.captured_at,
            "baseline_tool_version": baseline.tool_version,
            "csv_sha256": _sha256_file(csv_stage),
            "run_count": len(ordered_runs),
            "row_count": len(rows),
            "fields": LEDGER_FIELDS,
            "source_runs": [
                {
                    "window_id": window["id"],
                    "opens_at": window["opens_at"],
                    "scheduled_for": window["scheduled_for"],
                    "closes_at": window["closes_at"],
                    "captured_at": run.captured_at,
                    "rerun_csv_sha256": run.csv_sha256,
                    "manifest_sha256": run.manifest_sha256,
                    "tool_version": run.tool_version,
                    "capture_complete": True,
                    "has_exceptions": any(row["status"] != "PASS" for row in run.rows),
                    "counts": {status: sum(row["status"] == status for row in run.rows) for status in sorted(ALLOWED_STATUSES)},
                }
                for window, run in zip(schedule.value["windows"], ordered_runs, strict=True)
            ],
            "claim_limit": "Integrity-linked public static observations only; not authenticity, continuous monitoring, whole-site coverage, uptime, causation, or business impact.",
        }
        _write_json(meta_stage, metadata)
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "mode": "month-end-ledger",
            "tool_version": TOOL_VERSION,
            "committed_at": utc_timestamp(),
            "files": {name: _sha256_file(stage / name) for name in targets[:-1]},
        }
        _write_json(stage / "output-manifest.json", manifest)
        if out.exists():
            raise ConfigError("month-end ledger output directory appeared during staging")
        os.rename(stage, out)
        return metadata
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _run_month_end_ledger(args: argparse.Namespace) -> int:
    if len(args.run_manifests) != 4:
        raise ConfigError("month-end ledger requires exactly four --run-manifest inputs")
    inputs = [args.baseline_manifest.resolve(), *(path.resolve() for path in args.run_manifests)]
    if len(set(inputs)) != 5:
        raise ConfigError("month-end ledger source manifests must be unique")
    out_resolved = args.out.resolve()
    bundle_directories = {path.parent for path in inputs}
    nested_in_bundle = any(
        out_resolved == directory or directory in out_resolved.parents
        for directory in bundle_directories
    )
    if nested_in_bundle or out_resolved in {args.config.resolve(), args.schedule.resolve(), *inputs}:
        raise ConfigError("month-end ledger output must not alias an input")
    raw = _strict_json_object(args.config.read_bytes(), "config")
    config = validate_config(raw, check_dns=False)
    baseline = _load_verified_capture(args.baseline_manifest, "baseline")
    _require_verified_baseline_matches_config(
        baseline, config, "month-end ledger baseline does not match the frozen config",
    )
    schedule = _load_month_schedule(args.schedule, config, baseline)
    runs = [_load_verified_capture(path, "scheduled-rerun") for path in args.run_manifests]
    metadata = write_month_end_ledger(args.out, config, baseline, runs, schedule)
    print(json.dumps({
        "output": str(args.out / "month-end-ledger.csv"),
        "report": str(args.out / "month-end-ledger.md"),
        "metadata": metadata,
    }, sort_keys=True))
    return 0


def _run_schedule_digest(args: argparse.Namespace) -> int:
    raw = _strict_json_object(args.config.read_bytes(), "config")
    config = validate_config(raw, check_dns=False)
    baseline = _load_verified_capture(args.baseline_manifest, "baseline")
    _require_verified_baseline_matches_config(
        baseline, config, "schedule baseline does not match the frozen config",
    )
    schedule = _load_month_schedule(args.schedule, config, baseline)
    print(json.dumps({
        "schedule_sha256": schedule.sha256,
        "period_id": schedule.value["period_id"],
        "period_starts_at": schedule.value["period_starts_at"],
        "period_ends_at": schedule.value["period_ends_at"],
        "windows": schedule.value["windows"],
    }, sort_keys=True))
    return 0


def _capture_pages(
    config: dict,
    *,
    closes_at: datetime | None = None,
    now_provider: Callable[[], datetime] | None = None,
) -> dict[str, PageResult]:
    current_time = now_provider or (lambda: datetime.now(timezone.utc))
    pages: dict[str, PageResult] = {}
    for entry in config["urls"]:
        timeout = float(config["timeout_seconds"])
        if closes_at is not None:
            remaining = (closes_at - current_time()).total_seconds()
            if remaining <= 0:
                raise ConfigError("monthly scheduled rerun window closed before all GETs started")
            timeout = min(timeout, remaining)
        pages[entry["id"]] = fetch_page(
            entry["url"], config["domain"], timeout, config["max_response_bytes"],
        )
    return pages


def run(args: argparse.Namespace) -> int:
    mode = args.command
    if mode == "schedule-digest":
        return _run_schedule_digest(args)
    if mode == "month-end-ledger":
        return _run_month_end_ledger(args)
    raw = _strict_json_object(args.config.read_bytes(), "config")
    monthly_context = None
    if mode == "scheduled-rerun":
        if getattr(args, "schedule", None) is not None:
            if not getattr(args, "window", None):
                raise ConfigError("--window is required with --schedule")
            monthly_context = _monthly_scheduled_preflight(
                raw, args.baseline, args.schedule, args.window, args.out,
            )
        else:
            if getattr(args, "window", None):
                raise ConfigError("--window may be used only with --schedule")
            _scheduled_preflight(raw, args.baseline, args.scheduled_for)
    config = validate_config(raw, check_dns=mode == "baseline")
    loaded_baseline = None
    baseline = None
    if mode in {"rerun", "scheduled-rerun"}:
        if monthly_context is not None:
            _preflight_config, verified_baseline, _schedule, _window = monthly_context
            if verified_baseline.config_digest != config_digest(config):
                raise ConfigError("monthly scheduled rerun config changed after preflight")
            loaded_baseline = LoadedBaseline(
                {(row["url"], row["check"]): row["observed"] for row in verified_baseline.rows},
                verified_baseline.csv_sha256,
                verified_baseline.captured_at,
            )
        else:
            loaded_baseline = _load_baseline(
                args.baseline,
                config_digest(config),
                _config_keys(config),
                _config_expectations(config),
            )
        baseline = loaded_baseline.observations
    timestamp = None if monthly_context is not None else utc_timestamp()
    closes_at = None
    if monthly_context is not None:
        closes_at = validate_timestamp(monthly_context[3]["closes_at"])
    pages = _capture_pages(config, closes_at=closes_at)
    schedule_binding = None
    if monthly_context is not None:
        _preflight_config, _verified_baseline, schedule, window = monthly_context
        captured_time = datetime.now(timezone.utc).replace(microsecond=0)
        if not validate_timestamp(window["scheduled_for"]) <= captured_time < validate_timestamp(window["closes_at"]):
            raise ConfigError("monthly scheduled rerun left its agreed window before capture completed")
        timestamp = captured_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        schedule_binding = {
            "schedule_sha256": schedule.sha256,
            "window_id": window["id"],
            "scheduled_for": window["scheduled_for"],
        }
    rows = evaluate(config, pages, timestamp, baseline)
    metadata = write_run_artifacts(
        args.out, mode, rows, config, timestamp, loaded_baseline, schedule_binding,
    )
    csv_name = "baseline.csv" if mode == "baseline" else "rerun.csv"
    counts = {status: sum(row.status == status for row in rows) for status in ("PASS", "DRIFT", "UNAVAILABLE")}
    print(json.dumps({"output": str(args.out / csv_name), "exceptions": str(args.out / "exceptions.md"), "metadata": metadata, **counts}, sort_keys=True))
    return 0 if not counts["DRIFT"] and not counts["UNAVAILABLE"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("baseline", "rerun", "scheduled-rerun"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--config", required=True, type=Path)
        sub.add_argument("--out", required=True, type=Path)
        if command in {"rerun", "scheduled-rerun"}:
            sub.add_argument("--baseline", required=True, type=Path)
        if command == "scheduled-rerun":
            timing = sub.add_mutually_exclusive_group(required=True)
            timing.add_argument("--scheduled-for", help="UTC RFC 3339 second at or after the minimum baseline age")
            timing.add_argument("--schedule", type=Path, help="frozen four-window monthly schedule JSON")
            sub.add_argument("--window", help="window id from --schedule")
    ledger = subparsers.add_parser("month-end-ledger")
    ledger.add_argument("--config", required=True, type=Path)
    ledger.add_argument("--baseline-manifest", required=True, type=Path)
    ledger.add_argument("--schedule", required=True, type=Path)
    ledger.add_argument("--run-manifest", dest="run_manifests", required=True, action="append", type=Path)
    ledger.add_argument("--out", required=True, type=Path)
    digest = subparsers.add_parser("schedule-digest")
    digest.add_argument("--config", required=True, type=Path)
    digest.add_argument("--baseline-manifest", required=True, type=Path)
    digest.add_argument("--schedule", required=True, type=Path)
    return parser


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except (ConfigError, json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
