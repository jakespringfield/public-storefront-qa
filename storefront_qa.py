#!/usr/bin/env python3
"""Read-only, deterministic checks for a bounded set of public HTML pages."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import http.client
import ipaddress
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
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit


MAX_URLS = 6
MAX_CHECKS = 20
MAX_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 2_000_000
MAX_REDIRECTS = 5
MAX_GET_ATTEMPTS = 2
BASELINE_SCHEMA = "public-storefront-qa/baseline-v1"
RUN_SCHEMA = "public-storefront-qa/run-v1"
MANIFEST_SCHEMA = "public-storefront-qa/commit-v1"
CSV_FIELDS = ["url", "timestamp", "check", "expected", "observed", "status", "evidence"]
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


class ConfigError(ValueError):
    pass


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


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        raise ConfigError("timestamp must use UTC RFC 3339 seconds, for example 2026-08-14T12:00:00Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ConfigError("timestamp is not a valid UTC calendar time") from exc


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
            raise ConfigError("resolver returned a non-IP destination") from exc
        if not _is_public_unicast(parsed):
            raise ConfigError("configured domain must resolve only to public IP unicast addresses")
        clean.append(str(parsed))
    if not clean:
        raise ConfigError("configured domain did not resolve to an address")
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
    try:
        return _validated_addresses(host, result)
    except ConfigError as exc:
        raise FetchError(str(exc)) from exc


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
        if value not in {"present", "absent"}:
            raise ConfigError(f"check {check['id']} expected must be present or absent")
        return value
    if kind == "robots-indexability":
        if value not in {"indexable", "noindex"}:
            raise ConfigError(f"check {check['id']} expected must be indexable or noindex")
        return value
    if not isinstance(value, str):
        raise ConfigError(f"check {check['id']} expected must be a string")
    return value


def validate_config(raw: dict, resolver: Callable[[str], list[str]] = resolve_addresses) -> dict:
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    domain = raw.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        raise ConfigError("domain must be a non-empty hostname")
    domain = domain.rstrip(".").lower()
    if not HOST_PATTERN.fullmatch(domain) or domain == "localhost" or domain.endswith(".localhost"):
        raise ConfigError("domain must be a valid public hostname")
    timeout = raw.get("timeout_seconds", 10)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ConfigError(f"timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")
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
        url_id = check.get("url")
        if url_id not in url_ids:
            raise ConfigError(f"check {check_id} references an unknown URL id")
        kind = check.get("type")
        if kind not in CHECK_TYPES:
            raise ConfigError(f"check {check_id} has an unsupported type")
        clean = {"id": check_id, "url": url_id, "type": kind, "expected": _expected_string(check)}
        if kind in {"text", "selector", "asset-reference"}:
            value = check.get("value")
            if not isinstance(value, str) or not value:
                raise ConfigError(f"check {check_id} requires a non-empty value")
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
            _call_with_deadline(
                lambda: connection.request("GET", parts.path or "/", headers={
                    "Accept": "text/html,application/xhtml+xml;q=0.9",
                    "User-Agent": "Springfield-Public-Storefront-QA/0.2 (+read-only; public GET)",
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


def _fetch_chain_once(safe_url: str, domain: str, addresses: tuple[str, ...], deadline: float, max_bytes: int) -> PageResult:
    current = safe_url
    for redirect_count in range(MAX_REDIRECTS + 1):
        connection, response = _open_pinned(current, domain, addresses, deadline)
        try:
            headers = _headers_dict(response.getheaders())
            status = int(response.status)
            if status in TRANSIENT_STATUSES:
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
        for _attempt in range(MAX_GET_ATTEMPTS):
            try:
                return _fetch_chain_once(safe_url, domain, addresses, deadline, max_bytes)
            except TransientFetchError as exc:
                last_error = exc
                _remaining(deadline)
        raise TransientFetchError("GET failed after bounded retry") from last_error
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
        return body.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


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
        if check["url"] not in snapshots:
            snapshots[check["url"]] = _snapshot(page)
        observed, evidence = _observe(check, page, snapshots[check["url"]])
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
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != CSV_FIELDS:
            raise ConfigError("baseline CSV schema does not exactly match the required fields")
        return [{key: restore_csv_cell(value) for key, value in row.items()} for row in reader]


def markdown_cell(value: object) -> str:
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    escaped = html.escape(text, quote=True).replace("\\", "\\\\").replace("|", "\\|")
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
    earliest = baseline_time + timedelta(hours=config["scheduled_evidence_minimum_hours"])
    return {
        "schema": BASELINE_SCHEMA, "mode": "baseline", "config_digest": config_digest(config),
        "csv_sha256": _sha256_file(csv_path), "fields": CSV_FIELDS, "row_count": len(rows),
        "captured_at": timestamp, "earliest_scheduled_evidence_at": earliest.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write_run_artifacts(out: Path, mode: str, rows: list[CheckResult], config: dict, timestamp: str) -> dict:
    if mode not in {"baseline", "rerun", "scheduled-rerun"}:
        raise ConfigError("unsupported run mode")
    validate_timestamp(timestamp)
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
            metadata = {
                "schema": RUN_SCHEMA, "mode": mode,
                "evidence_class": "scheduled-change-evidence" if mode == "scheduled-rerun" else "immediate-mechanics-proof",
                "qualifies_as_scheduled_evidence": mode == "scheduled-rerun",
                "config_digest": config_digest(config), "csv_sha256": _sha256_file(csv_stage),
                "fields": CSV_FIELDS, "row_count": len(rows), "captured_at": timestamp,
            }
        _write_json(meta_stage, metadata)
        manifest = {
            "schema": MANIFEST_SCHEMA, "mode": mode, "committed_at": utc_timestamp(),
            "files": {csv_name: _sha256_file(csv_stage), "exceptions.md": _sha256_file(md_stage), meta_name: _sha256_file(meta_stage)},
        }
        _write_json(stage / "output-manifest.json", manifest)
        targets = [csv_name, "exceptions.md", meta_name, "output-manifest.json"]
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
        shutil.rmtree(stage, ignore_errors=True)


def load_baseline(path: Path, expected_config_digest: str, expected_keys: set[tuple[str, str]] | None = None) -> dict[tuple[str, str], str]:
    try:
        metadata = json.loads(path.with_name("baseline.meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("baseline metadata is missing or invalid") from exc
    required = {"schema", "mode", "config_digest", "csv_sha256", "fields", "row_count", "captured_at", "earliest_scheduled_evidence_at"}
    if set(metadata) != required or metadata.get("schema") != BASELINE_SCHEMA or metadata.get("mode") != "baseline":
        raise ConfigError("baseline metadata schema is invalid")
    if metadata["config_digest"] != expected_config_digest:
        raise ConfigError("baseline config digest does not match the current normalized config")
    if metadata["fields"] != CSV_FIELDS:
        raise ConfigError("baseline metadata fields are invalid")
    validate_timestamp(metadata["captured_at"])
    validate_timestamp(metadata["earliest_scheduled_evidence_at"])
    if _sha256_file(path) != metadata["csv_sha256"]:
        raise ConfigError("baseline CSV digest does not match its metadata")
    records = read_csv_records(path)
    validate_baseline_records(records)
    if metadata["row_count"] != len(records):
        raise ConfigError("baseline row count does not match its metadata")
    if {record["timestamp"] for record in records} != {metadata["captured_at"]}:
        raise ConfigError("baseline timestamps do not match metadata")
    result = {(record["url"], record["check"]): record["observed"] for record in records}
    if expected_keys is not None and set(result) != expected_keys:
        raise ConfigError("baseline rows do not exactly match the configured URL/check set")
    return result


def enforce_scheduled_evidence_gate(baseline_time: datetime, scheduled_for: datetime, now: datetime, minimum_age_hours: int) -> None:
    earliest = baseline_time + timedelta(hours=minimum_age_hours)
    if scheduled_for < earliest:
        raise ConfigError("scheduled date is earlier than the required baseline age")
    if now < scheduled_for or now < earliest:
        raise ConfigError("scheduled evidence gate is not open")


def _config_keys(config: dict) -> set[tuple[str, str]]:
    urls = {entry["id"]: entry["url"] for entry in config["urls"]}
    return {(urls[check["url"]], check["id"]) for check in config["checks"]}


def _scheduled_preflight(raw: dict, baseline_path: Path, scheduled_for: str, now: datetime | None = None) -> None:
    """Evaluate the local time gate before config validation can resolve DNS."""
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    minimum_age = raw.get("scheduled_evidence_minimum_hours", 72)
    if not isinstance(minimum_age, int) or isinstance(minimum_age, bool) or not 1 <= minimum_age <= 720:
        raise ConfigError("scheduled_evidence_minimum_hours must be an integer between 1 and 720")
    try:
        metadata = json.loads(baseline_path.with_name("baseline.meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("baseline metadata is missing or invalid") from exc
    if not isinstance(metadata, dict) or metadata.get("schema") != BASELINE_SCHEMA or metadata.get("mode") != "baseline":
        raise ConfigError("baseline metadata schema is invalid")
    baseline_time = validate_timestamp(metadata.get("captured_at"))
    recorded_earliest = validate_timestamp(metadata.get("earliest_scheduled_evidence_at"))
    calculated_earliest = baseline_time + timedelta(hours=minimum_age)
    if recorded_earliest != calculated_earliest:
        raise ConfigError("baseline scheduled evidence time does not match the local config gate")
    enforce_scheduled_evidence_gate(
        baseline_time,
        validate_timestamp(scheduled_for),
        now or datetime.now(timezone.utc),
        minimum_age,
    )


def run(args: argparse.Namespace) -> int:
    raw = json.loads(args.config.read_text(encoding="utf-8"))
    mode = args.command
    if mode == "scheduled-rerun":
        _scheduled_preflight(raw, args.baseline, args.scheduled_for)
    config = validate_config(raw)
    baseline = None
    if mode in {"rerun", "scheduled-rerun"}:
        baseline = load_baseline(args.baseline, config_digest(config), _config_keys(config))
    timestamp = utc_timestamp()
    pages = {
        entry["id"]: fetch_page(entry["url"], config["domain"], config["timeout_seconds"], config["max_response_bytes"])
        for entry in config["urls"]
    }
    rows = evaluate(config, pages, timestamp, baseline)
    metadata = write_run_artifacts(args.out, mode, rows, config, timestamp)
    csv_name = "baseline.csv" if mode == "baseline" else "rerun.csv"
    counts = {status: sum(row.status == status for row in rows) for status in ("PASS", "DRIFT", "UNAVAILABLE")}
    print(json.dumps({"output": str(args.out / csv_name), "exceptions": str(args.out / "exceptions.md"), "metadata": metadata, **counts}, sort_keys=True))
    return 0 if not counts["DRIFT"] and not counts["UNAVAILABLE"] else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("baseline", "rerun", "scheduled-rerun"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--config", required=True, type=Path)
        sub.add_argument("--out", required=True, type=Path)
        if command in {"rerun", "scheduled-rerun"}:
            sub.add_argument("--baseline", required=True, type=Path)
        if command == "scheduled-rerun":
            sub.add_argument("--scheduled-for", required=True, help="UTC RFC 3339 second at or after the minimum baseline age")
    return parser


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except (ConfigError, json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
