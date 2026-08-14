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
            raise ConfigError(f"check {check_id} ×Î¹îÚ$z{-®éÜj×'Vâ–â'Vç7Ð¢÷&FW&VE÷'Vç2Ò¶'•÷v–æF÷u·v–æF÷u²&–B%ÕÒf÷"v–æF÷r–â66†VGVÆRçfÇVU²'v–æF÷w2%ÕÐ¢Æ–æW2Ò°¢"2V&Æ–27F÷&Vg&öçBÖöçF‚ÖVæB6†ævRÆVFvW""Â""À¢$f÷W"fW&–f–VBÂ66†VGVÆRÖ&÷VæB&W'Vç2öböæRg&÷¦Vâ&6VÆ–æR&R–çfVçF÷&–VB&VÆ÷râöæÇ’ö'6W'fF–öâ÷"f–Æ&–Æ—G’G&ç6—F–öç2V"–âF†R6†ævRF&ÆRâ"Â""À¢$'6Væ6Röb&÷rÖVç2æòG&ç6—F–öâv2&V6÷&FVBÖöærF†Rg&÷¦Vâ6†V6·2BF†W6R6GW&W2â—BFöW2æ÷B&÷fRF†BF†RvV'6—FRF–Bæ÷B6†ævRÂ÷"W7F&Æ—6‚WF–ÖRÂ6W6F–öâÂ6÷'&V7FæW72Â6öçfW'6–öâVffV7BÂ÷"v†öÆR×6—FR6÷fW&vRâ"Â""À¢b"Ò6W'f–6RW&–öC¢¶Ö&¶F÷våö6VÆÂ‡66†VGVÆRçfÇVU²wW&–öE÷7F'G5öBuÒ—ÖF‡&÷Vv‚¶Ö&¶F÷våö6VÆÂ‡66†VGVÆRçfÇVU²wW&–öEöVæG5öBuÒ—Ö"À¢b"Ò66†VGVÆR4„Ó#Sc¢·66†VGVÆRç6†#SgÖ"À¢b"Ò&6VÆ–æR6GW&VC¢¶Ö&¶F÷våö6VÆÂ†&6VÆ–æRæ6GW&VEöB—Ö"À¢b"Ò&6VÆ–æR55b4„Ó#Sc¢¶&6VÆ–æRæ77e÷6†#SgÖ"À¢b"Òg&÷¦Vâ6öæf–r4„Ó#Sc¢¶&6VÆ–æRæ6öæf–uöF–vW7GÖ"Â""À¢"226GW&R–çfVçF÷'’"Â""À¢'Âv–æF÷rÂ÷Vç2Â66†VGVÆVBÂ6Æ÷6W2Â6GW&VBÂ52ÂE$”eBÂTäd”Ä$ÄRÂ&W'Vâ55b4„Ó#SbÂÖæ–fW7B4„Ó#SbÂ"À¢'ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒÓ§ÂÒÒÓ§ÂÒÒÓ§ÂÒÒ×ÂÒÒ×Â"À¢Ð¢f÷"v–æF÷rÂ'Vâ–â¦—‡66†VGVÆRçfÇVU²'v–æF÷w2%ÒÂ÷&FW&VE÷'Vç2Â7G&–7CÕG'VR“ ¢6÷VçG2Ò·7FGW3¢7VÒ‡&÷u²'7FGW2%ÒÓÒ7FGW2f÷"&÷r–â'Vâç&÷w2’f÷"7FGW2–âÄÄõtTEõ5DEU4U7Ð¢Æ–æW2æVæB€¢b'Â¶Ö&¶F÷våö6VÆÂ‡v–æF÷u²v–BuÒ—ÒÂ¶Ö&¶F÷våö6VÆÂ‡v–æF÷u²v÷Vç5öBuÒ—ÒÂ¶Ö&¶F÷våö6VÆÂ‡v–æF÷u²w66†VGVÆVEöf÷"uÒ—ÒÂ ¢b'¶Ö&¶F÷våö6VÆÂ‡v–æF÷u²v6Æ÷6W5öBuÒ—ÒÂ¶Ö&¶F÷våö6VÆÂ‡'Vâæ6GW&VEöB—ÒÂ¶6÷VçG5²u52u×ÒÂ¶6÷VçG5²tE$”eBu×ÒÂ ¢b'¶6÷VçG5²uTäd”Ä$ÄRu×ÒÂ·'Vâæ77e÷6†#SgÖÂ·'VâæÖæ–fW7E÷6†#SgÖÂ ¢¢Æ–æW2æW‡FVæB…°¢""Â"22&V6÷&FVBG&ç6—F–öç2"Â""À¢'Â'VâÂ7W'&VçB6GW&RÂ&Wf–÷W26GW&RÂU$ÂÂ6†V6²Â&6VÆ–æRö'6W'fF–öâÂ&Wf–÷W2ö'6W'fF–öâÂ&Wf–÷W27FGW2Âö'6W'fF–öâÂ7FGW2ÂWfVçBÂWf–FVæ6RÂ6÷W&6R&W'Vâ4„Ó#SbÂ"À¢'ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×ÂÒÒ×Â"À¢Ò¢–b&÷w3 ¢f÷"&÷r–â&÷w3 ¢fÇVW2Ò°¢&÷u²''Vâ%ÒÂ&÷u²&6GW&VEöB%ÒÂ&÷u²'&Wf–÷W5ö6GW&VEöB%ÒÂ&÷u²'W&Â%ÒÂ&÷u²&6†V6²%ÒÀ¢&÷u²&&6VÆ–æUöö'6W'fVB%ÒÂ&÷u²'&Wf–÷W5öö'6W'fVB%ÒÂ&÷u²'&Wf–÷W5÷7FGW2%ÒÂ&÷u²&ö'6W'fVB%ÒÀ¢&÷u²'7FGW2%ÒÂ&÷u²&WfVçE÷G—R%ÒÂ&÷u²&Wf–FVæ6R%ÒÂ&÷u²'6÷W&6Uö77e÷6†#Sb%ÒÀ¢Ð¢Æ–æW2æVæB‚'Â"²"Â"æ¦ö–â†Ö&¶F÷våö6VÆÂ‡fÇVR’f÷"fÇVR–âfÇVW2’²"Â"¢VÇ6S ¢Æ–æW2æVæB‚'ÂÒÂÒÂÒÂÒÂÒÂÒÂÒÂÒÂÒÂÒÂäôäRÂæòö'6W'fF–öâG&ç6—F–öç2vW&R&V6÷&FVBÖöærF†Rg&÷¦Vâ6†V6·27&÷72f÷W"6GW&W2âÂÒÂ"¢F‚çw&—FU÷FW‡B‚%Æâ"æ¦ö–â†Æ–æW2’²%Æâ"ÂVæ6öF–æsÒ'WFbÓ‚"  ¦FVbw&—FUöÖöçF…öVæEöÆVFvW"€¢÷WC¢F‚À¢6öæf–s¢F–7BÀ¢&6VÆ–æS¢fW&–f–VD6GW&RÀ¢'Vç3¢Æ—7EµfW&–f–VD6GW&UÒÀ¢66†VGVÆS¢ÆöFVE66†VGVÆRÀ¢æ÷s¢FFWF–ÖRÂæöæRÒæöæRÀ¢’ÓâF–7C ¢–b÷WBæW†—7G2‚“ ¢&—6R6öæf–tW'&÷"‚&ÖöçF‚ÖVæBÆVFvW"&WV—&W2g&W6‚÷WGWBF—&V7F÷'’"¢&÷w2Òö'V–ÆEöÖöçF…öVæEöÆVFvW"†&6VÆ–æRÂ'Vç2Â66†VGVÆRÂæ÷sÖæ÷r¢'•÷v–æF÷rÒ·'Vâçv–æF÷uö–C¢'Vâf÷"'Vâ–â'Vç7Ð¢÷&FW&VE÷'Vç2Ò¶'•÷v–æF÷u·v–æF÷u²&–B%ÕÒf÷"v–æF÷r–â66†VGVÆRçfÇVU²'v–æF÷w2%ÕÐ¢÷WBç&VçBæÖ¶F—"‡&VçG3ÕG'VRÂW†—7Eöö³ÕG'VR¢7FvRÒF‚‡FV×f–ÆRæÖ¶GFV×‡&Vf—ƒÖb"ç¶÷WBææÖWÒç7FvRÒ"ÂF—#Ö÷WBç&VçB’¢F&vWG2Ò²&ÖöçF‚ÖVæBÖÆVFvW"æ77b"Â&ÖöçF‚ÖVæBÖÆVFvW"æÖB"Â&ÖöçF‚ÖVæBÖÆVFvW"æÖWFæ§6öâ"Â&÷WGWBÖÖæ–fW7Bæ§6öâ%Ð¢G'“ ¢77e÷7FvRÒ7FvRòF&vWG5³Ð¢ÖE÷7FvRÒ7FvRòF&vWG5³Ð¢ÖWF÷7FvRÒ7FvRòF&vWG5³%Ð¢÷w&—FUöÆVFvW%ö77b†77e÷7FvRÂ&÷w2¢÷w&—FUöÆVFvW%öÖ&¶F÷vâ†ÖE÷7FvRÂ&÷w2Â&6VÆ–æRÂ÷&FW&VE÷'Vç2Â66†VGVÆR¢ÖWFFFÒ°¢'66†VÖ#¢ÄTDtU%õ44„TÔÀ¢&ÖöFR#¢&ÖöçF‚ÖVæBÖÆVFvW""À¢'FööÅ÷fW'6–öâ#¢DôôÅõdU%4”ôâÀ¢&Wf–FVæ6Uö6Æ72#¢&f÷W"×66†VGVÆVB×'VâÖ6†ævRÖöæÇ’ÖÆVFvW""À¢&vVæW&FVEöB#¢WF5÷F–ÖW7F×‚’À¢&FöÖ–â#¢6öæf–u²&FöÖ–â%ÒÀ¢&6öæf–uöF–vW7B#¢&6VÆ–æRæ6öæf–uöF–vW7BÀ¢'66†VGVÆU÷6†#Sb#¢66†VGVÆRç6†#SbÀ¢'W&–öEö–B#¢66†VGVÆRçfÇVU²'W&–öEö–B%ÒÀ¢'W&–öE÷7F'G5öB#¢66†VGVÆRçfÇVU²'W&–öE÷7F'G5öB%ÒÀ¢'W&–öEöVæG5öB#¢66†VGVÆRçfÇVU²'W&–öEöVæG5öB%ÒÀ¢&&6VÆ–æUö77e÷6†#Sb#¢&6VÆ–æRæ77e÷6†#SbÀ¢&&6VÆ–æUöÖæ–fW7E÷6†#Sb#¢&6VÆ–æRæÖæ–fW7E÷6†#SbÀ¢&&6VÆ–æUö6GW&VEöB#¢&6VÆ–æRæ6GW&VEöBÀ¢&&6VÆ–æU÷FööÅ÷fW'6–öâ#¢&6VÆ–æRçFööÅ÷fW'6–öâÀ¢&77e÷6†#Sb#¢÷6†#Seöf–ÆR†77e÷7FvR’À¢''Våö6÷VçB#¢ÆVâ†÷&FW&VE÷'Vç2’À¢'&÷uö6÷VçB#¢ÆVâ‡&÷w2’À¢&f–VÆG2#¢ÄTDtU%ôd”TÄE2À¢'6÷W&6U÷'Vç2#¢°¢°¢'v–æF÷uö–B#¢v–æF÷u²&–B%ÒÀ¢&÷Vç5öB#¢v–æF÷u²&÷Vç5öB%ÒÀ¢'66†VGVÆVEöf÷"#¢v–æF÷u²'66†VGVÆVEöf÷"%ÒÀ¢&6Æ÷6W5öB#¢v–æF÷u²&6Æ÷6W5öB%ÒÀ¢&6GW&VEöB#¢'Vâæ6GW&VEöBÀ¢'&W'Våö77e÷6†#Sb#¢'Vâæ77e÷6†#SbÀ¢&Öæ–fW7E÷6†#Sb#¢'VâæÖæ–fW7E÷6†#SbÀ¢'FööÅ÷fW'6–öâ#¢'VâçFööÅ÷fW'6–öâÀ¢&6GW&Uö6ö×ÆWFR#¢G'VRÀ¢&†5öW†6WF–öç2#¢ç’‡&÷u²'7FGW2%ÒÒ%52"f÷"&÷r–â'Vâç&÷w2’À¢&6÷VçG2#¢·7FGW3¢7VÒ‡&÷u²'7FGW2%ÒÓÒ7FGW2f÷"&÷r–â'Vâç&÷w2’f÷"7FGW2–â6÷'FVB„ÄÄõtTEõ5DEU4U2—ÒÀ¢Ð¢f÷"v–æF÷rÂ'Vâ–â¦—‡66†VGVÆRçfÇVU²'v–æF÷w2%ÒÂ÷&FW&VE÷'Vç2Â7G&–7CÕG'VR¢ÒÀ¢&6Æ–ÕöÆ–Ö—B#¢$–çFVw&—G’ÖÆ–æ¶VBV&Æ–27FF–2ö'6W'fF–öç2öæÇ“²æ÷BWF†VçF–6—G’Â6öçF–çV÷W2Ööæ—F÷&–ærÂv†öÆR×6—FR6÷fW&vRÂWF–ÖRÂ6W6F–öâÂ÷"'W6–æW72–×7Bâ"À¢Ð¢÷w&—FUö§6öâ†ÖWF÷7FvRÂÖWFFF¢Öæ–fW7BÒ°¢'66†VÖ#¢Ôä”dU5Eõ44„TÔÀ¢&ÖöFR#¢&ÖöçF‚ÖVæBÖÆVFvW""À¢'FööÅ÷fW'6–öâ#¢DôôÅõdU%4”ôâÀ¢&6öÖÖ—GFVEöB#¢WF5÷F–ÖW7F×‚’À¢&f–ÆW2#¢¶æÖS¢÷6†#Seöf–ÆR‡7FvRòæÖR’f÷"æÖR–âF&vWG5³¢Ó×ÒÀ¢Ð¢÷w&—FUö§6öâ‡7FvRò&÷WGWBÖÖæ–fW7Bæ§6öâ"ÂÖæ–fW7B¢–b÷WBæW†—7G2‚“ ¢&—6R6öæf–tW'&÷"‚&ÖöçF‚ÖVæBÆVFvW"÷WGWBF—&V7F÷'’V&VBGW&–ær7Fv–ær"¢÷2ç&VæÖR‡7FvRÂ÷WB¢&WGW&âÖWFFF¢f–æÆÇ“ ¢–b7FvRæW†—7G2‚“ ¢6‡WF–Âç&×G&VR‡7FvRÂ–væ÷&UöW'&÷'3ÕG'VR  ¦FVb÷'VåöÖöçF…öVæEöÆVFvW"†&w3¢&w'6RäæÖW76R’Óâ–çC ¢–bÆVâ†&w2ç'VåöÖæ–fW7G2’ÒC ¢&—6R6öæf–tW'&÷"‚&ÖöçF‚ÖVæBÆVFvW"&WV—&W2W†7FÇ’f÷W"Ò×'VâÖÖæ–fW7B–çWG2"¢–çWG2Ò¶&w2æ&6VÆ–æUöÖæ–fW7Bç&W6öÇfR‚’Â¢‡F‚ç&W6öÇfR‚’f÷"F‚–â&w2ç'VåöÖæ–fW7G2•Ð¢–bÆVâ‡6WB†–çWG2’’ÒS ¢&—6R6öæf–tW'&÷"‚&ÖöçF‚ÖVæBÆVFvW"6÷W&6RÖæ–fW7G2×W7B&RVæ—VR"¢÷WE÷&W6öÇfVBÒ&w2æ÷WBç&W6öÇfR‚¢'VæFÆUöF—&V7F÷&–W2Ò·F‚ç&VçBf÷"F‚–â–çWG7Ð¢æW7FVEö–åö'VæFÆRÒç’€¢÷WE÷&W6öÇfVBÓÒF—&V7F÷'’÷"F—&V7F÷'’–â÷WE÷&W6öÇfVBç&VçG0¢f÷"F—&V7F÷'’–â'VæFÆUöF—&V7F÷&–W0¢¢–bæW7FVEö–åö'VæFÆR÷"÷WE÷&W6öÇfVB–â¶&w2æ6öæf–rç&W6öÇfR‚’Â&w2ç66†VGVÆRç&W6öÇfR‚’Â¦–çWG7Ó ¢&—6R6öæf–tW'&÷"‚&ÖöçF‚ÖVæBÆVFvW"÷WGWB×W7Bæ÷BÆ–2â–çWB"¢&rÒ÷7G&–7Eö§6öåöö&¦V7B†&w2æ6öæf–rç&VEö'—FW2‚’Â&6öæf–r"¢6öæf–rÒfÆ–FFUö6öæf–r‡&rÂ6†V6µöFç3ÔfÇ6R¢&6VÆ–æRÒöÆöE÷fW&–f–VEö6GW&R†&w2æ&6VÆ–æUöÖæ–fW7BÂ&&6VÆ–æR"¢÷&WV—&U÷fW&–f–VEö&6VÆ–æUöÖF6†W5ö6öæf–r€¢&6VÆ–æRÂ6öæf–rÂ&ÖöçF‚ÖVæBÆVFvW"&6VÆ–æRFöW2æ÷BÖF6‚F†Rg&÷¦Vâ6öæf–r"À¢¢66†VGVÆRÒöÆöEöÖöçF…÷66†VGVÆR†&w2ç66†VGVÆRÂ6öæf–rÂ&6VÆ–æR¢'Vç2ÒµöÆöE÷fW&–f–VEö6GW&R‡F‚Â'66†VGVÆVB×&W'Vâ"’f÷"F‚–â&w2ç'VåöÖæ–fW7G5Ð¢ÖWFFFÒw&—FUöÖöçF…öVæEöÆVFvW"†&w2æ÷WBÂ6öæf–rÂ&6VÆ–æRÂ'Vç2Â66†VGVÆR¢&–çB†§6öâæGV×2‡°¢&÷WGWB#¢7G"†&w2æ÷WBò&ÖöçF‚ÖVæBÖÆVFvW"æ77b"’À¢'&W÷'B#¢7G"†&w2æ÷WBò&ÖöçF‚ÖVæBÖÆVFvW"æÖB"’À¢&ÖWFFF#¢ÖWFFFÀ¢ÒÂ6÷'Eö¶W—3ÕG'VR’¢&WGW&â   ¦FVb÷'Vå÷66†VGVÆUöF–vW7B†&w3¢&w'6RäæÖW76R’Óâ–çC ¢&rÒ÷7G&–7Eö§6öåöö&¦V7B†&w2æ6öæf–rç&VEö'—FW2‚’Â&6öæf–r"¢6öæf–rÒfÆ–FFUö6öæf–r‡&rÂ6†V6µöFç3ÔfÇ6R¢&6VÆ–æRÒöÆöE÷fW&–f–VEö6GW&R†&w2æ&6VÆ–æUöÖæ–fW7BÂ&&6VÆ–æR"¢÷&WV—&U÷fW&–f–VEö&6VÆ–æUöÖF6†W5ö6öæf–r€¢&6VÆ–æRÂ6öæf–rÂ'66†VGVÆR&6VÆ–æRFöW2æ÷BÖF6‚F†Rg&÷¦Vâ6öæf–r"À¢¢66†VGVÆRÒöÆöEöÖöçF…÷66†VGVÆR†&w2ç66†VGVÆRÂ6öæf–rÂ&6VÆ–æR¢&–çB†§6öâæGV×2‡°¢'66†VGVÆU÷6†#Sb#¢66†VGVÆRç6†#SbÀ¢'W&–öEö–B#¢66†VGVÆRçfÇVU²'W&–öEö–B%ÒÀ¢'W&–öE÷7F'G5öB#¢66†VGVÆRçfÇVU²'W&–öE÷7F'G5öB%ÒÀ¢'W&–öEöVæG5öB#¢66†VGVÆRçfÇVU²'W&–öEöVæG5öB%ÒÀ¢'v–æF÷w2#¢66†VGVÆRçfÇVU²'v–æF÷w2%ÒÀ¢ÒÂ6÷'Eö¶W—3ÕG'VR’¢&WGW&â   ¦FVbö6GW&U÷vW2€¢6öæf–s¢F–7BÀ¢¢À¢6Æ÷6W5öC¢FFWF–ÖRÂæöæRÒæöæRÀ¢æ÷u÷&÷f–FW#¢6ÆÆ&ÆUµµÒÂFFWF–ÖUÒÂæöæRÒæöæRÀ¢’ÓâF–7E·7G"ÂvU&W7VÇEÓ ¢7W'&VçE÷F–ÖRÒæ÷u÷&÷f–FW"÷"†ÆÖ&F¢FFWF–ÖRææ÷r‡F–ÖW¦öæRçWF2’¢vW3¢F–7E·7G"ÂvU&W7VÇEÒÒ·Ð¢f÷"VçG'’–â6öæf–u²'W&Ç2%Ó ¢F–ÖV÷WBÒfÆöB†6öæf–u²'F–ÖV÷WE÷6V6öæG2%Ò¢–b6Æ÷6W5öB—2æ÷BæöæS ¢&VÖ–æ–ærÒ†6Æ÷6W5öBÒ7W'&VçE÷F–ÖR‚’’çF÷FÅ÷6V6öæG2‚¢–b&VÖ–æ–ærÃÒ ¢&—6R6öæf–tW'&÷"‚&ÖöçF†Ç’66†VGVÆVB&W'Vâv–æF÷r6Æ÷6VB&Vf÷&RÆÂtUG27F'FVB"¢F–ÖV÷WBÒÖ–â‡F–ÖV÷WBÂ&VÖ–æ–ær¢vW5¶VçG'•²&–B%ÕÒÒfWF6…÷vR€¢VçG'•²'W&Â%ÒÂ6öæf–u²&FöÖ–â%ÒÂF–ÖV÷WBÂ6öæf–u²&Ö…÷&W7öç6Uö'—FW2%ÒÀ¢¢&WGW&âvW0  ¦FVb'Vâ†&w3¢&w'6RäæÖW76R’Óâ–çC ¢ÖöFRÒ&w2æ6öÖÖæ@¢–bÖöFRÓÒ'66†VGVÆRÖF–vW7B# ¢&WGW&â÷'Vå÷66†VGVÆUöF–vW7B†&w2¢–bÖöFRÓÒ&ÖöçF‚ÖVæBÖÆVFvW"# ¢&WGW&â÷'VåöÖöçF…öVæEöÆVFvW"†&w2¢&rÒ÷7G&–7Eö§6öåöö&¦V7B†&w2æ6öæf–rç&VEö'—FW2‚’Â&6öæf–r"¢ÖöçF†Ç•ö6öçFW‡BÒæöæP¢–bÖöFRÓÒ'66†VGVÆVB×&W'Vâ# ¢–bvWFGG"†&w2Â'66†VGVÆR"ÂæöæR’—2æ÷BæöæS ¢–bæ÷BvWFGG"†&w2Â'v–æF÷r"ÂæöæR“ ¢&—6R6öæf–tW'&÷"‚"Ò×v–æF÷r—2&WV—&VBv—F‚Ò×66†VGVÆR"¢ÖöçF†Ç•ö6öçFW‡BÒöÖöçF†Ç•÷66†VGVÆVE÷&VfÆ–v‡B€¢&rÂ&w2æ&6VÆ–æRÂ&w2ç66†VGVÆRÂ&w2çv–æF÷rÂ&w2æ÷WBÀ¢¢VÇ6S ¢–bvWFGG"†&w2Â'v–æF÷r"ÂæöæR“ ¢&—6R6öæf–tW'&÷"‚"Ò×v–æF÷rÖ’&RW6VBöæÇ’v—F‚Ò×66†VGVÆR"¢÷66†VGVÆVE÷&VfÆ–v‡B‡&rÂ&w2æ&6VÆ–æRÂ&w2ç66†VGVÆVEöf÷"¢6öæf–rÒfÆ–FFUö6öæf–r‡&rÂ6†V6µöFç3ÖÖöFRÓÒ&&6VÆ–æR"¢ÆöFVEö&6VÆ–æRÒæöæP¢&6VÆ–æRÒæöæP¢–bÖöFR–â²'&W'Vâ"Â'66†VGVÆVB×&W'Vâ'Ó ¢–bÖöçF†Ç•ö6öçFW‡B—2æ÷BæöæS ¢÷&VfÆ–v‡Eö6öæf–rÂfW&–f–VEö&6VÆ–æRÂ÷66†VGVÆRÂ÷v–æF÷rÒÖöçF†Ç•ö6öçFW‡@¢–bfW&–f–VEö&6VÆ–æRæ6öæf–uöF–vW7BÒ6öæf–uöF–vW7B†6öæf–r“ ¢&—6R6öæf–tW'&÷"‚&ÖöçF†Ç’66†VGVÆVB&W'Vâ6öæf–r6†ævVBgFW"&VfÆ–v‡B"¢ÆöFVEö&6VÆ–æRÒÆöFVD&6VÆ–æR€¢²‡&÷u²'W&Â%ÒÂ&÷u²&6†V6²%Ò“¢&÷u²&ö'6W'fVB%Òf÷"&÷r–âfW&–f–VEö&6VÆ–æRç&÷w7ÒÀ¢fW&–f–VEö&6VÆ–æRæ77e÷6†#SbÀ¢fW&–f–VEö&6VÆ–æRæ6GW&VEöBÀ¢¢VÇ6S ¢ÆöFVEö&6VÆ–æRÒöÆöEö&6VÆ–æR€¢&w2æ&6VÆ–æRÀ¢6öæf–uöF–vW7B†6öæf–r’À¢ö6öæf–uö¶W—2†6öæf–r’À¢ö6öæf–uöW‡V7FF–öç2†6öæf–r’À¢¢&6VÆ–æRÒÆöFVEö&6VÆ–æRæö'6W'fF–öç0¢F–ÖW7F×ÒæöæR–bÖöçF†Ç•ö6öçFW‡B—2æ÷BæöæRVÇ6RWF5÷F–ÖW7F×‚¢6Æ÷6W5öBÒæöæP¢–bÖöçF†Ç•ö6öçFW‡B—2æ÷BæöæS ¢6Æ÷6W5öBÒfÆ–FFU÷F–ÖW7F×†ÖöçF†Ç•ö6öçFW‡E³5Õ²&6Æ÷6W5öB%Ò¢vW2Òö6GW&U÷vW2†6öæf–rÂ6Æ÷6W5öCÖ6Æ÷6W5öB¢66†VGVÆUö&–æF–ærÒæöæP¢–bÖöçF†Ç•ö6öçFW‡B—2æ÷BæöæS ¢÷&VfÆ–v‡Eö6öæf–rÂ÷fW&–f–VEö&6VÆ–æRÂ66†VGVÆRÂv–æF÷rÒÖöçF†Ç•ö6öçFW‡@¢6GW&VE÷F–ÖRÒFFWF–ÖRææ÷r‡F–ÖW¦öæRçWF2’ç&WÆ6R†Ö–7&÷6V6öæCÓ¢–bæ÷BfÆ–FFU÷F–ÖW7F×‡v–æF÷u²'66†VGVÆVEöf÷"%Ò’ÃÒ6GW&VE÷F–ÖRÂfÆ–FFU÷F–ÖW7F×‡v–æF÷u²&6Æ÷6W5öB%Ò“ ¢&—6R6öæf–tW'&÷"‚&ÖöçF†Ç’66†VGVÆVB&W'VâÆVgB—G2w&VVBv–æF÷r&Vf÷&R6GW&R6ö×ÆWFVB"¢F–ÖW7F×Ò6GW&VE÷F–ÖRç7G&gF–ÖR‚"U’ÒVÒÒVEBTƒ¢TÓ¢U5¢"¢66†VGVÆUö&–æF–ærÒ°¢'66†VGVÆU÷6†#Sb#¢66†VGVÆRç6†#SbÀ¢'v–æF÷uö–B#¢v–æF÷u²&–B%ÒÀ¢'66†VGVÆVEöf÷"#¢v–æF÷u²'66†VGVÆVEöf÷"%ÒÀ¢Ð¢&÷w2ÒWfÇVFR†6öæf–rÂvW2ÂF–ÖW7F×Â&6VÆ–æR¢ÖWFFFÒw&—FU÷'Våö'F–f7G2€¢&w2æ÷WBÂÖöFRÂ&÷w2Â6öæf–rÂF–ÖW7F×ÂÆöFVEö&6VÆ–æRÂ66†VGVÆUö&–æF–ærÀ¢¢77eöæÖRÒ&&6VÆ–æRæ77b"–bÖöFRÓÒ&&6VÆ–æR"VÇ6R'&W'Vâæ77b ¢6÷VçG2Ò·7FGW3¢7VÒ‡&÷rç7FGW2ÓÒ7FGW2f÷"&÷r–â&÷w2’f÷"7FGW2–â‚%52"Â$E$”eB"Â%Täd”Ä$ÄR"—Ð¢&–çB†§6öâæGV×2‡²&÷WGWB#¢7G"†&w2æ÷WBò77eöæÖR’Â&W†6WF–öç2#¢7G"†&w2æ÷WBò&W†6WF–öç2æÖB"’Â&ÖWFFF#¢ÖWFFFÂ¢¦6÷VçG7ÒÂ6÷'Eö¶W—3ÕG'VR’¢&WGW&â–bæ÷B6÷VçG5²$E$”eB%ÒæBæ÷B6÷VçG5²%Täd”Ä$ÄR%ÒVÇ6R   ¦FVb'V–ÆE÷'6W"‚’Óâ&w'6Rä&wVÖVçE'6W# ¢'6W"Ò6fT&wVÖVçE'6W"†FW67&—F–öãÕõöFö5õò¢7V''6W'2Ò'6W"æFE÷7V''6W'2†FW7CÒ&6öÖÖæB"Â&WV—&VCÕG'VR¢f÷"6öÖÖæB–â‚&&6VÆ–æR"Â'&W'Vâ"Â'66†VGVÆVB×&W'Vâ"“ ¢7V"Ò7V''6W'2æFE÷'6W"†6öÖÖæB¢7V"æFEö&wVÖVçB‚"ÒÖ6öæf–r"Â&WV—&VCÕG'VRÂG—SÕF‚¢7V"æFEö&wVÖVçB‚"ÒÖ÷WB"Â&WV—&VCÕG'VRÂG—SÕF‚¢–b6öÖÖæB–â²'&W'Vâ"Â'66†VGVÆVB×&W'Vâ'Ó ¢7V"æFEö&wVÖVçB‚"ÒÖ&6VÆ–æR"Â&WV—&VCÕG'VRÂG—SÕF‚¢–b6öÖÖæBÓÒ'66†VGVÆVB×&W'Vâ# ¢F–Ö–ærÒ7V"æFEö×WGVÆÇ•öW†6ÇW6—fUöw&÷W‡&WV—&VCÕG'VR¢F–Ö–æræFEö&wVÖVçB‚"Ò×66†VGVÆVBÖf÷""Â†VÇÒ%UD2$d2333’6V6öæBB÷"gFW"F†RÖ–æ–×VÒ&6VÆ–æRvR"¢F–Ö–æræFEö&wVÖVçB‚"Ò×66†VGVÆR"ÂG—SÕF‚Â†VÇÒ&g&÷¦Vâf÷W"×v–æF÷rÖöçF†Ç’66†VGVÆR¥4ôâ"¢7V"æFEö&wVÖVçB‚"Ò×v–æF÷r"Â†VÇÒ'v–æF÷r–Bg&öÒÒ×66†VGVÆR"¢ÆVFvW"Ò7V''6W'2æFE÷'6W"‚&ÖöçF‚ÖVæBÖÆVFvW""¢ÆVFvW"æFEö&wVÖVçB‚"ÒÖ6öæf–r"Â&WV—&VCÕG'VRÂG—SÕF‚¢ÆVFvW"æFEö&wVÖVçB‚"ÒÖ&6VÆ–æRÖÖæ–fW7B"Â&WV—&VCÕG'VRÂG—SÕF‚¢ÆVFvW"æFEö&wVÖVçB‚"Ò×66†VGVÆR"Â&WV—&VCÕG'VRÂG—SÕF‚¢ÆVFvW"æFEö&wVÖVçB‚"Ò×'VâÖÖæ–fW7B"ÂFW7CÒ''VåöÖæ–fW7G2"Â&WV—&VCÕG'VRÂ7F–öãÒ&VæB"ÂG—SÕF‚¢ÆVFvW"æFEö&wVÖVçB‚"ÒÖ÷WB"Â&WV—&VCÕG'VRÂG—SÕF‚¢F–vW7BÒ7V''6W'2æFE÷'6W"‚'66†VGVÆRÖF–vW7B"¢F–vW7BæFEö&wVÖVçB‚"ÒÖ6öæf–r"Â&WV—&VCÕG'VRÂG—SÕF‚¢F–vW7BæFEö&wVÖVçB‚"ÒÖ&6VÆ–æRÖÖæ–fW7B"Â&WV—&VCÕG'VRÂG—SÕF‚¢F–vW7BæFEö&wVÖVçB‚"Ò×66†VGVÆR"Â&WV—&VCÕG'VRÂG—SÕF‚¢&WGW&â'6W   ¦FVbÖ–â‚’Óâ–çC ¢G'“ ¢&WGW&â'Vâ†'V–ÆE÷'6W"‚’ç'6Uö&w2‚’¢W†6WB„6öæf–tW'&÷"Â§6öâä¥4ôäFV6öFTW'&÷"Âõ4W'&÷"’2W†3 ¢&–çB†b&W'&÷#¢¶W†7Ò"Âf–ÆS×7—2ç7FFW'"¢&WGW&â  ¦–bõöæÖUõòÓÒ%õöÖ–åõò# ¢&—6R7—7FVÔW†—B†Ö–â‚’ 