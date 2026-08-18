# Public Storefront QA

[![Test](https://github.com/jakespringfield/public-storefront-qa/actions/workflows/test.yml/badge.svg)](https://github.com/jakespringfield/public-storefront-qa/actions/workflows/test.yml)

Bounded, read-only baseline and drift evidence for small public storefront surfaces. The Python-standard-library runner performs one bounded request workflow per explicitly configured public HTML URL, including at most five same-host redirects and one transient retry, parses returned HTML without executing JavaScript, and writes a losslessly machine-readable CSV plus an escaped exception report.

The free core is complete and usable on its own. It contains no AI runtime, telemetry, account requirement, third-party SaaS dependency, or checkout dependency. Normal DNS infrastructure and the configured public target hosts still receive ordinary network request metadata.

## Managed pilot

Springfield Systems offers a **$250 USD managed pilot** for one buyer-authorized public domain: up to six public URLs and 20 frozen checks, a baseline, one rerun of the same frozen scope after at least 72 real hours, source-linked CSV and Markdown evidence, and one consolidated factual correction. An optional **$150 USD per-domain monthly continuation** adds four weekly reruns of the same frozen scope and one change-only month-end ledger. Each continuation month requires separate written acceptance of the price, exact service period, and four non-overlapping UTC capture windows. The acceptance must reference the canonical schedule SHA-256 before the first window. It is month-to-month, with no automatic renewal or scope expansion.

See the [managed pilot page](https://springfield-systems.jakespringfield1.workers.dev/public-storefront-qa) for the buyer-facing scope, deliverables, operating boundaries, and public intake path.

See [SAMPLE_OUTPUT.md](SAMPLE_OUTPUT.md) for the immediate mechanics preview and [SCHEDULED_OUTPUT.md](SCHEDULED_OUTPUT.md) for the first genuine 72-hour comparison. The scheduled proof preserves its detected CTA-copy drift instead of rewriting the result as a pass.

The free core requires the caller to design the configuration and monthly schedule, run it at the agreed times, retain separate source bundles, verify manifests, generate the ledger, and interpret exceptions. The managed service adds written scope and schedule design, buyer approval, scheduled captures in the agreed windows, retained and versioned runs, manifest verification, bounded exception interpretation, and the buyer handoff. The pilot correction does not automatically renew as a monthly correction; any continuation correction must be stated in that month's written acceptance.

One-off pilot artifacts are retained locally for at most 30 days after delivery. While a monthly continuation is active, Springfield Systems retains only the frozen config, baseline, accepted schedule, committed run bundles, and dependent ledgers needed to deliver the service. Those local artifacts are deleted within 30 days after final continuation delivery or cancellation. Delivered buyer copies and public GitHub issue history are outside the local deletion process. See [PRIVACY.md](PRIVACY.md).

The service never signs in, submits forms, enters carts or checkout, accesses analytics or customer data, changes a site, performs security testing, or claims legal compliance or conversion accuracy. Scope review is non-binding and starts no work or payment: [request a public pilot scope review](https://github.com/jakespringfield/public-storefront-qa/issues/new?template=pilot-scope-review.yml). GitHub sign-in is required to submit, and the resulting issue is public.

For a question about whether this public-only scope fits before submitting, email [jakespringfield1@gmail.com](mailto:jakespringfield1@gmail.com?subject=Public%20Storefront%20QA%20scope%20question). Do not send credentials, customer or personal data, private-repository details, or security findings. Email creates no order or payment obligation and does not replace the public scope-review intake.

Jake Springfield is a public-facing business alias for Springfield Systems, which is not represented as incorporated. OpenAI Codex materially assisted implementation, testing, and documentation. No separate personal human review is promised. The project and service are independent of OpenAI and every storefront evaluated.

## Safety boundary

- One exact ASCII hostname, 1-6 explicit URLs, and 1-20 checks per normalized config. Each URL is capped at 4,096 characters, each configured expected or match value at 16,384 characters, and JSON nesting at 100 levels so every generated artifact can be verified consistently across supported Python versions with the same parser bounds.
- Only `http` or `https` on ports 80/443. Credentials and every query/fragment delimiter, including empty `?`/`#`, are rejected without echoing the rejected URL.
- URL paths are repeatedly percent-decoded and Unicode-normalized until stable. Ambiguous encoding, backslashes, semicolons, dot paths, and account/auth/cart/checkout route segments are rejected. Accepted Unicode paths are UTF-8 percent-encoded only at the HTTP transport seam.
- DNS must return only public unicast addresses. Private, loopback, link-local, multicast, unspecified, reserved, and malformed destinations fail closed. After a verified baseline, a transient DNS failure is recorded as `UNAVAILABLE`; it never relaxes the destination-class check.
- Each fetch resolves once inside its deadline, freezes that validated address set, then connects directly to one of those IPs. HTTP retains the configured `Host`; HTTPS retains both `Host` and certificate-checked SNI. Redirects must stay on the exact hostname and reuse the pinned address set. This removes a second DNS lookup from the connection path.
- Each URL has one end-to-end deadline (maximum 20 seconds) covering bounded DNS, all connection/request attempts, up to five redirects, one retry for transient GET failures/statuses, response headers, and the response body. If the retry also returns a transient status, that final response remains observable when it is HTML; a non-HTML final response is `UNAVAILABLE` under the MIME boundary. Blocking request and header phases are guarded by the shared wall clock, not only socket-inactivity timeouts. The body limit is at most 2,000,000 bytes.
- Final responses must parse to exactly `text/html` or `application/xhtml+xml`; MIME parameters are parsed separately. Unsupported or failing declared charsets fall back to UTF-8 replacement, decoded surrogate code points are replaced, and malformed or marked-section (`<![...`) HTML becomes an explicit `UNAVAILABLE` observation instead of varying across parser versions or crashing the capture.
- The runner never submits a form, signs in, accesses an account, enters a cart/checkout flow, mutates a site, executes JavaScript, or uses browser automation.
- It does not crawl links, `robots.txt`, or assets. `asset-reference` inspects static `href`/`src` values only and never fetches the referenced object.

This is external evidence capture, not a security scanner, rendered-browser test, accessibility audit, legal-compliance check, or conversion-accuracy claim. A hostile process with local filesystem write access can alter the tool and its SHA-256 metadata; the artifacts are integrity-linked, not cryptographically signed. Scheduled evidence also assumes the host UTC clock is trustworthy; this no-spend MVP does not use an external timestamp authority.

## Check types

| Type | Observation |
|---|---|
| `status` | Final HTTP status integer |
| `title` | Normalized HTML `<title>` text |
| `canonical` | First HTTP(S) canonical URL, resolved absolute, `absent`, or `malformed` |
| `robots-indexability` | `noindex` if meta robots or `X-Robots-Tag` contains it, otherwise `indexable`, meaning only that no `noindex` was observed in those two surfaces; `robots.txt` is not fetched and this does not establish search-engine eligibility |
| `structured-data-presence` | Presence of `script[type="application/ld+json"]`; content is not evaluated or executed |
| `text` | Literal static HTML text outside `head`, script/style/noscript/template, `hidden`, `aria-hidden="true"`, and inline display/visibility hiding |
| `selector` | Static presence using `tag`, `#id`, `.class`, `tag#id`, `tag.class`, or `tag#id.class` |
| `asset-reference` | Exact normalized same-domain HTTP(S) `href` or `src`; referenced content is not fetched |

Presence checks expect `present` or `absent`. Canonical expects a same-domain absolute URL or `absent`.

## Baseline and immediate mechanics proof

Python 3.11 or newer is sufficient. No install or paid service is needed.

```powershell
git clone https://github.com/jakespringfield/public-storefront-qa.git
cd public-storefront-qa
python storefront_qa.py baseline --config examples\springfield.json --out sample-output
python storefront_qa.py rerun --config examples\springfield.json --baseline sample-output\baseline.csv --out sample-output
```

Baseline compares observations with config expectations. Immediate `rerun` compares new observations with the baseline and is labeled `immediate-mechanics-proof` in `rerun.meta.json`. It proves the comparison mechanics only. It is not evidence of 72-hour stability or drift detection.

The baseline is bound to the SHA-256 digest of the entire normalized config, including URL/check semantics and transport bounds. `baseline.meta.json` also binds tool version, CSV digest, exact schema, row count, timestamp, and earliest scheduled evidence time. Baseline loading validates metadata, CSV digest, exact columns, status enum, timestamps, uniqueness, and the exact configured URL/check set. Rerun metadata records the exact loaded baseline CSV SHA-256 and its `captured_at` timestamp.

## Real scheduled evidence gate

The Springfield example requires 72 elapsed hours. Read `earliest_scheduled_evidence_at` from `baseline.meta.json`, then run on or after that real time:

```powershell
$scheduledValue = (Get-Content sample-output\baseline.meta.json -Raw | ConvertFrom-Json).earliest_scheduled_evidence_at
$scheduled = if ($scheduledValue -is [datetime]) { $scheduledValue.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$scheduledValue }
python storefront_qa.py scheduled-rerun --config examples\springfield.json --baseline sample-output\baseline.csv --out sample-output --scheduled-for $scheduled
```

The command has no timestamp override. Before full config validation or DNS, it reads only the local configured minimum age and baseline metadata timestamps needed for the gate. It refuses before any DNS or network event unless the scheduled date is at least the configured baseline age and the actual system clock has reached both gates. Full config, digest, CSV, and network validation occur only after that local gate opens. Only a successful `scheduled-rerun` is labeled `scheduled-change-evidence`.

## Four-window monthly continuation

Monthly evidence uses a frozen JSON schedule rather than timestamp arithmetic inferred after the fact. Start from [`examples/monthly-schedule.template.json`](examples/monthly-schedule.template.json), then replace its period, baseline hash/time, and four UTC windows with the proposed values. The normalized config digest must match the frozen config. The four half-open windows must be ordered and non-overlapping; each `scheduled_for` must fall inside its window; every window must open after baseline eligibility.

Validate the complete proposal and print its canonical digest without DNS or target access:

```powershell
python storefront_qa.py schedule-digest --config frozen.json --baseline-manifest runs\baseline\output-manifest.json --schedule monthly-schedule.json
```

The buyer's written acceptance must reference that returned `schedule_sha256` before the first window. The same digest is then printed in each committed run and final ledger. Any schedule edit changes the digest and requires new written acceptance before capture begins.

Use a fresh output directory for every window. A schedule-bound run refuses before DNS when its window is not open, rechecks the clock before every URL, caps each URL's total DNS-and-GET deadline at the remaining window time, and stops launching URLs at close. It records the schedule digest, window ID, scheduled time, and actual capture time, checks the window again after network capture, then installs one complete directory by a single same-filesystem rename. A target-side transient DNS failure or other `UNAVAILABLE` observation is a valid captured result. An unsafe DNS destination, provenance, operator, storage, or preflight failure that commits no bundle does not count as one of the four captures.

```powershell
python storefront_qa.py scheduled-rerun --config frozen.json --baseline runs\baseline\baseline.csv --schedule monthly-schedule.json --window week-1 --out runs\week-1
python storefront_qa.py scheduled-rerun --config frozen.json --baseline runs\baseline\baseline.csv --schedule monthly-schedule.json --window week-2 --out runs\week-2
python storefront_qa.py scheduled-rerun --config frozen.json --baseline runs\baseline\baseline.csv --schedule monthly-schedule.json --window week-3 --out runs\week-3
python storefront_qa.py scheduled-rerun --config frozen.json --baseline runs\baseline\baseline.csv --schedule monthly-schedule.json --window week-4 --out runs\week-4
```

After the accepted period ends, aggregate the four committed manifests. Manifest arguments may be supplied in any order; schedule order controls the output.

```powershell
python storefront_qa.py month-end-ledger --config frozen.json --baseline-manifest runs\baseline\output-manifest.json --schedule monthly-schedule.json --run-manifest runs\week-1\output-manifest.json --run-manifest runs\week-2\output-manifest.json --run-manifest runs\week-3\output-manifest.json --run-manifest runs\week-4\output-manifest.json --out ledgers\2026-09
```

The ledger command performs no DNS or network access. It reads each committed source file once, verifies exact manifest hashes, metadata, CSV schema, row keys, status coherence, frozen config/baseline lineage, schedule/window binding, capture order, and period completion, then creates a fresh output directory by a single same-filesystem rename. Its Markdown always inventories all four runs. Its CSV contains only transitions in observation or availability across `baseline -> week 1 -> week 2 -> week 3 -> week 4`. Repeated unchanged drift or repeated unavailability is not duplicated. A zero-transition CSV contains only its header and the report says only that no transitions were recorded among the frozen checks, never that the website did not change.

## Outputs and safe consumption

Baseline writes `baseline.csv`; either rerun writes `rerun.csv`. Every run also writes `exceptions.md`, mode-specific metadata, and `output-manifest.json`. Metadata and the manifest identify the tool version. All files are staged first, installed with rollback, and the manifest is committed last as the logical transaction marker. Consumers should verify the latest manifest hashes before using a pair.

CSV columns are exactly `url,timestamp,check,expected,observed,status,evidence`. Status is `PASS`, `DRIFT`, or `UNAVAILABLE`. Formula-triggering prefixes are neutralized with a collision-safe reversible apostrophe encoding. `read_csv_records()` restores the exact logical values, including values originally beginning with apostrophes. Markdown cells HTML-escape untrusted text and escape backslashes, pipes, and line endings.

`exceptions.md` contains only DRIFT/UNAVAILABLE rows; full PASS evidence remains in CSV. A completed monthly aggregation writes `month-end-ledger.csv`, `month-end-ledger.md`, `month-end-ledger.meta.json`, and `output-manifest.json`. The ledger metadata inventories the four agreed windows, actual capture times, hashes, source versions, completeness, and PASS/DRIFT/UNAVAILABLE counts. Exit codes are `0` for all PASS or a valid ledger, including a ledger with transitions; `2` for a capture with drift/unavailability; and `1` for invalid, incomplete, premature, tampered, or provenance-mismatched input.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The offline suite includes adversarial regressions for scope caps, deeply nested and huge-number JSON, malformed JSON types and Unicode, timestamp overflow, destination classes, transient DNS capture versus private-DNS fail-closed behavior, DNS pinning and SNI, redirect/domain rules, secret-safe errors, repeated route decoding, Unicode request paths, empty delimiters, size/deadline and window-close enforcement, retry bounds, declared-charset failures, malformed HTML/references, hidden/template text, all check types, reversible CSV neutralization, Markdown/HTML escaping, baseline provenance, staged output failure, CLI exit semantics, the scheduled-date gate, schedule-bound fresh directories, zero-network ledger generation, exact source-manifest verification, malformed self-rehashed CSV, source/output aliasing, period completion, zero-transition language, and unavailability/recovery transitions.

## License and support boundary

The core is MIT-licensed. See [LICENSE](LICENSE). Security and data-handling boundaries are documented in [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md). This repository provides the free software as-is; the managed pilot is a separate evidence-capture service with the fixed scope above.
