# Public Storefront QA

Bounded, read-only baseline and drift evidence for small public storefront surfaces. The Python-standard-library runner performs one bounded request workflow per explicitly configured public HTML URL, including at most five same-host redirects and one transient retry, parses returned HTML without executing JavaScript, and writes a losslessly machine-readable CSV plus an escaped exception report.

The free core is complete and usable on its own. It contains no AI runtime, telemetry, account requirement, third-party SaaS dependency, or checkout dependency. Normal DNS infrastructure and the configured public target hosts still receive ordinary network request metadata.

## Managed pilot

Springfield Systems offers a **$250 USD managed pilot** for one buyer-authorized public domain: up to six public URLs and 20 frozen checks, a baseline, one rerun of the same frozen scope after at least 72 real hours, source-linked CSV and Markdown evidence, and one consolidated factual correction. An optional **$150 USD per-domain monthly continuation** adds four weekly reruns of the same frozen scope and one change-only month-end ledger.

The free core requires the caller to design the configuration, run and schedule it, retain local history, verify manifests, and interpret exceptions. The managed service adds written scope design and approval, real-time scheduling, retained and versioned runs, manifest verification, bounded exception interpretation, the month-end ledger, and the included correction.

The service never signs in, submits forms, enters carts or checkout, accesses analytics or customer data, changes a site, performs security testing, or claims legal compliance or conversion accuracy. Scope review is non-binding and starts no work or payment: [request a public pilot scope review](https://github.com/jakespringfield/public-storefront-qa/issues/new?template=pilot-scope-review.yml).

Jake Springfield is a public-facing business alias for Springfield Systems, which is not represented as incorporated. OpenAI Codex materially assisted implementation, testing, and documentation. No separate personal human review is promised. The project and service are independent of OpenAI and every storefront evaluated.

## Safety boundary

- One exact ASCII hostname, 1-6 explicit URLs, and 1-20 checks per normalized config.
- Only `http` or `https` on ports 80/443. Credentials and every query/fragment delimiter, including empty `?`/`#`, are rejected without echoing the rejected URL.
- URL paths are repeatedly percent-decoded and Unicode-normalized until stable. Ambiguous encoding, backslashes, semicolons, dot paths, and account/auth/cart/checkout route segments are rejected.
- DNS must return only public unicast addresses. Private, loopback, link-local, multicast, unspecified, reserved, and malformed destinations fail closed.
- Each fetch resolves once inside its deadline, freezes that validated address set, then connects directly to one of those IPs. HTTP retains the configured `Host`; HTTPS retains both `Host` and certificate-checked SNI. Redirects must stay on the exact hostname and reuse the pinned address set. This removes a second DNS lookup from the connection path.
- Each URL has one end-to-end deadline (maximum 20 seconds) covering bounded DNS, all connection/request attempts, up to five redirects, one retry for transient GET failures/statuses, response headers, and the response body. Blocking request and header phases are guarded by the shared wall clock, not only socket-inactivity timeouts. The body limit is at most 2,000,000 bytes.
- Final responses must parse to exactly `text/html` or `application/xhtml+xml`; MIME parameters are parsed separately.
- The runner never submits a form, signs in, accesses an account, enters a cart/checkout flow, mutates a site, executes JavaScript, or uses browser automation.
- It does not crawl links, `robots.txt`, or assets. `asset-reference` inspects static `href`/`src` values only and never fetches the referenced object.

This is external evidence capture, not a security scanner, rendered-browser test, accessibility audit, legal-compliance check, or conversion-accuracy claim. A hostile process with local filesystem write access can alter the tool and its SHA-256 metadata; the artifacts are integrity-linked, not cryptographically signed. Scheduled evidence also assumes the host UTC clock is trustworthy; this no-spend MVP does not use an external timestamp authority.

## Check types

| Type | Observation |
|---|---|
| `status` | Final HTTP status integer |
| `title` | Normalized HTML `<title>` text |
| `canonical` | First HTTP(S) canonical URL, resolved absolute, `absent`, or `malformed` |
| `robots-indexability` | `noindex` if meta robots or `X-Robots-Tag` contains it, otherwise `no-noindex-observed`; `robots.txt` is not fetched and this does not establish search-engine eligibility |
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

The baseline is bound to the SHA-256 digest of the entire normalized config, including URL/check semantics and transport bounds. `baseline.meta.json` also binds CSV digest, exact schema, row count, timestamp, and earliest scheduled evidence time. Baseline loading validates metadata, CSV digest, exact columns, status enum, timestamps, uniqueness, and the exact configured URL/check set.

## Real scheduled evidence gate

The Springfield example requires 72 elapsed hours. Read `earliest_scheduled_evidence_at` from `baseline.meta.json`, then run on or after that real time:

```powershell
$scheduledValue = (Get-Content sample-output\baseline.meta.json -Raw | ConvertFrom-Json).earliest_scheduled_evidence_at
$scheduled = if ($scheduledValue -is [datetime]) { $scheduledValue.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$scheduledValue }
python storefront_qa.py scheduled-rerun --config examples\springfield.json --baseline sample-output\baseline.csv --out sample-output --scheduled-for $scheduled
```

The command has no timestamp override. Before full config validation or DNS, it reads only the local configured minimum age and baseline metadata timestamps needed for the gate. It refuses before any DNS or network event unless the scheduled date is at least the configured baseline age and the actual system clock has reached both gates. Full config, digest, CSV, and network validation occur only after that local gate opens. Only a successful `scheduled-rerun` is labeled `scheduled-change-evidence`.

## Outputs and safe consumption

Baseline writes `baseline.csv`; either rerun writes `rerun.csv`. Every run also writes `exceptions.md`, mode-specific metadata, and `output-manifest.json`. All files are staged first, installed with rollback, and the manifest is committed last as the logical transaction marker. Consumers should verify the latest manifest hashes before using a pair.

CSV columns are exactly `url,timestamp,check,expected,observed,status,evidence`. Status is `PASS`, `DRIFT`, or `UNAVAILABLE`. Formula-triggering prefixes are neutralized with a collision-safe reversible apostrophe encoding. `read_csv_records()` restores the exact logical values, including values originally beginning with apostrophes. Markdown cells HTML-escape untrusted text and escape backslashes, pipes, and line endings.

`exceptions.md` contains only DRIFT/UNAVAILABLE rows; full PASS evidence remains in CSV. Exit codes are `0` for all PASS, `2` for drift/unavailability, and `1` for invalid or provenance-mismatched input.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The offline suite includes adversarial regressions for scope caps, destination classes, DNS pinning and SNI, redirect/domain rules, secret-safe errors, repeated route decoding, empty delimiters, size/deadline enforcement, retry bounds, exact MIME parsing, malformed references, hidden/template text, all check types, reversible CSV neutralization, Markdown/HTML escaping, baseline provenance, staged output failure, and the scheduled-date gate.

## License and support boundary

The core is MIT-licensed. See [LICENSE](LICENSE). Security and data-handling boundaries are documented in [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md). This repository provides the free software as-is; the managed pilot is a separate evidence-capture service with the fixed scope above.

