# First scheduled output

This is the first genuine scheduled comparison for the public Springfield Systems Storefront QA page. It is public product evidence, not client work, a sale, or a claim that the page stayed unchanged.

- Frozen baseline captured: `2026-08-14T13:45:52Z`
- Scheduled comparison captured: `2026-08-17T22:31:46Z`
- Elapsed time: 80 hours, 45 minutes, 54 seconds
- Result: 7 PASS, 1 DRIFT, 0 UNAVAILABLE
- Evidence class: `scheduled-change-evidence`
- Tool version: `1.1.0`

| Check | Result |
|---|---|
| HTTP status | PASS, `200` |
| HTML title | PASS, exact match |
| Canonical URL | PASS, exact match |
| Noindex observation | PASS, `indexable` |
| JSON-LD presence | PASS, `present` |
| Primary copy | DRIFT, expected literal was absent |
| Main selector | PASS, `main#storefront-main` present |
| Same-domain home reference | PASS, present |

The frozen baseline expected `Request the $250 pilot scope review`. The comparison correctly reported that exact literal as absent. A later read confirmed the route returned HTTP 200 and contained `Request the non-binding $250 pilot scope review`. The drift is therefore classified as deliberate buyer-boundary hardening, but it remains DRIFT in the committed evidence.

## Published rows and integrity

- [Baseline CSV](docs/scheduled-proof-2026-08-17/baseline.csv), SHA-256 `88f54ed21be65d2f5c108220d3fd80332ab2bde11f24cb82ae776160dad499f9`
- [Scheduled CSV](docs/scheduled-proof-2026-08-17/rerun.csv), SHA-256 `13b632990b6260c76a51075134a56f659b9fe6eee327d3c2eea554a5342bd753`
- Original rerun metadata SHA-256 `29d9901547f5755e1da1f1a1bb2f387f4d4ad704898bb97d33d9dc8bb5f8f125`
- Original exception report SHA-256 `93fa183c8704f6f8bd9a2ec9cea730ea008813f9438e4980bc444613ac4cc761`
- Original commit manifest SHA-256 `b2f160e7100317059ae71073da54e3af964ce7d159c6615bde573c56b6d21bca`

The two published CSV files are byte-identical to the retained capture inputs and outputs. The original metadata, exception report, and manifest remain in the local evidence bundle and were independently hash-verified before this summary was published.

## Limits and next window

The runner inspected returned static HTML only. It did not execute JavaScript, fetch referenced assets, sign in, submit forms, access analytics or customer data, mutate the site, or establish accessibility, legal compliance, conversion accuracy, or causation.

The original retained baseline did not preserve a baseline-mode commit manifest, so it cannot seed the four-window monthly workflow. The current example configuration also reflects the new non-binding CTA. A future scheduled or monthly claim requires a fresh baseline manifest against that current frozen configuration and a new 72-hour window.
