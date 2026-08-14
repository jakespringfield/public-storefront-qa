# Sample output

This is a compact preview of the free runner's evidence format against the public Springfield Systems Storefront QA page. It is not client work, a 72-hour stability claim, or scheduled change evidence.

- Baseline captured: `2026-08-14T13:45:52Z`
- Immediate comparison captured: `2026-08-14T13:45:53Z`
- Result: 8 PASS, 0 DRIFT, 0 UNAVAILABLE
- Evidence class: `immediate-mechanics-proof`
- Earliest eligible scheduled comparison for this exact baseline: `2026-08-17T13:45:52Z`

| Check | Expected | Observed | Status |
|---|---|---|---|
| HTTP status | `200` | `200` | PASS |
| HTML title | `Public Storefront QA Managed Pilot \| Springfield Systems` | exact match | PASS |
| Canonical URL | `/public-storefront-qa` absolute URL | exact match | PASS |
| Noindex observation | `indexable` | `indexable` | PASS |
| JSON-LD presence | `present` | `present` | PASS |
| Primary copy | `present` | `present` | PASS |
| Main selector | `main#storefront-main` present | present | PASS |
| Same-domain home reference | `present` | `present` | PASS |

The full CSV adds the exact public URL, UTC timestamp, expected value, observed value, status, and source-specific evidence for every row. The exception report contains only DRIFT and UNAVAILABLE rows, while the manifest binds the committed output files to SHA-256 digests.

## Integrity and limits

- Tool version: `1.0.0`
- Normalized configuration SHA-256: `ca75cae4a97293e602a35895348e98f050980772a6baeec0b9860a05b9e659ee`
- Baseline CSV SHA-256: `88f54ed21be65d2f5c108220d3fd80332ab2bde11f24cb82ae776160dad499f9`
- Immediate comparison CSV SHA-256: `055001396f0dc5e650228dbf49c13c7642bbb90ff7feb46e89ff9a569d69a181`

The runner inspects returned static HTML only. It does not execute JavaScript, fetch referenced assets, sign in, submit forms, access analytics or customer data, mutate the site, or establish search-engine eligibility, accessibility, legal compliance, conversion accuracy, or causation.

The [$250 managed pilot](https://springfield-systems.jakespringfield1.workers.dev/public-storefront-qa) applies the same bounded format to a separately approved public scope and delays the comparison by at least 72 real hours.
