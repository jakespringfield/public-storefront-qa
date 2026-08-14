# Privacy and data handling

The free runner sends bounded read-only requests only to the public URLs in the supplied configuration. It has no telemetry, AI runtime, account, analytics integration, or third-party SaaS dependency. DNS infrastructure and the configured target hosts necessarily receive ordinary request metadata such as hostname, source IP, timing, user agent, and requested path according to their own policies.

Local artifacts contain the configured public URLs, timestamps, expectations, observations, evidence text, hashes, and run metadata. They remain wherever the operator writes them. The repository does not transmit or retain those artifacts.

For a managed pilot, submit only public, non-security URLs and public expectations. Do not submit credentials, personal or customer data, unpublished code, analytics exports, vulnerability details, or financial information. The public scope-review route is hosted by GitHub: submissions are public and GitHub processes and retains them under its own policies. Deleting managed local artifacts does not erase GitHub issue history.

Managed artifacts are retained locally for at most 30 days after delivery for one factual correction, then deleted locally.

