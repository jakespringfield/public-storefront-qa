# Security boundary

Public Storefront QA is not a security scanner. Use it only on public HTML URLs that you are authorized to check at low frequency.

Do not use it for vulnerability discovery, authenticated areas, credentials, customer data, account, cart, checkout, administration, or destructive testing. The runner rejects credential-bearing URLs, query strings, fragments, private address classes, sensitive route segments, cross-host redirects, and unsupported ports. It never executes target code or JavaScript.

Report a vulnerability in this repository through GitHub's private vulnerability reporting feature if enabled. Do not place vulnerability details in a public issue.
