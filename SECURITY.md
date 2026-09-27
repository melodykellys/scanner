# Security Policy

Signal Recon is a reconnaissance and security-header review tool. This policy explains how to report security issues in the project and how to use the scanner responsibly.

## Reporting a Vulnerability

Please do not publish an exploitable vulnerability in a public issue or pull request before the maintainers have had a chance to review it.

1. Check the repository's **Security** tab for a private vulnerability reporting option and use it when available.
2. If private reporting is unavailable, contact a repository maintainer privately through their GitHub profile and ask for a secure reporting channel. Do not include exploit details in a public issue.
3. Include the affected version or commit, the component involved, concise reproduction steps, the security impact, and sanitized logs or screenshots when useful.

Please avoid including credentials, personal information, unredacted tokens, or data belonging to a third party. A report should demonstrate the issue with the minimum testing necessary. Do not access, modify, or retain other users' data.

There is no published bug bounty or guaranteed response time. The maintainers will review reports as their availability permits and may ask for additional details.

## Supported Versions

Security fixes are intended for the latest version on the repository's default branch. No older release support window is currently published. Update to the latest code before reporting an issue where practical.

## Authorized Use

Only scan systems that you own or are explicitly authorized to assess. The scanner sends HTTP requests to the supplied target, checks a bounded list of common paths, resolves discovered hostnames, and runs Nmap against selected common ports. Passive lookups may send the target domain to Certificate Transparency and Internet Archive services.

Keep scans within the agreed scope and rate limits of the target owner. Do not use the tool to evade access controls, disrupt services, access accounts or data, or test systems without permission. A discovered route, response code, technology signature, or client-side string is a lead for review, not proof of a vulnerability.

## Data Handling

- The browser stores the most recent scan report in `localStorage` so the detail pages can display it. Clear the browser's site data to remove that saved report.
- JSON export creates a file in the user's browser. Handle exported reports as potentially sensitive, because they can contain target hostnames, routes, response metadata, and masked credential-like matches.
- The application code does not persist scan reports to a server-side database. This does not cover server, proxy, or hosting-provider logs in deployments managed outside this project.
- The scanner contacts the target and selected public data sources. Do not submit targets or scan data you are not permitted to disclose to those services.

## Deployment Caution

The scan API does not currently require authentication and accepts a user-supplied target. Run it locally or behind access controls. Do not expose it as a public service without first implementing and reviewing authentication, authorization, target/scope restrictions, rate limits, and protections against requests to localhost, private networks, and cloud metadata endpoints.

## Scanner Limitations

Signal Recon provides bounded reconnaissance, not a complete penetration test or vulnerability certification. Network filtering, WAF behavior, timeouts, third-party source outages, and application-specific routing can affect results. Findings labeled possible or unverified require manual confirmation, and a scan with no findings does not establish that a target is secure.


### Thanks and Happy Hacking