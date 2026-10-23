# Automated Web Security Scanner Using Python

## Overview
A beginner-friendly educational tool that performs read-only checks on a website for:
- Whether the supplied URL uses HTTPS.
- Common security response headers.
- Basic observation of the `Access-Control-Allow-Origin` CORS response header.
- HTTP response status and final URL after redirects.

## Important ethical and safety note
Run this tool only against websites you own or have explicit permission to assess. It sends a normal HTTP GET request and does not attempt exploitation, login bypass, brute force, or data extraction. This is a learning aid, not a complete security audit.

## Files
- `scanner.py` — application source code.
- `requirements.txt` — Python dependency list.
- `project_report.pdf` — project report.
- `README.md` — setup and usage instructions.

## Requirements
- Python 3.9 or later
- Internet access
- `requests` library

## Install and run
```bash
python -m pip install -r requirements.txt
python scanner.py https://example.com
```
Use a site you own or are authorized to test instead of `example.com`.

Save results as JSON:
```bash
python scanner.py https://example.com --json report.json
```

## Understanding the results
- `PASS`: a basic check passed or a header was observed.
- `INFO`: information for review; it does not automatically indicate a vulnerability.
- `REVIEW`: a configuration value was observed and should be checked against the site's intended policy.
- `WARNING`: a potential improvement was noticed.
- `ERROR`: the request could not be completed.

A missing security header is not by itself proof that a site is vulnerable. Some headers depend on the type of application and its deployment.

## Limitations
- Checks only the first page response and its response headers.
- Does not crawl the site or test authentication, input validation, TLS cipher strength, or exploitability.
- CORS is context-dependent; a response header alone cannot establish whether a CORS policy is unsafe.
- Results can vary due to redirects, proxies, CDN settings, and server behavior.

## Future improvements
- Add HTML and PDF report export.
- Add unit tests and structured severity scoring.
- Add a small graphical user interface.
- Add checks for cookie flags and certificate expiry with careful validation.

## Author
Student project for learning Python and introductory web security.
