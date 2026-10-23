#!/usr/bin/env python3
"""
Automated Web Security Scanner
Educational project: checks basic HTTPS, response headers, and CORS behavior.
Only scan websites you own or have explicit permission to test.
"""
import argparse
import json
import sys
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS in supported browsers.",
    "Content-Security-Policy": "Helps reduce some cross-site scripting risks.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps reduce clickjacking risks in older browser controls.",
    "Referrer-Policy": "Controls how much referrer information is sent.",
    "Permissions-Policy": "Controls access to selected browser features.",
}

def normalize_url(value):
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError("Please enter a valid hostname or URL.")
    return value

def scan(url, timeout=8):
    result = {
        "url": url,
        "checks": [],
        "notes": [
            "This is a basic educational checker, not a full penetration test.",
            "A missing header is not automatically proof of a vulnerability."
        ],
    }
    parsed = urlparse(url)
    result["checks"].append({
        "name": "HTTPS",
        "status": "PASS" if parsed.scheme == "https" else "WARNING",
        "details": "URL uses HTTPS." if parsed.scheme == "https" else
                   "URL uses HTTP. Prefer HTTPS for sites that handle real users or data."
    })

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Educational-Web-Security-Scanner/1.0"},
        )
    except requests.RequestException as exc:
        result["checks"].append({
            "name": "HTTP request",
            "status": "ERROR",
            "details": f"Could not fetch the page: {exc}"
        })
        return result

    result["final_url"] = response.url
    result["http_status"] = response.status_code
    result["server_redirected_to_https"] = urlparse(response.url).scheme == "https"

    for header, explanation in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        result["checks"].append({
            "name": f"Header: {header}",
            "status": "PASS" if value else "INFO",
            "details": f"Present: {value}" if value else f"Not detected. {explanation}"
        })

    # Safe, read-only CORS observation: inspect the response header only.
    # We do not send crafted Origin values or attempt to access protected data.
    cors = response.headers.get("Access-Control-Allow-Origin")
    if cors:
        detail = f"Access-Control-Allow-Origin returned: {cors}. Review whether this is intended."
        status = "REVIEW"
    else:
        detail = "No Access-Control-Allow-Origin header observed on this response."
        status = "INFO"
    result["checks"].append({"name": "CORS header observation", "status": status, "details": detail})
    result["checks"].append({
        "name": "HTTP response",
        "status": "INFO",
        "details": f"Final response status: {response.status_code}; final URL: {response.url}"
    })
    return result

def print_report(result):
    print("\n=== Automated Web Security Scanner ===")
    print("Target:", result["url"])
    if "final_url" in result:
        print("Final URL:", result["final_url"])
        print("HTTP status:", result["http_status"])
    print("-" * 64)
    for item in result["checks"]:
        print(f"[{item['status']}] {item['name']}")
        print("  ", item["details"])
    if result.get("notes"):
        print("\nNotes:")
        for note in result["notes"]:
            print("-", note)

def main():
    parser = argparse.ArgumentParser(
        description="Basic read-only checks for HTTPS, common security headers, and CORS header observation."
    )
    parser.add_argument("url", help="URL of a website you own or are authorized to test")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--json", dest="json_file", help="Optional path to save results as JSON")
    args = parser.parse_args()

    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        sys.exit(2)

    result = scan(url, timeout=max(1, min(args.timeout, 30)))
    print_report(result)
    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_file}")

if __name__ == "__main__":
    main()
