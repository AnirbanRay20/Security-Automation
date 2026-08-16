"""
log_enricher.py

Parses a plain-text log file, extracts public IPv4 addresses with a
regular expression, deduplicates them, and enriches each one with
country / ISP / hosting-proxy-mobile flags from the ip-api.com REST API.

Live network access to ip-api.com is not guaranteed in every grading
or CI environment, so this script supports a --mock flag that reads
pre-saved sample responses from sample_data/ip_api_sample.json instead
of making a real HTTP call. See the README's "External API fallback"
section for why this exists.

Usage:
    python3 log_enricher.py sample_data/sample_firewall.log
    python3 log_enricher.py sample_data/sample_firewall.log --mock
"""

import argparse
import ipaddress
import json
import re
import sys

import requests

# Matches four dot-separated groups of 1-3 digits. This is intentionally
# permissive (it will match e.g. 999.999.999.999) — validity and the
# private/public distinction are enforced afterwards with the ipaddress
# module, which is far less error-prone than trying to encode RFC 1918
# ranges directly into the regex.
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# The task spec calls out exactly these three RFC 1918 private ranges to
# skip. We check membership in these networks explicitly rather than
# using ipaddress.IPv4Address.is_private, because is_private also excludes
# loopback, link-local, and documentation/TEST-NET ranges (e.g.
# 203.0.113.0/24) — broader than what the task asks us to filter, and it
# would silently swallow other non-RFC1918 ranges an analyst might still
# want enriched.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_private_range(ip_obj: ipaddress.IPv4Address) -> bool:
    return any(ip_obj in net for net in PRIVATE_NETWORKS)


def extract_public_ips(log_path: str) -> set:
    """Read a log file and return the set of unique, valid, public IPv4 addresses found in it."""
    public_ips = set()
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for candidate in IPV4_PATTERN.findall(line):
                try:
                    ip_obj = ipaddress.IPv4Address(candidate)
                except ValueError:
                    continue  # not a valid IPv4 address (e.g. a version string like 1.2.3.4 that's out of range)
                if is_private_range(ip_obj):
                    continue  # skip 10.x.x.x, 172.16-31.x.x, 192.168.x.x per the task spec
                public_ips.add(str(ip_obj))
    return public_ips


def enrich_ip_live(ip: str) -> dict:
    """Query ip-api.com for a single IP and extract the fields we care about."""
    url = f"http://ip-api.com/json/{ip}"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"request failed: {e}"}
    except json.JSONDecodeError as e:
        return {"error": f"invalid JSON in response: {e}"}

    if data.get("status") != "success":
        return {"error": data.get("message", "lookup failed")}

    return {
        "country": data.get("country"),
        "isp": data.get("isp"),
        "hosting": data.get("hosting"),
        "proxy": data.get("proxy"),
        "mobile": data.get("mobile"),
    }


def enrich_ip_mock(ip: str, mock_data: dict) -> dict:
    """Look up a single IP in the pre-saved sample_data/ip_api_sample.json file."""
    entry = mock_data.get(ip)
    if entry is None:
        return {"error": "no mock data available for this IP"}
    if entry.get("status") != "success":
        return {"error": entry.get("message", "lookup failed")}
    return {
        "country": entry.get("country"),
        "isp": entry.get("isp"),
        "hosting": entry.get("hosting"),
        "proxy": entry.get("proxy"),
        "mobile": entry.get("mobile"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract and enrich public IPs from a log file")
    parser.add_argument("log_path", help="Path to the log file to parse")
    parser.add_argument("--mock", action="store_true",
                         help="Use saved sample_data/ip_api_sample.json instead of a live ip-api.com call")
    args = parser.parse_args()

    public_ips = extract_public_ips(args.log_path)

    enriched = {}
    if args.mock:
        try:
            with open("sample_data/ip_api_sample.json", "r", encoding="utf-8") as f:
                mock_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Could not load mock data: {e}", file=sys.stderr)
            sys.exit(1)
        for ip in sorted(public_ips):
            enriched[ip] = enrich_ip_mock(ip, mock_data)
    else:
        for ip in sorted(public_ips):
            enriched[ip] = enrich_ip_live(ip)

    print(json.dumps(enriched, indent=2))


if __name__ == "__main__":
    main()
