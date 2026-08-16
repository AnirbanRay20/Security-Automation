"""
virustotal_check.py

Queries the VirusTotal public API v3 for each unique public IP (reuses
extract_public_ips from log_enricher.py) and reports vendor detection
counts and the last analysis date.

The VirusTotal API key is loaded from the VT_API_KEY environment
variable and is never hardcoded (see .env.example).

Live network access to VirusTotal is not guaranteed in every grading
or CI environment, so this script supports a --mock flag that reads
pre-saved sample responses from sample_data/virustotal_sample.json
instead of making a real HTTP call.

Usage:
    export VT_API_KEY=your_real_key_here
    python3 virustotal_check.py sample_data/sample_firewall.log
    python3 virustotal_check.py sample_data/sample_firewall.log --mock
"""

import argparse
import datetime
import json
import os
import sys

import requests
from dotenv import load_dotenv

from log_enricher import extract_public_ips

load_dotenv()

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def check_ip_live(ip: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(VT_BASE_URL + ip, headers=headers, timeout=10)
        if resp.status_code == 401:
            return {"error": "invalid or missing VirusTotal API key"}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded — try again later"}
        if resp.status_code == 404:
            return {"error": "IP not found in VirusTotal"}
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"request failed: {e}"}
    except json.JSONDecodeError as e:
        return {"error": f"invalid JSON in response: {e}"}

    return _extract_fields(data)


def check_ip_mock(ip: str, mock_data: dict) -> dict:
    entry = mock_data.get(ip)
    if entry is None:
        return {"error": "no mock data available for this IP"}
    return _extract_fields(entry)


def _extract_fields(data: dict) -> dict:
    try:
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        last_date_epoch = attrs.get("last_analysis_date")
        last_date = (
            datetime.datetime.fromtimestamp(last_date_epoch, datetime.timezone.utc).isoformat()
            if last_date_epoch is not None
            else None
        )
        return {
            "malicious_detections": stats.get("malicious"),
            "harmless_detections": stats.get("harmless"),
            "last_analysis_date": last_date,
        }
    except (KeyError, TypeError) as e:
        return {"error": f"unexpected response shape: {e}"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich public IPs from a log file with VirusTotal data")
    parser.add_argument("log_path", help="Path to the log file to parse")
    parser.add_argument("--mock", action="store_true",
                         help="Use saved sample_data/virustotal_sample.json instead of a live VirusTotal call")
    args = parser.parse_args()

    public_ips = extract_public_ips(args.log_path)
    results = {}

    if args.mock:
        try:
            with open("sample_data/virustotal_sample.json", "r", encoding="utf-8") as f:
                mock_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Could not load mock data: {e}", file=sys.stderr)
            sys.exit(1)
        for ip in sorted(public_ips):
            results[ip] = check_ip_mock(ip, mock_data)
    else:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            print("VT_API_KEY is not set. Set it in your environment or .env file, "
                  "or re-run with --mock.", file=sys.stderr)
            sys.exit(1)
        for ip in sorted(public_ips):
            results[ip] = check_ip_live(ip, api_key)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
