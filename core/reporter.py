# core/reporter.py

import json
import os
from datetime import datetime
from core.scoring import calculate_host_risk, calculate_global_risk


def normalize_result(result):
    return result


def summarize_results(results):

    total_hosts = len(set(r["ip"] for r in results))
    total_services = len(results)
    total_vulns = sum(
        len(r.get("findings", {}).get("vulnerabilities", []))
        for r in results
    )

    return {
        "total_hosts": total_hosts,
        "total_services": total_services,
        "total_vulnerabilities": total_vulns
    }


def build_report(results, metadata):

    summary = summarize_results(results)

    host_vuln_map = {}

    for result in results:
        ip = result["ip"]
        vulns = result.get("findings", {}).get("vulnerabilities", [])

        if ip not in host_vuln_map:
            host_vuln_map[ip] = []

        host_vuln_map[ip].extend(vulns)

    per_host_risk = {
        ip: calculate_host_risk(vulns)
        for ip, vulns in host_vuln_map.items()
    }

    global_risk = calculate_global_risk(results)

    return {
        "scan_metadata": metadata,
        "summary": summary,
        "global_risk": global_risk,
        "per_host_risk": per_host_risk,
        "results": results
    }


def save_json_report(report_data):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    return filename