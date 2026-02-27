import os
import json
from datetime import datetime


def severity_color(severity):

    colors = {
        "CRITICAL": "#8B0000",
        "HIGH": "#FF4500",
        "MEDIUM": "#FFA500",
        "LOW": "#32CD32",
        "INFO": "#1E90FF",
        "NONE": "#808080"
    }

    return colors.get(severity, "#000000")


def generate_html_report(report_data):

    os.makedirs("reports", exist_ok=True)

    filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    html = f"""
    <html>
    <head>
        <title>Scan Report</title>
        <style>
            body {{
                font-family: Arial;
                background-color: #f4f4f4;
                margin: 20px;
            }}

            .card {{
                background: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 6px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.1);
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}

            th {{
                background-color: #333;
                color: white;
            }}

            h2 {{
                margin-top: 0;
            }}

            pre {{
                background: #f0f0f0;
                padding: 10px;
                overflow-x: auto;
                font-size: 12px;
            }}

            details {{
                margin-top: 10px;
            }}

            summary {{
                cursor: pointer;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
    """

    # ==========================================================
    # GLOBAL RISK
    # ==========================================================

    html += f"""
    <div class="card">
        <h2>Global Risk</h2>
        <p><b>Overall Score:</b> {report_data['global_risk']['overall_score']}</p>
        <p style="color:{severity_color(report_data['global_risk']['overall_severity'])}">
            <b>Severity:</b> {report_data['global_risk']['overall_severity']}
        </p>
    </div>
    """

    # ==========================================================
    # PER HOST RISK
    # ==========================================================

    html += """
    <div class="card">
        <h2>Per Host Risk</h2>
        <table>
            <tr>
                <th>Host</th>
                <th>Total Score</th>
                <th>Highest Severity</th>
            </tr>
    """

    for ip, risk in report_data["per_host_risk"].items():
        html += f"""
            <tr>
                <td>{ip}</td>
                <td>{risk['total_score']}</td>
                <td style="color:{severity_color(risk['highest_severity'])}">
                    {risk['highest_severity']}
                </td>
            </tr>
        """

    html += "</table></div>"

    # ==========================================================
    # DETAILED FINDINGS
    # ==========================================================

    html += "<div class='card'><h2>Detailed Findings</h2>"

    for result in report_data["results"]:

        vulns = result.get("findings", {}).get("vulnerabilities", [])

        if not vulns:
            continue

        html += f"<h3>{result['ip']}:{result['port']} ({result['service']})</h3>"

        # Sort by effective score (highest first)
        sorted_vulns = sorted(
            vulns,
            key=lambda x: x.get("effective_score", x.get("cvss_score", 0)),
            reverse=True
        )

        # ---------------- Vulnerabilities ----------------
        for vuln in sorted_vulns:

            score = vuln.get("effective_score", vuln.get("cvss_score", 0))

            html += f"""
                <div style="margin-bottom:15px;">
                    <b>{vuln['name']}</b><br>
                    <b>Score:</b> {score}<br>
                    <span style="color:{severity_color(vuln['severity'])}">
                        <b>Severity:</b> {vuln['severity']}
                    </span><br>
                    {vuln.get('description', '')}
                </div>
            """

        # ---------------- Evidence Block ----------------
        findings_copy = result.get("findings", {}).copy()

        # Remove vulnerabilities from evidence to avoid duplication
        findings_copy.pop("vulnerabilities", None)

        # Remove empty fields
        findings_copy = {
            k: v for k, v in findings_copy.items()
            if v not in (None, [], "", {})
        }

        if findings_copy:
            html += f"""
                <details>
                    <summary>View Evidence</summary>
                    <pre>{json.dumps(findings_copy, indent=4)}</pre>
                </details>
            """

        html += "<hr>"

    html += "</div>"

    # ==========================================================
    # FOOTER
    # ==========================================================

    html += f"""
    <div class="card">
        <h2>Scan Metadata</h2>
        <pre>{json.dumps(report_data.get("scan_metadata", {}), indent=4)}</pre>
    </div>
    """

    html += "</body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename