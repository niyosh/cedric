# core/html_report.py

import os
from datetime import datetime


def severity_color(severity):

    colors = {
        "CRITICAL": "#8B0000",
        "HIGH": "#FF4500",
        "MEDIUM": "#FFA500",
        "LOW": "#32CD32",
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
            body {{ font-family: Arial; background-color: #f4f4f4; }}
            .card {{ background: white; padding: 15px; margin: 15px; border-radius: 5px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #333; color: white; }}
        </style>
    </head>
    <body>

    <div class="card">
        <h2>Global Risk</h2>
        <p>Overall Score: {report_data['global_risk']['overall_score']}</p>
        <p style="color:{severity_color(report_data['global_risk']['overall_severity'])}">
            Severity: {report_data['global_risk']['overall_severity']}
        </p>
    </div>

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

    html += "<div class='card'><h2>Detailed Findings</h2>"

    for result in report_data["results"]:

        vulns = result.get("findings", {}).get("vulnerabilities", [])

        if not vulns:
            continue

        html += f"<h3>{result['ip']}:{result['port']} ({result['service']})</h3>"

        for vuln in vulns:

            score = vuln.get("effective_score", vuln.get("cvss_score", 0))

            html += f"""
                <p>
                    <b>{vuln['name']}</b><br>
                    Score: {score}<br>
                    <span style="color:{severity_color(vuln['severity'])}">
                        Severity: {vuln['severity']}
                    </span><br>
                    {vuln.get('description', '')}
                </p>
            """

    html += "</div></body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename