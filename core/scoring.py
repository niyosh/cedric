# core/scoring.py

from typing import Dict, List


# ---------------------------------------------------------
# CENTRAL VULNERABILITY DATABASE
# ---------------------------------------------------------

VULNERABILITY_DB = {

    "SMTP_OPEN_RELAY": {
        "name": "Open Relay",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "description": "SMTP server allows unauthenticated mail relay."
    },

    "SMTP_VRFY_ENUM": {
        "name": "User Enumeration via VRFY",
        "severity": "LOW",
        "cvss_score": 3.1,
        "description": "SMTP VRFY command allows user enumeration."
    },

    "FTP_ANONYMOUS_LOGIN": {
        "name": "Anonymous FTP Login Allowed",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "FTP server allows anonymous authentication."
    },

    "SSH_PASSWORD_AUTH": {
        "name": "Password Authentication Enabled",
        "severity": "LOW",
        "cvss_score": 2.6,
        "description": "SSH server allows password authentication."
    },

"FTP_DIRECTORY_LISTING": {
    "name": "FTP Directory Listing Enabled",
    "severity": "MEDIUM",
    "cvss_score": 5.3,
    "description": "FTP server allows directory listing which may expose sensitive files."
},

"FTP_BOUNCE_ATTACK": {
    "name": "FTP Bounce Attack Possible",
    "severity": "HIGH",
    "cvss_score": 7.8,
    "description": "FTP server accepts PORT command enabling potential bounce attack."
},

"FTP_WEAK_CREDENTIALS": {
    "name": "Weak FTP Credentials",
    "severity": "CRITICAL",
    "cvss_score": 9.0,
    "description": "FTP service allows login with weak or default credentials."
},

"FTP_FEAT_COMMAND": {
    "name": "FTP FEAT Command Enabled",
    "severity": "LOW",
    "cvss_score": 2.0,
    "description": "FTP FEAT command reveals server capabilities."
},

"FTP_SITE_EXEC": {
    "name": "FTP SITE EXEC Command Enabled",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "description": "FTP SITE EXEC command may allow remote command execution."
},

"FTP_ALLO_COMMAND": {
    "name": "FTP ALLO Command Accepted",
    "severity": "LOW",
    "cvss_score": 2.5,
    "description": "FTP ALLO command accepted."
},

"FTP_MDTM_COMMAND": {
    "name": "FTP MDTM Command Enabled",
    "severity": "LOW",
    "cvss_score": 2.5,
    "description": "FTP MDTM command reveals file timestamps."
},

"FTP_STAT_COMMAND": {
    "name": "FTP STAT Command Enabled",
    "severity": "LOW",
    "cvss_score": 2.0,
    "description": "FTP STAT command reveals server information."
}
}


# ---------------------------------------------------------
# EXPLOITABILITY WEIGHTING
# ---------------------------------------------------------

EXPLOITABILITY_FACTORS = {
    "REMOTE_NO_AUTH": 1.2,
    "REMOTE_AUTH_REQUIRED": 1.0,
    "LOCAL": 0.7,
    "INTERNAL_ONLY": 0.6
}


# ---------------------------------------------------------
# GET VULNERABILITY TEMPLATE
# ---------------------------------------------------------

def get_vuln(vuln_id: str, exploitability: str = "REMOTE_AUTH_REQUIRED") -> Dict:

    vuln = VULNERABILITY_DB.get(vuln_id)

    if not vuln:
        return {
            "name": vuln_id,
            "severity": "LOW",
            "cvss_score": 0.0,
            "effective_score": 0.0,
            "description": "Undefined vulnerability"
        }

    base_score = vuln["cvss_score"]
    factor = EXPLOITABILITY_FACTORS.get(exploitability, 1.0)

    effective_score = round(base_score * factor, 2)

    return {
        **vuln,
        "effective_score": effective_score,
        "exploitability": exploitability
    }


# ---------------------------------------------------------
# HOST RISK CALCULATION
# ---------------------------------------------------------

def calculate_host_risk(vulnerabilities: List[Dict]) -> Dict:

    if not vulnerabilities:
        return {
            "total_score": 0,
            "highest_severity": "NONE"
        }

    total_score = sum(
        v.get("effective_score", v.get("cvss_score", 0))
        for v in vulnerabilities
    )

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severities = [v.get("severity", "LOW") for v in vulnerabilities]

    highest = "LOW"
    for level in severity_order:
        if level in severities:
            highest = level
            break

    return {
        "total_score": round(total_score, 2),
        "highest_severity": highest
    }


# ---------------------------------------------------------
# GLOBAL RISK CALCULATION
# ---------------------------------------------------------

def calculate_global_risk(results: List[Dict]) -> Dict:

    all_vulns = []

    for result in results:
        vulns = result.get("findings", {}).get("vulnerabilities", [])
        all_vulns.extend(vulns)

    if not all_vulns:
        return {
            "overall_score": 0,
            "overall_severity": "NONE"
        }

    total_score = sum(
        v.get("effective_score", v.get("cvss_score", 0))
        for v in all_vulns
    )

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severities = [v.get("severity", "LOW") for v in all_vulns]

    highest = "LOW"
    for level in severity_order:
        if level in severities:
            highest = level
            break

    return {
        "overall_score": round(total_score, 2),
        "overall_severity": highest
    }