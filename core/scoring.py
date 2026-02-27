# core/scoring.py

from typing import Dict, List


# ---------------------------------------------------------
# CENTRAL VULNERABILITY DATABASE
# ---------------------------------------------------------

VULNERABILITY_DB = {

    # ---------------- SMTP ----------------

    # ----------- Critical / Real Vulns -----------

    "SMTP_OPEN_RELAY": {
        "name": "SMTP Open Relay",
        "severity": "CRITICAL",
        "cvss_score": 9.5,
        "description": "SMTP server allows unauthenticated users to relay email messages."
    },

    "SMTP_BLANK_AUTH": {
        "name": "SMTP Authentication Weak / Valid Credentials Found",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "SMTP service allows successful authentication using discovered or weak credentials."
    },

    "SMTP_VRFY_ENUM": {
        "name": "SMTP User Enumeration via VRFY",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "SMTP VRFY command allows remote enumeration of valid user accounts."
    },

    "SMTP_INVALID_CERTIFICATE": {
        "name": "SMTP Invalid or Misconfigured TLS Certificate",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "description": "SMTP STARTTLS certificate is self-signed, improperly configured, or missing required attributes."
    },
    "SMTP_STARTTLS_FAILED": {
    "name": "SMTP STARTTLS Negotiation Failed",
    "severity": "LOW",
    "cvss_score": 3.5,
    "description": "SMTP server advertises STARTTLS but TLS negotiation failed."
    },

    # ----------- SMTP - Informational Checks -----------

    "SMTP_BANNER_DISCLOSED": {
        "name": "SMTP Banner Disclosure",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP service discloses banner information which may reveal server software details."
    },

    "SMTP_EHLO_CAPABILITIES_DISCLOSED": {
        "name": "SMTP EHLO Capabilities Disclosure",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP server discloses supported capabilities via EHLO response."
    },

    "SMTP_STARTTLS_SUPPORTED": {
        "name": "SMTP STARTTLS Supported",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP server supports STARTTLS encryption."
    },

    "SMTP_AUTH_MECHANISMS_DISCLOSED": {
        "name": "SMTP Authentication Mechanisms Disclosed",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP server discloses supported authentication mechanisms."
    },

    "SMTP_VALID_USERS_ENUMERATED": {
        "name": "Valid SMTP Users Enumerated",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP enumeration process identified one or more valid user accounts."
    },

    "SMTP_RELAY_TEST_PERFORMED": {
        "name": "SMTP Relay Test Performed",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP relay testing was performed against the target service."
    },

    "SMTP_STARTTLS_NEGOTIATED": {
        "name": "SMTP STARTTLS Negotiation Successful",
        "severity": "INFO",
        "cvss_score": 0.0,
        "description": "SMTP STARTTLS negotiation completed successfully."
    },

    # ---------------- FTP ----------------
    "FTP_ANONYMOUS_LOGIN": {
        "name": "Anonymous FTP Login Allowed",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "FTP server allows anonymous authentication."
    },

    "FTP_DIRECTORY_LISTING": {
        "name": "FTP Directory Listing Enabled",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "FTP server allows directory listing exposing potential sensitive files."
    },

    "FTP_BOUNCE_ATTACK": {
        "name": "FTP Bounce Attack Possible",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "description": "FTP server accepts arbitrary PORT command enabling bounce attack."
    },

    "FTP_WEAK_CREDENTIALS": {
        "name": "Weak FTP Credentials",
        "severity": "CRITICAL",
        "cvss_score": 9.0,
        "description": "FTP service allows login with weak or default credentials."
    },

    "FTP_USER_ENUMERATION": {
        "name": "FTP User Enumeration",
        "severity": "MEDIUM",
        "cvss_score": 5.0,
        "description": "FTP service reveals valid usernames."
    },

    "FTP_NO_ENCRYPTION": {
        "name": "FTP Without Encryption",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "FTP service does not support TLS, credentials transmitted in cleartext."
    },

    "FTP_SITE_EXEC": {
        "name": "FTP SITE EXEC Command Enabled",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "FTP SITE EXEC may allow remote command execution."
    },
    # ---------------- SSH ----------------
    "CVE-2018-15473": {
        "name": "OpenSSH Username Enumeration",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "OpenSSH versions prior to 7.7 allow username enumeration via timing side-channel."
    },

    "SSH_PASSWORD_AUTH_ENABLED": {
        "name": "SSH Password Authentication Enabled",
        "severity": "MEDIUM",
        "cvss_score": 5.0,
        "description": "SSH password authentication is enabled, increasing brute-force and credential stuffing risk."
    },

    "SSH_WEAK_CREDENTIALS": {
        "name": "Valid SSH Weak Credentials",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Service allows authentication using weak or default credentials, enabling full remote compromise."
    },

    "SSH_WEAK_CIPHER": {
        "name": "Weak SSH Cipher Supported",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Server supports legacy or insecure ciphers (CBC/3DES/ARCFOUR) susceptible to cryptographic attacks."
    },

    "SSH_WEAK_MAC": {
        "name": "Weak SSH MAC Algorithm Supported",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "description": "Server supports weak MAC algorithms such as MD5 or SHA1, risking message integrity."
    },

    "SSH_WEAK_HOSTKEY_SHA1": {
        "name": "SHA1-Based SSH Host Key Supported",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Server supports ssh-rsa (SHA1-based) host keys which are vulnerable to collision attacks."
    },
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


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


# ---------------------------------------------------------
# GET VULNERABILITY TEMPLATE
# ---------------------------------------------------------

def get_vuln(vuln_id: str,
             exploitability: str = "REMOTE_AUTH_REQUIRED") -> Dict:

    vuln = VULNERABILITY_DB.get(vuln_id)

    if not vuln:
        return {
            "id": vuln_id,
            "name": vuln_id,
            "severity": "LOW",
            "cvss_score": 0.0,
            "effective_score": 0.0,
            "description": "Undefined vulnerability",
            "exploitability": exploitability
        }

    base_score = float(vuln.get("cvss_score", 0))
    factor = EXPLOITABILITY_FACTORS.get(exploitability, 1.0)

    # Cap score at 10.0 (CVSS maximum)
    effective_score = round(min(base_score * factor, 10.0), 2)

    return {
        "id": vuln_id,
        "name": vuln["name"],
        "severity": vuln["severity"],
        "cvss_score": base_score,
        "effective_score": effective_score,
        "description": vuln["description"],
        "exploitability": exploitability
    }


# ---------------------------------------------------------
# HOST RISK CALCULATION
# ---------------------------------------------------------

def calculate_host_risk(vulnerabilities: List[Dict]) -> Dict:

    if not vulnerabilities:
        return {
            "total_score": 0.0,
            "highest_severity": "NONE"
        }

    # Remove duplicate vulnerability IDs
    unique = {v["id"]: v for v in vulnerabilities}.values()

    total_score = sum(v.get("effective_score", 0) for v in unique)

    severities = [v.get("severity", "LOW") for v in unique]

    highest = "NONE"
    for level in SEVERITY_ORDER:
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
            "overall_score": 0.0,
            "overall_severity": "NONE"
        }

    # Remove duplicates across hosts
    unique = {v["id"] + str(v.get("exploitability")): v
              for v in all_vulns}.values()

    total_score = sum(v.get("effective_score", 0) for v in unique)

    severities = [v.get("severity", "LOW") for v in unique]

    highest = "NONE"
    for level in SEVERITY_ORDER:
        if level in severities:
            highest = level
            break

    return {
        "overall_score": round(total_score, 2),
        "overall_severity": highest
    }