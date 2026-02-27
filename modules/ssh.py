# modules/ssh.py

import asyncssh
import asyncio
import socket
import re
from datetime import datetime
from core.scoring import get_vuln

MODULE_NAME = "ssh"

WEAK_USERNAMES = ["root", "admin", "test", "user"]
DEFAULT_PASSWORDS = ["password", "123456", "admin", "root"]

WEAK_CIPHERS = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour"]
WEAK_MACS = ["hmac-md5", "hmac-sha1"]
WEAK_HOST_KEYS = ["ssh-rsa"]  # SHA1-based


# -------------------------------------------------
# RAW BANNER GRAB (NO AUTH ATTEMPT)
# -------------------------------------------------
async def banner_grab(ip, port, timeout=5):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return banner.decode(errors="ignore").strip()
    except Exception:
        return None


# -------------------------------------------------
# PARSE VERSION
# -------------------------------------------------
def parse_version(banner):
    match = re.search(r"SSH-\d\.\d-(\S+)", banner or "")
    return match.group(1) if match else None


# -------------------------------------------------
# ENUMERATE ALGORITHMS
# -------------------------------------------------
async def enumerate_algorithms(ip, port, timeout=5):
    try:
        conn = await asyncssh.connect(
            ip,
            port=port,
            username="invalid",
            password="invalid",
            known_hosts=None,
            login_timeout=timeout
        )
    except asyncssh.PermissionDenied as e:
        transport = e.connection.get_transport() if hasattr(e, "connection") else None
        if not transport:
            return {}

        return {
            "kex": transport.get_extra_info("kex_algs"),
            "ciphers": transport.get_extra_info("server_cipher_algs"),
            "macs": transport.get_extra_info("server_mac_algs"),
            "host_keys": transport.get_extra_info("server_host_key_algs"),
        }
    except Exception:
        return {}

    return {}


# -------------------------------------------------
# PASSWORD AUTH CHECK
# -------------------------------------------------
async def check_password_auth(ip, port, timeout=5):
    try:
        await asyncssh.connect(
            ip,
            port=port,
            username="invaliduser",
            password="invalidpass",
            known_hosts=None,
            login_timeout=timeout
        )
    except asyncssh.PermissionDenied:
        return True
    except Exception:
        return False
    return False


# -------------------------------------------------
# USER ENUMERATION (BASIC)
# -------------------------------------------------
async def enumerate_users(ip, port, timeout=5):
    valid = []
    for user in WEAK_USERNAMES:
        try:
            await asyncssh.connect(
                ip,
                port=port,
                username=user,
                password="invalidpass",
                known_hosts=None,
                login_timeout=timeout
            )
        except asyncssh.PermissionDenied:
            valid.append(user)
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return valid


# -------------------------------------------------
# PARALLEL CREDENTIAL SPRAY
# -------------------------------------------------
async def credential_spray(ip, port, timeout=5, concurrency=3):
    found = []
    semaphore = asyncio.Semaphore(concurrency)

    async def attempt(user, pwd):
        async with semaphore:
            try:
                await asyncssh.connect(
                    ip,
                    port=port,
                    username=user,
                    password=pwd,
                    known_hosts=None,
                    login_timeout=timeout
                )
                found.append({"username": user, "password": pwd})
            except:
                pass

    tasks = []
    for u in WEAK_USERNAMES:
        for p in DEFAULT_PASSWORDS:
            tasks.append(asyncio.create_task(attempt(u, p)))

    await asyncio.gather(*tasks)
    return found


# -------------------------------------------------
# WEAK ALGORITHM ANALYSIS
# -------------------------------------------------
def analyze_algorithms(algo_data):
    findings = []
    vulnerabilities = []

    if not algo_data:
        return findings, vulnerabilities

    ciphers = algo_data.get("ciphers") or []
    macs = algo_data.get("macs") or []
    host_keys = algo_data.get("host_keys") or []

    weak_cipher_detected = any(c in WEAK_CIPHERS for c in ciphers)
    weak_mac_detected = any(m in WEAK_MACS for m in macs)
    weak_hostkey_detected = any(h in WEAK_HOST_KEYS for h in host_keys)

    if weak_cipher_detected:
        vulnerabilities.append(
            get_vuln("SSH_WEAK_CIPHER", exploitability="NETWORK")
        )

    if weak_mac_detected:
        vulnerabilities.append(
            get_vuln("SSH_WEAK_MAC", exploitability="NETWORK")
        )

    if weak_hostkey_detected:
        vulnerabilities.append(
            get_vuln("SSH_WEAK_HOSTKEY_SHA1", exploitability="NETWORK")
        )

    findings.append({
        "kex": algo_data.get("kex"),
        "ciphers": ciphers,
        "macs": macs,
        "host_keys": host_keys
    })

    return findings, vulnerabilities


# -------------------------------------------------
# VERSION BASED CVE MAPPING
# -------------------------------------------------
def detect_version_vulns(ssh_version):
    vulns = []

    if not ssh_version:
        return vulns

    if "OpenSSH_" in ssh_version:
        try:
            version_number = ssh_version.split("_")[1]
            major_minor = float(version_number.split("p")[0])

            if major_minor < 7.7:
                vulns.append(
                    get_vuln("CVE-2018-15473", exploitability="REMOTE_AUTH_REQUIRED")
                )
        except:
            pass

    return vulns


# -------------------------------------------------
# MAIN SCAN
# -------------------------------------------------
async def scan(ip, port, service, version, module_config=None, profile="normal"):
    timeout = module_config.get("timeout", 5) if module_config else 5
    aggressive = profile == "aggressive"

    findings = {
        "banner": None,
        "ssh_version": None,
        "algorithms": {},
        "password_auth_enabled": False,
        "valid_users": [],
        "weak_credentials": [],
        "vulnerabilities": []
    }

    try:
        banner = await banner_grab(ip, port, timeout)
        findings["banner"] = banner

        ssh_version = parse_version(banner)
        findings["ssh_version"] = ssh_version

        findings["vulnerabilities"].extend(
            detect_version_vulns(ssh_version)
        )

        algo_data = await enumerate_algorithms(ip, port, timeout)
        algo_findings, algo_vulns = analyze_algorithms(algo_data)
        findings["algorithms"] = algo_findings
        findings["vulnerabilities"].extend(algo_vulns)

        if profile != "stealth":

            findings["password_auth_enabled"] = await check_password_auth(
                ip, port, timeout
            )

            if findings["password_auth_enabled"]:
                findings["vulnerabilities"].append(
                    get_vuln("SSH_PASSWORD_AUTH_ENABLED", exploitability="REMOTE_AUTH_REQUIRED")
                )

            findings["valid_users"] = await enumerate_users(ip, port, timeout)

            if aggressive:
                findings["weak_credentials"] = await credential_spray(
                    ip, port, timeout
                )

                if findings["weak_credentials"]:
                    findings["vulnerabilities"].append(
                        get_vuln("SSH_WEAK_CREDENTIALS", exploitability="REMOTE_AUTH_REQUIRED")
                    )

    except Exception:
        pass

    return build_result(ip, port, service, version, findings)


# -------------------------------------------------
# RESULT BUILDER
# -------------------------------------------------
def build_result(ip, port, service, version, findings):
    return {
        "ip": ip,
        "port": port,
        "service": service,
        "module": MODULE_NAME,
        "version": version,
        "timestamp": datetime.utcnow().isoformat(),
        "findings": findings
    }