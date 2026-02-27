# modules/ssh.py

import asyncssh
from datetime import datetime
from core.scoring import get_vuln


async def banner_grab(ip, port, timeout=5):
    try:
        await asyncssh.connect(
            ip,
            port=port,
            username="invalid",
            password="invalid",
            known_hosts=None,
            login_timeout=timeout
        )
    except asyncssh.PermissionDenied as e:
        return str(e)
    except Exception:
        return None


async def check_password_auth(ip, port, timeout=5):
    try:
        await asyncssh.connect(
            ip,
            port=port,
            username="invalid",
            password="invalid",
            known_hosts=None,
            login_timeout=timeout
        )
    except asyncssh.PermissionDenied:
        return True
    except Exception:
        return False

    return False


async def scan(ip, port, service, version, module_config=None, profile="normal"):

    timeout = module_config.get("timeout", 5) if module_config else 5

    findings = {
        "banner": None,
        "password_auth_enabled": False,
        "vulnerabilities": []
    }

    try:
        findings["banner"] = await banner_grab(ip, port, timeout)

        if profile != "stealth":
            findings["password_auth_enabled"] = await check_password_auth(ip, port, timeout)

            if findings["password_auth_enabled"]:
                findings["vulnerabilities"].append(
                    get_vuln("SSH_PASSWORD_AUTH", exploitability="REMOTE_AUTH_REQUIRED")
                )

    except Exception:
        pass

    return build_result(ip, port, service, version, findings)


def build_result(ip, port, service, version, findings):
    return {
        "ip": ip,
        "port": port,
        "service": service,
        "module": "ssh",
        "version": version,
        "timestamp": datetime.now().isoformat(),
        "findings": findings
    }