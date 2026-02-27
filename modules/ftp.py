# modules/ftp.py

import asyncio
from datetime import datetime
from core.scoring import get_vuln

COMMON_CREDENTIALS = [
    ("anonymous", "anonymous@"),
    ("ftp", "ftp"),
    ("admin", "admin"),
    ("user", "password"),
    ("test", "test"),
    ("root", "root"),
]

DEFAULT_TIMEOUT = 5


async def open_connection(ip, port, timeout=DEFAULT_TIMEOUT):
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
    except Exception:
        return None, None


async def send_command(writer, reader, command, timeout=DEFAULT_TIMEOUT):
    try:
        writer.write(command)
        await writer.drain()
        return await asyncio.wait_for(reader.read(1024), timeout=timeout)
    except Exception:
        return b""


async def check_anonymous_login(reader, writer):
    await send_command(writer, reader, b"USER anonymous\r\n")
    response = await send_command(writer, reader, b"PASS anonymous@\r\n")
    return b"230" in response


async def check_list_command(reader, writer):
    response = await send_command(writer, reader, b"LIST\r\n")
    return b"150" in response or b"125" in response


async def check_ftp_bounce(reader, writer):
    response = await send_command(writer, reader, b"PORT 127,0,0,1,0,80\r\n")
    return b"200" in response


async def check_vulnerable_commands(reader, writer):
    vulnerable_cmds = {
        b"FEAT\r\n": "FTP_FEAT_COMMAND",
        b"SITE EXEC\r\n": "FTP_SITE_EXEC",
        b"ALLO 1\r\n": "FTP_ALLO_COMMAND",
        b"MDTM\r\n": "FTP_MDTM_COMMAND",
        b"STAT\r\n": "FTP_STAT_COMMAND"
    }

    found = []

    for cmd, vuln_id in vulnerable_cmds.items():
        response = await send_command(writer, reader, cmd)
        if response and b"500" not in response and b"502" not in response:
            found.append(vuln_id)

    return found


async def brute_force_login(ip, port, timeout):

    for username, password in COMMON_CREDENTIALS:

        reader, writer = await open_connection(ip, port, timeout)
        if not reader:
            return None

        await reader.read(1024)

        await send_command(writer, reader, f"USER {username}\r\n".encode())
        response = await send_command(writer, reader, f"PASS {password}\r\n".encode())

        writer.close()
        await writer.wait_closed()

        if b"230" in response:
            return username, password

    return None


async def scan(ip, port, service, version, module_config=None, profile="normal"):

    timeout = module_config.get("timeout", DEFAULT_TIMEOUT) if module_config else DEFAULT_TIMEOUT

    findings = {
        "banner": None,
        "anonymous_login": False,
        "directory_listing": False,
        "ftp_bounce": False,
        "brute_force_creds": None,
        "vulnerabilities": []
    }

    reader, writer = await open_connection(ip, port, timeout)
    if not reader:
        return build_result(ip, port, service, version, findings)

    try:
        banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        findings["banner"] = banner.decode(errors="ignore").strip()

        if profile != "stealth":

            findings["anonymous_login"] = await check_anonymous_login(reader, writer)
            if findings["anonymous_login"]:
                findings["vulnerabilities"].append(
                    get_vuln("FTP_ANONYMOUS_LOGIN", exploitability="REMOTE_NO_AUTH")
                )

            findings["directory_listing"] = await check_list_command(reader, writer)
            if findings["directory_listing"]:
                findings["vulnerabilities"].append(
                    get_vuln("FTP_DIRECTORY_LISTING", exploitability="REMOTE_NO_AUTH")
                )

            findings["ftp_bounce"] = await check_ftp_bounce(reader, writer)
            if findings["ftp_bounce"]:
                findings["vulnerabilities"].append(
                    get_vuln("FTP_BOUNCE_ATTACK", exploitability="REMOTE_NO_AUTH")
                )

            vuln_cmds = await check_vulnerable_commands(reader, writer)
            for vuln_id in vuln_cmds:
                findings["vulnerabilities"].append(
                    get_vuln(vuln_id, exploitability="REMOTE_NO_AUTH")
                )

        if profile == "aggressive":
            creds = await brute_force_login(ip, port, timeout)
            if creds:
                findings["brute_force_creds"] = {
                    "username": creds[0],
                    "password": creds[1]
                }
                findings["vulnerabilities"].append(
                    get_vuln("FTP_WEAK_CREDENTIALS", exploitability="REMOTE_AUTH_REQUIRED")
                )

    except Exception:
        pass

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    return build_result(ip, port, service, version, findings)


def build_result(ip, port, service, version, findings):
    return {
        "ip": ip,
        "port": port,
        "service": service,
        "module": "ftp",
        "version": version,
        "timestamp": datetime.now().isoformat(),
        "findings": findings
    }