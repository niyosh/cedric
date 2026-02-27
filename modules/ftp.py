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

COMMON_USERNAMES = [
    "anonymous", "ftp", "admin", "user",
    "test", "root", "guest", "info"
]

DEFAULT_TIMEOUT = 5


# -----------------------------
# Connection Helpers
# -----------------------------

async def open_connection(ip, port, timeout=DEFAULT_TIMEOUT):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        banner = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        return reader, writer, banner
    except Exception:
        return None, None, None


async def send_command(reader, writer, command, timeout=DEFAULT_TIMEOUT):
    try:
        writer.write(command)
        await writer.drain()
        return await asyncio.wait_for(reader.read(2048), timeout=timeout)
    except Exception:
        return b""


async def close_connection(writer):
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def login(reader, writer, username, password):
    await send_command(reader, writer, f"USER {username}\r\n".encode())
    response = await send_command(reader, writer, f"PASS {password}\r\n".encode())
    return b"230" in response


# -----------------------------
# Checks
# -----------------------------

async def check_anonymous_login(ip, port, timeout):
    reader, writer, _ = await open_connection(ip, port, timeout)
    if not reader:
        return False

    success = await login(reader, writer, "anonymous", "anonymous@")
    await close_connection(writer)
    return success


async def check_directory_listing(ip, port, timeout):
    reader, writer, _ = await open_connection(ip, port, timeout)
    if not reader:
        return False

    success = await login(reader, writer, "anonymous", "anonymous@")
    if not success:
        await close_connection(writer)
        return False

    response = await send_command(reader, writer, b"LIST\r\n")
    await close_connection(writer)

    return b"150" in response or b"125" in response


async def check_ftp_bounce(ip, port, timeout):
    reader, writer, _ = await open_connection(ip, port, timeout)
    if not reader:
        return False

    response = await send_command(writer=writer, reader=reader,
                                  command=b"PORT 127,0,0,1,0,80\r\n")
    await close_connection(writer)
    return b"200" in response


async def check_user_enumeration(ip, port, timeout):
    reader, writer, _ = await open_connection(ip, port, timeout)
    if not reader:
        return []

    valid_users = []

    for user in COMMON_USERNAMES:
        resp = await send_command(
            reader, writer,
            f"USER {user}\r\n".encode()
        )
        if b"331" in resp:
            valid_users.append(user)

    await close_connection(writer)
    return valid_users


async def check_ftps_support(ip, port, timeout):
    reader, writer, _ = await open_connection(ip, port, timeout)
    if not reader:
        return False

    resp = await send_command(reader, writer, b"AUTH TLS\r\n")
    await close_connection(writer)

    return b"234" in resp


async def check_site_exec(ip, port, timeout):
    reader, writer, _ = await open_connection(ip, port, timeout)
    if not reader:
        return False

    resp = await send_command(reader, writer, b"SITE EXEC\r\n")
    await close_connection(writer)

    if resp and b"500" not in resp and b"502" not in resp:
        return True

    return False


async def brute_force_login(ip, port, timeout):
    for username, password in COMMON_CREDENTIALS:
        reader, writer, _ = await open_connection(ip, port, timeout)
        if not reader:
            return None

        success = await login(reader, writer, username, password)
        await close_connection(writer)

        if success:
            return username, password

    return None


# -----------------------------
# Main Scan
# -----------------------------

async def scan(ip, port, service, version,
               module_config=None, profile="normal"):

    timeout = module_config.get(
        "timeout", DEFAULT_TIMEOUT
    ) if module_config else DEFAULT_TIMEOUT

    findings = {
        "banner": None,
        "anonymous_login": False,
        "directory_listing": False,
        "ftp_bounce": False,
        "user_enumeration": [],
        "ftps_support": False,
        "site_exec_supported": False,
        "brute_force_creds": None,
        "vulnerabilities": []
    }

    # Grab banner once
    reader, writer, banner = await open_connection(ip, port, timeout)
    if not reader:
        return build_result(ip, port, service, version, findings)

    findings["banner"] = banner.decode(errors="ignore").strip()
    await close_connection(writer)

    # ---------------- NORMAL PROFILE ----------------
    if profile != "stealth":

        if await check_anonymous_login(ip, port, timeout):
            findings["anonymous_login"] = True
            findings["vulnerabilities"].append(
                get_vuln("FTP_ANONYMOUS_LOGIN",
                         exploitability="REMOTE_NO_AUTH")
            )

        if await check_directory_listing(ip, port, timeout):
            findings["directory_listing"] = True
            findings["vulnerabilities"].append(
                get_vuln("FTP_DIRECTORY_LISTING",
                         exploitability="REMOTE_NO_AUTH")
            )

        if await check_ftp_bounce(ip, port, timeout):
            findings["ftp_bounce"] = True
            findings["vulnerabilities"].append(
                get_vuln("FTP_BOUNCE_ATTACK",
                         exploitability="REMOTE_NO_AUTH")
            )

        users = await check_user_enumeration(ip, port, timeout)
        if users:
            findings["user_enumeration"] = users
            findings["vulnerabilities"].append(
                get_vuln("FTP_USER_ENUMERATION",
                         exploitability="REMOTE_NO_AUTH")
            )

        if not await check_ftps_support(ip, port, timeout):
            findings["vulnerabilities"].append(
                get_vuln("FTP_NO_ENCRYPTION",
                         exploitability="REMOTE_NO_AUTH")
            )
        else:
            findings["ftps_support"] = True

        if await check_site_exec(ip, port, timeout):
            findings["site_exec_supported"] = True
            findings["vulnerabilities"].append(
                get_vuln("FTP_SITE_EXEC",
                         exploitability="REMOTE_NO_AUTH")
            )

    # ---------------- AGGRESSIVE PROFILE ----------------
    if profile == "aggressive":

        creds = await brute_force_login(ip, port, timeout)
        if creds:
            findings["brute_force_creds"] = {
                "username": creds[0],
                "password": creds[1]
            }
            findings["vulnerabilities"].append(
                get_vuln("FTP_WEAK_CREDENTIALS",
                         exploitability="REMOTE_AUTH_REQUIRED")
            )

    return build_result(ip, port, service, version, findings)


# -----------------------------
# Result Builder
# -----------------------------

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