import asyncio
import ssl
import base64
from datetime import datetime
from core.scoring import get_vuln

DEFAULT_TIMEOUT = 6
MAX_RETRIES = 2


# ==========================================================
# CONNECTION
# ==========================================================

async def open_connection(ip, port, timeout, use_ssl=False):
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
        return reader, writer
    except Exception:
        return None, None


async def safe_close(writer):
    if not writer:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def safe_read(reader):
    lines = []
    while True:
        line = await reader.readline()
        if not line:
            break

        decoded = line.decode(errors="ignore").strip()
        lines.append(decoded)

        if len(decoded) >= 4 and decoded[3] == " ":
            break

    return "\n".join(lines)


async def safe_send(writer, cmd):
    writer.write((cmd + "\r\n").encode())
    await writer.drain()


# ==========================================================
# STARTTLS
# ==========================================================

async def upgrade_starttls(reader, writer):
    try:
        await safe_send(writer, "STARTTLS")
        resp = await safe_read(reader)

        if not resp.startswith("220"):
            return False, None

        ssl_ctx = ssl.create_default_context()
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_event_loop()

        new_transport = await loop.start_tls(
            transport,
            protocol,
            ssl_ctx,
            server_hostname=None
        )

        reader._transport = new_transport
        writer._transport = new_transport

        cert = new_transport.get_extra_info("peercert")
        return True, cert

    except Exception:
        return False, None


def analyze_certificate(cert):
    issues = []
    if not cert:
        return issues

    if not cert.get("issuer"):
        issues.append("Missing issuer")

    return issues


# ==========================================================
# AUTH
# ==========================================================

async def test_auth_login(reader, writer, username, password):
    try:
        await safe_send(writer, "AUTH LOGIN")
        await safe_read(reader)

        await safe_send(writer, base64.b64encode(username.encode()).decode())
        await safe_read(reader)

        await safe_send(writer, base64.b64encode(password.encode()).decode())
        resp = await safe_read(reader)

        return resp.startswith("235")
    except Exception:
        return False


async def brute_force_auth(reader, writer, userlist, passlist):
    for user in userlist:
        for pwd in passlist:
            if await test_auth_login(reader, writer, user, pwd):
                return [(user, pwd)]
    return []


# ==========================================================
# USER ENUMERATION
# ==========================================================

async def enumerate_users(reader, writer, userlist):
    found = []
    for user in userlist:
        await safe_send(writer, f"VRFY {user}")
        resp = await safe_read(reader)
        if resp.startswith("250"):
            found.append(user)
    return found


# ==========================================================
# RELAY
# ==========================================================

async def send_mail(reader, writer, mail_from, rcpt_to, body):
    try:
        await safe_send(writer, f"MAIL FROM:<{mail_from}>")
        await safe_read(reader)

        await safe_send(writer, f"RCPT TO:<{rcpt_to}>")
        rcpt_resp = await safe_read(reader)

        if not rcpt_resp.startswith("250"):
            return False

        await safe_send(writer, "DATA")
        await safe_read(reader)

        await safe_send(writer, body + "\r\n.")
        final = await safe_read(reader)

        return final.startswith("250")
    except Exception:
        return False


# ==========================================================
# MAIN SCAN
# ==========================================================

async def scan(ip, port, service, version, module_config=None, profile="normal"):

    timeout = module_config.get("timeout", DEFAULT_TIMEOUT) if module_config else DEFAULT_TIMEOUT
    exploit_mode = module_config.get("exploit_mode", False) if module_config else False

    findings = {
        "banner": None,
        "capabilities": [],
        "starttls_supported": False,
        "certificate_issues": [],
        "auth_methods": [],
        "valid_credentials": [],
        "enumerated_users": [],
        "relay_success": False,
        "vulnerabilities": []
    }

    use_ssl = True if port == 465 else False

    for _ in range(MAX_RETRIES):

        reader, writer = await open_connection(ip, port, timeout, use_ssl)
        if not reader:
            continue

        try:
            banner = await safe_read(reader)
            findings["banner"] = banner

            if banner:
                findings["vulnerabilities"].append(
                    get_vuln("SMTP_BANNER_DISCLOSED", exploitability="REMOTE_NO_AUTH")
                )

            await safe_send(writer, "EHLO scanner.local")
            ehlo = await safe_read(reader)

            caps = []
            for line in ehlo.splitlines():
                if line.startswith("250-") or line.startswith("250 "):
                    caps.append(line[4:].strip())

            findings["capabilities"] = caps

            if caps:
                findings["vulnerabilities"].append(
                    get_vuln("SMTP_EHLO_CAPABILITIES_DISCLOSED", exploitability="REMOTE_NO_AUTH")
                )

            # STARTTLS
            if "STARTTLS" in [c.upper() for c in caps]:
                findings["starttls_supported"] = True
                findings["vulnerabilities"].append(
                    get_vuln("SMTP_STARTTLS_SUPPORTED", exploitability="REMOTE_NO_AUTH")
                )

                success, cert = await upgrade_starttls(reader, writer)

                if success:
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_STARTTLS_NEGOTIATED", exploitability="REMOTE_NO_AUTH")
                    )

                    issues = analyze_certificate(cert)
                    if issues:
                        findings["certificate_issues"] = issues
                        findings["vulnerabilities"].append(
                            get_vuln("SMTP_INVALID_CERTIFICATE", exploitability="REMOTE_NO_AUTH")
                        )
                else:
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_STARTTLS_FAILED", exploitability="REMOTE_NO_AUTH")
                    )

            # AUTH detection
            for cap in caps:
                if cap.upper().startswith("AUTH"):
                    findings["auth_methods"] = cap.split()[1:]
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_AUTH_MECHANISMS_DISCLOSED", exploitability="REMOTE_NO_AUTH")
                    )

            # Enumeration
            if module_config and module_config.get("userlist"):
                users = await enumerate_users(reader, writer, module_config["userlist"])
                findings["enumerated_users"] = users
                if users:
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_VRFY_ENUM", exploitability="REMOTE_NO_AUTH")
                    )
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_VALID_USERS_ENUMERATED", exploitability="REMOTE_NO_AUTH")
                    )

            # Brute force
            if exploit_mode and module_config.get("userlist") and module_config.get("passlist"):
                creds = await brute_force_auth(reader, writer,
                                               module_config["userlist"],
                                               module_config["passlist"])
                if creds:
                    findings["valid_credentials"] = creds
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_BLANK_AUTH", exploitability="REMOTE_NO_AUTH")
                    )

            # Relay test
            if exploit_mode and module_config.get("relay_from") and module_config.get("relay_to"):
                findings["vulnerabilities"].append(
                    get_vuln("SMTP_RELAY_TEST_PERFORMED", exploitability="REMOTE_NO_AUTH")
                )

                success = await send_mail(
                    reader,
                    writer,
                    module_config["relay_from"],
                    module_config["relay_to"],
                    module_config.get("relay_body", "Test Mail")
                )

                if success:
                    findings["relay_success"] = True
                    findings["vulnerabilities"].append(
                        get_vuln("SMTP_OPEN_RELAY", exploitability="REMOTE_NO_AUTH")
                    )

            break

        except Exception:
            continue

        finally:
            await safe_close(writer)

    return {
        "ip": ip,
        "port": port,
        "service": service,
        "module": "smtp",
        "version": version,
        "timestamp": datetime.utcnow().isoformat(),
        "findings": findings
    }