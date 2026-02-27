# modules/smtp.py

import asyncio
from datetime import datetime
from core.scoring import get_vuln


async def open_connection(ip, port, timeout=5):
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
    except Exception:
        return None, None


async def read_response(reader):
    try:
        data = await reader.read(1024)
        return data.decode(errors="ignore")
    except Exception:
        return ""


async def send_command(writer, command):
    writer.write((command + "\r\n").encode())
    await writer.drain()


async def scan(ip, port, service, version, module_config=None, profile="normal"):

    timeout = module_config.get("timeout", 5) if module_config else 5

    findings = {
        "banner": None,
        "vrfy_enabled": False,
        "open_relay": False,
        "vulnerabilities": []
    }

    reader, writer = await open_connection(ip, port, timeout)

    if not reader:
        return build_result(ip, port, service, version, findings)

    try:
        findings["banner"] = await read_response(reader)

        if profile != "stealth":

            # VRFY check
            await send_command(writer, "VRFY root")
            response = await read_response(reader)

            if response.startswith("250"):
                findings["vrfy_enabled"] = True
                findings["vulnerabilities"].append(
                    get_vuln("SMTP_VRFY_ENUM", exploitability="REMOTE_NO_AUTH")
                )

            # Open relay test
            await send_command(writer, "HELO test.com")
            await read_response(reader)

            await send_command(writer, "MAIL FROM:<a@test.com>")
            await read_response(reader)

            await send_command(writer, "RCPT TO:<b@test.com>")
            relay_response = await read_response(reader)

            if relay_response.startswith("250"):
                findings["open_relay"] = True
                findings["vulnerabilities"].append(
                    get_vuln("SMTP_OPEN_RELAY", exploitability="REMOTE_NO_AUTH")
                )

    except Exception:
        pass

    writer.close()
    await writer.wait_closed()

    return build_result(ip, port, service, version, findings)


def build_result(ip, port, service, version, findings):
    return {
        "ip": ip,
        "port": port,
        "service": service,
        "module": "smtp",
        "version": version,
        "timestamp": datetime.now().isoformat(),
        "findings": findings
    }