# core/mapper.py

import asyncio
import xml.etree.ElementTree as ET
import shutil
import os
from datetime import datetime
import yaml


# -------------------------
# LOAD CONFIG
# -------------------------

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


config = load_config()

NMAP_CONFIG = config["general"].get("nmap", {})
GLOBAL_PROFILE = config["general"].get("profile", "normal")

NMAP_PATH = NMAP_CONFIG.get("path")
NMAP_TIMEOUT = NMAP_CONFIG.get("timeout", 600)
SAVE_RAW_XML = NMAP_CONFIG.get("save_raw_xml", False)


# Auto-detect Nmap if not set
if not NMAP_PATH:
    NMAP_PATH = shutil.which("nmap")

if not NMAP_PATH:
    raise Exception("Nmap binary not found. Configure in config.yaml")


# -------------------------
# BUILD NMAP COMMAND
# -------------------------

def build_nmap_command(target):

    if GLOBAL_PROFILE == "stealth":
        args = ["-sS", "-T2", "-Pn", "--open"]

    elif GLOBAL_PROFILE == "aggressive":
        args = ["-sV", "-sC", "-O", "-Pn", "--open"]

    else:
        args = ["-sV", "-Pn", "--open"]

    return [NMAP_PATH, *args, "-oX", "-", target]


# -------------------------
# ASYNC RUN NMAP
# -------------------------

async def run_nmap(target):

    cmd = build_nmap_command(target)

    print(f"[+] Running Nmap ({GLOBAL_PROFILE}) on {target}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=NMAP_TIMEOUT
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            print(f"[-] Nmap timeout on {target}")
            return None

        if process.returncode != 0:
            print(f"[-] Nmap failed on {target}")
            print(stderr.decode().strip())
            return None

        xml_output = stdout.decode()

        if SAVE_RAW_XML:
            save_raw_xml(target, xml_output)

        return xml_output

    except Exception as e:
        print(f"[-] Nmap execution error: {e}")
        return None


# -------------------------
# SAVE RAW XML
# -------------------------

def save_raw_xml(target, xml_data):

    os.makedirs("reports/raw_nmap", exist_ok=True)

    filename = f"reports/raw_nmap/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(xml_data)

    print(f"[+] Raw Nmap XML saved: {filename}")


# -------------------------
# PARSE XML
# -------------------------

def parse_nmap_xml(xml_data):

    hosts = []

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        print("[-] Failed to parse Nmap XML output")
        return []

    for host in root.findall("host"):

        address = host.find("address")
        if address is None:
            continue

        ip = address.attrib.get("addr")

        ports_element = host.find("ports")
        if ports_element is None:
            continue

        ports_info = []

        for port in ports_element.findall("port"):

            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            portid = int(port.attrib.get("portid"))

            service_elem = port.find("service")

            service_name = ""
            service_version = ""

            if service_elem is not None:
                service_name = service_elem.attrib.get("name", "").lower()
                service_version = service_elem.attrib.get("version", "")

            ports_info.append({
                "port": portid,
                "service": service_name,
                "version": service_version
            })

        if ports_info:
            hosts.append({
                "ip": ip,
                "ports": ports_info
            })

    return hosts


# -------------------------
# FULL WORKFLOW
# -------------------------

async def scan_target(target):

    xml_output = await run_nmap(target)

    if not xml_output:
        return []

    return parse_nmap_xml(xml_output)