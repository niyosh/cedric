import subprocess
import xml.etree.ElementTree as ET

NMAP_PATH = "nmap"


def run_nmap(target):
    """
    Run Nmap scan and return raw XML output.
    """
    print(f"[+] Running Nmap scan on {target}...")

    cmd = [NMAP_PATH, "-Pn", "-sV", "-p-", "--open", "-oX", "-", target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if result.returncode != 0:
            print(f"[-] Nmap failed on {target}")
            return None

        return result.stdout

    except subprocess.TimeoutExpired:
        print(f"[-] Nmap timeout on {target}")
        return None


def parse_nmap_xml(xml_data):
    """
    Parse Nmap XML and return structured host/port data.
    """
    hosts = []

    root = ET.fromstring(xml_data)

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

        hosts.append({
            "ip": ip,
            "ports": ports_info
        })

    return hosts


def scan_target(target):
    """
    Full Nmap workflow: run + parse
    Returns structured scan results.
    """
    xml_output = run_nmap(target)
    if not xml_output:
        return []

    return parse_nmap_xml(xml_output)
