# main.py

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.mapper import scan_target
import ftp
import ssh
import web

SERVICE_MODULE_MAP = {
    "ftp": ftp,
    "ssh": ssh,
    "http": web,
    "https": web,
}

THREADS = 10


def dispatch_scan(ip, port, service, version):
    module = SERVICE_MODULE_MAP.get(service)

    if not module:
        for svc, mod in SERVICE_MODULE_MAP.items():
            if svc in service:
                module = mod
                break

    if module and hasattr(module, "scan"):
        print(f"[+] Dispatching {module.__name__} on {ip}:{port}")
        return module.scan(ip, port, service, version)

    print(f"[!] No module found for {service} on {ip}:{port}")
    return None


def load_targets(target_input):
    if target_input.endswith(".txt"):
        with open(target_input, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return [target_input]


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)

    targets = load_targets(sys.argv[1])

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_map = {}

        for target in targets:
            hosts = scan_target(target)

            for host in hosts:
                ip = host["ip"]

                for port_info in host["ports"]:
                    future = executor.submit(
                        dispatch_scan,
                        ip,
                        port_info["port"],
                        port_info["service"],
                        port_info["version"]
                    )
                    future_map[future] = (ip, port_info["port"])

        for future in as_completed(future_map):
            ip, port = future_map[future]
            try:
                future.result()
                print(f"[+] Completed module scan for {ip}:{port}")
            except Exception as e:
                print(f"[-] Error scanning {ip}:{port} → {e}")


if __name__ == "__main__":
    main()
