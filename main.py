# main.py

import asyncio
import os
import sys
import yaml
import importlib
from datetime import datetime

from core.engine import AsyncEngine
from core.mapper import scan_target
from core.reporter import normalize_result, build_report, save_json_report
from core.html_report import generate_html_report
from core.logger import setup_logger


# ---------------------------------------------------------
# LOAD CONFIG
# ---------------------------------------------------------

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


config = load_config()

GENERAL_CONFIG = config.get("general", {})
MODULE_CONFIG = config.get("modules", {})

MAX_CONCURRENCY = GENERAL_CONFIG.get("threads", 300)
PROFILE = GENERAL_CONFIG.get("profile", "normal")
LOG_LEVEL = GENERAL_CONFIG.get("log_level", "INFO")

logger = setup_logger(LOG_LEVEL)


# ---------------------------------------------------------
# DYNAMIC MODULE LOADER
# ---------------------------------------------------------

def load_modules():
    modules = {}
    modules_path = os.path.join(os.path.dirname(__file__), "modules")

    for file in os.listdir(modules_path):
        if file.endswith(".py") and file != "__init__.py":
            name = file[:-3]
            modules[name] = importlib.import_module(f"modules.{name}")

    return modules


SERVICE_MODULES = load_modules()


# ---------------------------------------------------------
# ASYNC DISPATCHER
# ---------------------------------------------------------

async def dispatch_scan(ip, port, service, version):

    matched_module = None
    module_settings = None

    # Match service name to module
    for name, module in SERVICE_MODULES.items():
        if name in service:
            matched_module = module
            module_settings = MODULE_CONFIG.get(name, {})
            break

    if not matched_module:
        return None

    if not module_settings.get("enabled", False):
        return None

    try:
        result = await matched_module.scan(
            ip=ip,
            port=port,
            service=service,
            version=version,
            module_config=module_settings,
            profile=PROFILE
        )

        if result:
            return normalize_result(result)

    except Exception as e:
        logger.error(f"Module failure {ip}:{port} ({service}) → {e}")

    return None


# ---------------------------------------------------------
# TARGET LOADER
# ---------------------------------------------------------

def load_targets(target_input):

    if target_input.endswith(".txt"):
        with open(target_input, "r") as f:
            return [line.strip() for line in f if line.strip()]

    return [target_input]


# ---------------------------------------------------------
# ASYNC MAIN
# ---------------------------------------------------------

async def async_main():

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target | targets.txt>")
        return

    targets = load_targets(sys.argv[1])

    logger.info(f"Profile: {PROFILE}")
    logger.info(f"Max Concurrency: {MAX_CONCURRENCY}")

    all_scan_jobs = []

    # -------------------------------------------------
    # STEP 1: Async Nmap Enumeration
    # -------------------------------------------------
    for target in targets:
        logger.info(f"Running Nmap on {target}")

        hosts = await scan_target(target)

        for host in hosts:
            ip = host["ip"]

            for port_info in host["ports"]:
                all_scan_jobs.append({
                    "ip": ip,
                    "port": port_info["port"],
                    "service": port_info["service"],
                    "version": port_info["version"],
                })

    logger.info(f"Total service jobs queued: {len(all_scan_jobs)}")

    if not all_scan_jobs:
        logger.warning("No open services detected.")
        return

    # -------------------------------------------------
    # STEP 2: Async Execution Engine
    # -------------------------------------------------
    engine = AsyncEngine(
        max_concurrency=MAX_CONCURRENCY,
        base_rate_delay=0.0,
        adaptive_rate=True,
        enable_metrics=True
    )

    results = await engine.run(all_scan_jobs, dispatch_scan)

    # -------------------------------------------------
    # STEP 3: Reporting
    # -------------------------------------------------
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "profile": PROFILE,
        "concurrency": MAX_CONCURRENCY,
        "engine_metrics": engine.get_metrics()
    }

    final_report = build_report(results, metadata)

    json_file = save_json_report(final_report)
    html_file = generate_html_report(final_report)

    logger.info("========== SCAN COMPLETE ==========")
    logger.info(f"JSON Report: {json_file}")
    logger.info(f"HTML Report: {html_file}")

    logger.info(f"Global Risk: {final_report['global_risk']}")
    logger.info(f"Engine Metrics: {engine.get_metrics()}")


# ---------------------------------------------------------
# ENTRYPOINT
# ---------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(async_main())