#!/usr/bin/env python3
import os
import json
import sys
from pathlib import Path
from typing import Any

from modules.core.logger           import setup_logging
from modules.core.session_manager  import SessionManager
from modules.core.pipeline         import Pipeline

from modules.drivers.discovery.nmap_driver        import NmapDriver
from modules.drivers.discovery.dirb_driver       import DirbDriver
from modules.drivers.discovery.gobuster_driver  import GobusterDriver
from modules.drivers.exploitation.auth_driver          import AuthDriver
from modules.drivers.discovery.form_discovery     import FormDiscoveryDriver
from modules.drivers.brute.hydra_http_driver      import HydraHttpDriver
from modules.drivers.vuln.sqlmap_driver           import SQLMapDriver
from modules.drivers.brute.hydra_driver           import HydraDriver
from modules.drivers.post_exploit.empire_driver import EmpireDriver

#from modules.drivers.exploitation.metasploit_driver    import MetasploitDriver
#from modules.drivers.post_exploit.empire_driver           import EmpireDriver

CONFIG_DEFAULT_PATH = "config/pentest_config.json"

def load_config(path: str) -> dict:
    """Load and parse the JSON configuration file."""
    with open(path, "r") as f:
        return json.load(f)

def load_targets(path: str) -> list[str]:
    """Read the targets file, one target per non-empty line."""
    text = Path(path).read_text().splitlines()
    return [line.strip() for line in text if line.strip()]

#def build_drivers(config: dict, session_mgr: SessionManager, logger) -> dict[str, Any]:
    """Instantiate all your drivers and return a mapping stage→driver instance."""
    return {
        "discovery":       NmapDriver(config, session_mgr, logger),
        "auth":            AuthDriver(config, session_mgr, logger),
        "form_discovery":  FormDiscoveryDriver(config, session_mgr, logger),
        "hydra_http":      HydraHttpDriver(config, session_mgr, logger),
        "sqlmap":          SQLMapDriver(config, session_mgr, logger),
        "brute":           HydraDriver(config, session_mgr, logger),
        "exploit":         MetasploitDriver(config, session_mgr, logger),
        "post":            EmpireDriver(config, session_mgr, logger),
    }

def interactive_main():
    # 1) Load config
    config_path = input(f"Config file [{CONFIG_DEFAULT_PATH}]: ") or CONFIG_DEFAULT_PATH
    if not os.path.isfile(config_path):
        print(f"Error: config file not found at {config_path}")
        sys.exit(1)
    config = load_config(config_path)

    # 2) Prepare logging, sessions, pipeline
    log_path    = config.get("log_file", "results/logs/pipeline.log")
    logger      = setup_logging(log_path)
    session_mgr = SessionManager()
    drivers = {
        "discovery":     NmapDriver,     # ← class!
        "auth":          AuthDriver,
        "gobuster":GobusterDriver,
        "form_discovery":FormDiscoveryDriver,
        "hydra_http":    HydraHttpDriver,
        "sqlmap":        SQLMapDriver,
        "brute":         HydraDriver,
        "postexploit": EmpireDriver,
        # …other drivers…
    }
    pipeline    = Pipeline(drivers, config, logger,session_mgr)

    # 3) Load targets once
    try:
        targets = load_targets(config["targets_file"])
    except Exception as e:
        logger.error(f"Failed to load targets: {e}")
        sys.exit(1)

    # 4) Main menu loop
    while True:
        print("\n=== Automated Pentest Framework ===")
        print("1 -- Start Scan")
        print("2 -- Show Config")
        print("99 -- Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            logger.info("Launching full pipeline")
            try:
                pipeline.run_full(targets)
                logger.info("Full scan completed successfully")
            except Exception:
                logger.exception("Error during full scan")
        elif choice == "2":
            print("\n--- Current Configuration ---")
            print(json.dumps(config, indent=2))
        elif choice == "99":
            print("Exiting. Goodbye!")
            break
        else:
            print(f"Unknown option '{choice}'. Please enter 1, 2, or 99.")

if __name__ == "__main__":
    interactive_main()
