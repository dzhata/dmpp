import argparse
import json
import logging
import sys
from pathlib import Path

# Core orchestration imports
from modules.core.logger import setup_logging
from modules.core.session_manager import SessionManager
from modules.drivers.discovery.nmap_driver import NmapDriver
from modules.drivers.brute.hydra_driver import HydraDriver
from modules.core.pipeline import Pipeline

# TODO: import other drivers: AuthDriver, SQLMapDriver, WirelessDriver, MetasploitDriver, EmpireDriver


def load_config(path):
    with open(path) as f:
        return json.load(f)


def load_targets(targets_path):
    return [line.strip() for line in Path(targets_path).read_text().splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="Automated Pentest Framework Controller"
    )
    parser.add_argument("-c", "--config", required=True,
                        help="Path to pentest_config.json")
    parser.add_argument("command", choices=["full", "net-scan", "discovery", "brute", "inject", "exploit", "post"],
                        help="Pipeline stage to execute")
    args = parser.parse_args()

    # Load configuration and targets
    config = load_config(args.config)
    targets = load_targets(config.get("targets_file", "config/targets.txt"))

    # Initialize logging
    log_path = config.get("log_file", "results/logs/pipeline.log")
    logger = setup_logging(log_path)
    logger.info(f"Starting command: {args.command}")

    # Initialize shared session manager for cookie reuse
    session_mgr = SessionManager()

    # Build driver instances
    drivers = {
        "discovery": NmapDriver(config, session_mgr, logger),
        "brute": HydraDriver(config, session_mgr, logger),
        # TODO: instantiate other drivers here
    }

    # Initialize pipeline
    pipeline = Pipeline(drivers, config, logger)

    try:
        if args.command == "full":
            pipeline.run_full(targets)
        else:
            pipeline.run_stage(args.command, targets)

    except Exception as e:
        logger.exception("Pipeline execution failed")
        sys.exit(1)

    logger.info("Pipeline completed successfully")


if __name__ == "__main__":
    main()
