import os
import json
from typing import Dict, List, Any

from modules.core.driver import DriverResult, ParsedResult
from modules.core.logger import setup_logging
from modules.core.session_manager import SessionManager


class Pipeline:
    """
    Orchestrates execution of multiple tool drivers in defined stages,
    tracks intermediate results, and generates a final report.
    """

    STAGE_SEQUENCE = [
        "discovery",      # Nmap
        "auth",           # Python script,will run only if cfg says so
        "form_discovery", # FormDiscovery
        "brute",          # Hydra\
        "inject",         # SQLMap
        "exploit",        # Metasploit
        "post"            # Empire
    ]

    def __init__(
        self,
        drivers: Dict[str, Any],
        config: Dict[str, Any],
        logger
    ):
        self.drivers = drivers
        self.config = config
        self.logger = logger
        self.results: Dict[str, Dict[str, Any]] = {}

    def run_stage(self, stage: str, targets: List[str]) -> None:
        """
        Run a single stage across all targets. Supports composite commands like 'net-scan'.
        """
        # Composite command handling
        if stage == "net-scan":
            for sub in ["discovery", "inject", "brute"]:
                self.run_stage(sub, targets)
            return

        driver = self.drivers.get(stage)
        if not driver:
            self.logger.warning(f"No driver for stage '{stage}', skipping.")
            return

        stage_results: Dict[str, Any] = {}
        for target in targets:
            self.logger.info(f"[{stage}] Starting target {target}")
            try:
                # Execute tool
                drv_result: DriverResult = driver.run(
                    target,
                    timeout=self.config.get("scan_timeout_sec")
                )
                # Parse output
                parsed: ParsedResult = driver.parse(drv_result.raw_output)
                stage_results[target] = parsed.data
                self.logger.debug(f"[{stage}] Parsed data for {target}: {parsed.data}")
            except Exception as e:
                self.logger.error(f"[{stage}] Failed on {target}: {e}")

        self.results[stage] = stage_results

    def run_full(self, targets: List[str]) -> None:
        """
        Execute the entire pipeline in order, then generate the final report.
        """
        # Determine active stages
        stages = list(self.STAGE_SEQUENCE)
        if not self.config.get("enable_wireless", True) and "brute" in stages:
            # Example: skip wireless if later added
            pass
        if not self.config.get("enable_post", True):
            for s in ["exploit", "post"]:
                if s in stages:
                    stages.remove(s)

        # Run each stage
        for stage in stages:
            self.run_stage(stage, targets)

        # Generate report
        report_path = self.config.get("report_path", "results/final_report.json")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        try:
            from modules.drivers.reporting.report_gen import ReportGenerator
            # Instantiate with logger and config, not results
            rg = ReportGenerator(self.logger, self.config)

            # Push each stage’s parsed data into the report generator
            for stage_name, stage_data in self.results.items():
                rg.add_tool_results(stage_name, stage_data)

            # (Optional) If you have any per-target metadata in config:
            for target, meta in self.config.get("target_meta", {}).items():
                rg.add_target_metadata(target, meta)

            # Now generate the unified report
            rg.generate(report_path)
            self.logger.info(f"Final report written to {report_path}")
        except ImportError:
            self.logger.warning("ReportGenerator not found; skipping final report generation.")
