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
        "gobuster", # Gobuster Driver,
        "auth",           # static creds
        "form_discovery", # HTML form crawl
        "hydra_http",     # brute HTTP forms
        "auth",           # dynamic creds
        "sqlmap",         # injection
        "brute",          # SSH brute
        "exploit",        # Metasploit
        "post"            # Empire
    ]

    def __init__(
        self,
        drivers: Dict[str, Any],
        config: Dict[str, Any],
        logger,
        session_mgr, 
    ):
        self.drivers = drivers
        self.config = config
        self.logger = logger
        self.session_mgr = session_mgr
        self.results: Dict[str, Dict[str, Any]] = {}

    def run_stage(self, stage: str, targets: List[str], **kwargs) -> None:
        """
        Run a single stage across all targets. Composite commands 
        like 'net-scan' are handled here too.
        """
        # Composite command support
        if stage == "net-scan":
            for sub in ("discovery", "inject", "brute"):
                self.run_stage(sub, targets)
            return

        driver_cls = self.drivers.get(stage)
        if not driver_cls:
            self.logger.warning(f"No driver for stage '{stage}', skipping.")
            return

        # Instantiate once per stage, passing in the shared session_mgr for cookies
        driver = driver_cls(self.config, self.session_mgr, self.logger)

        stage_results: Dict[str, Any] = {}
        for target in targets:
            self.logger.info(f"[{stage}] Starting target {target}")
            try:
                # run() may accept extra kwargs like forms, userlist, etc.
                drv_result: DriverResult = driver.run(
                    target,
                    **kwargs,
                    timeout=self.config.get("scan_timeout_sec")
                )
                parsed: ParsedResult = driver.parse(drv_result.raw_output)
                stage_results[target] = parsed.data
                self.logger.debug(f"[{stage}] Parsed data for {target}: {parsed.data}")

            except Exception as e:
                self.logger.error(f"[{stage}] Failed on {target}: {e}")

        self.results[stage] = stage_results


    def run_full(self, targets: List[str]) -> None:
        """
        Execute the pipeline in a specific order that handles static creds,
        dynamic brute, form crawl, SQLMap, and then the rest.
        """
        # 1) Nmap discovery
        self.run_stage("discovery", targets)
        # 1.5) Dirb discovery
        self.run_stage("gobuster", targets)
        # 2) Static auth (only for those in auth_required & with creds)
        auth_req = set(self.config.get("auth_required", []))
        static_creds = set(self.config.get("auth_credentials", {}).keys())
        to_auth_static = [t for t in targets if t in auth_req and t in static_creds]
        if to_auth_static:
            self.run_stage("auth", to_auth_static)

        # 2) Build full list of URLs for form crawling:
        form_targets = set()
        # a) include the original targets (will be normalized by the driver)
        form_targets.update(targets)
        # b) for each host, append each dir path Gobuster found
        for host, data in self.results.get("dirb", {}).items():
            for subpath in data.get("paths", []):
                # ensure leading slash, then build a full URL
                suffix = subpath if subpath.startswith("/") else f"/{subpath}"
                url = host if host.startswith("http") else f"http://{host}"
                form_targets.add(f"{url.rstrip('/')}{suffix}")
    
        # 3) Crawl forms on every discovered URL
        self.run_stage("form_discovery", list(form_targets))


        # 4) HydraHttp brute for auth_required but *no* static creds
        to_brute_http = [t for t in targets if t in auth_req and t not in static_creds]
        for t in to_brute_http:
            forms = self.results.get("form_discovery", {})\
                                .get(t, {})\
                                .get("forms", [])
            for form in forms:
                # userlist/passlist from config
                self.run_stage(
                    "hydra_http",
                    [t],
                    form=form,
                    userlist=self.config["hydra_userlist"],
                    passlist=self.config["hydra_passlist"]
                )
            # if any creds found, pick first and inject into config for second auth pass
            creds = self.results.get("hydra_http", {}).get(t, {}).get("credentials", [])
            if creds:
                user, pw = creds[0]["username"], creds[0]["password"]
                self.config.setdefault("auth_credentials", {})[t] = {
                    "login_url":       form["action"],
                    "username_field":  self.config.get("username_field","username"),
                    "password_field":  self.config.get("password_field","password"),
                    "username":        user,
                    "password":        pw
                }

        # 5) Dynamic auth with discovered creds
        to_auth_dynamic = [t for t in targets if t in auth_req and t in self.config.get("auth_credentials", {})]
        if to_auth_dynamic:
            self.run_stage("auth", to_auth_dynamic)

        # 6) SQLMap injection on every form
        for t in targets:
            forms = self.results.get("form_discovery", {})\
                                .get(t, {})\
                                .get("forms", [])
            self.run_stage("sqlmap", [t], forms=forms)

        # 7) SSH brute (unchanged)
        self.run_stage("brute", targets)

        # 8) Exploit and Post
        for stage in ("exploit","post"):
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
