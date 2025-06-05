import os
import json
import threading
import glob
from typing import Dict, List, Any
from urllib.parse import urljoin

from modules.core.driver import DriverResult, ParsedResult
from modules.core.logger import setup_logging
from modules.core.session_manager import SessionManager
from modules.drivers.exploitation.metasploit_manager import MetasploitManager, generate_per_exploit_rcs,clean_rc_dir
from modules.drivers.exploitation.auth_driver import DVWAAuthDriver
from modules.core.utils import should_skip_sqlmap_form,safe_filename,get_ip, is_plain_host,update_metasploit_sessions

class Pipeline:
    """
    Orchestrates execution of multiple tool drivers in defined stages,
    tracks intermediate results, and generates a final report.
    """

    STAGE_SEQUENCE = [
        #"discovery",      # Nmap
        #"gobuster",       # Gobuster Driver,
        "auth",           # static creds
        "form_discovery", # HTML form crawl
        "brute",          # brute
        "hydra_http",     # brute HTTP forms
        "auth",           # dynamic creds
        "sqlmap",         # injection
        "exploit",        # Metasploit
        "postexploit"     # Empire
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
        # in Pipeline.run_full(), right after self.run_stage("discovery", …)
        disc = self.results.get("discovery", {})
        for tgt, data in disc.items():
            unique = []
            seen = set()
            for h in data.get("hosts", []):
                if h["ip"] not in seen:
                    seen.add(h["ip"])
                    unique.append(h)
            self.results["discovery"][tgt]["hosts"] = unique

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
        for host, data in self.results.get("gobuster", {}).items():
            for subpath in data.get("paths", []):
                # ensure leading slash, then build a full URL
                suffix = subpath if subpath.startswith("/") else f"/{subpath}"
                url = host if host.startswith("http") else f"http://{host}"
                form_targets.add(f"{url.rstrip('/')}{suffix}")
        # Ensure all form_targets are normalized (scheme and no trailing slash)
        normalized_form_targets = set()
        for ft in form_targets:
            if not ft.startswith("http"):
                ft = f"http://{ft}"
            normalized_form_targets.add(ft.rstrip("/"))
        form_targets = normalized_form_targets

        # 3) Crawl forms on every discovered URL
        self.run_stage("form_discovery", list(form_targets))

        #auth for dvwa
        auth = DVWAAuthDriver("http://127.0.0.1/DVWA", "admin", "password")
        if auth.login():
            session = auth.get_session()
            phpsessid = auth.get_cookie()
            self.logger.info(f"[auth] DVWA login successful: {self.config.get('dvwa_user', 'admin')} (PHPSESSID {phpsessid})")
        else:
            self.logger.warning("[auth] DVWA login failed.")

        dvwa_url = "http://127.0.0.1/DVWA"
        dvwa_session = self.session_mgr.get(dvwa_url.rstrip("/"))
        if not dvwa_session:
            self.logger.warning(f"[pipeline] No DVWA session found for {dvwa_url}")
        else:
            # Find login forms in form discovery results for DVWA
            dvwa_forms = []
            for url, result in self.results.get("form_discovery", {}).items():
                # Normalize URL (strip query, trailing slash)
                norm_url = url.split("?")[0].rstrip("/")
                if norm_url == dvwa_url.rstrip("/"):
                    dvwa_forms.extend(result.get("forms", []))

            if not dvwa_forms:
                self.logger.warning(f"[pipeline] No DVWA login forms discovered at {dvwa_url}")
            else:
                for form in dvwa_forms:
                    self.logger.info(f"[pipeline] Running hydra_http on DVWA login form: {form.get('action')}")
                    # Call hydra_http driver with authenticated session
                    self.run_stage(
                        "hydra_http",
                        [dvwa_url],
                        form=form,
                        userlist=self.config["hydra_userlist"],
                        passlist=self.config["hydra_passlist"],
                        session=dvwa_session
            )
            # Target both SQLi and Blind SQLi modules
            sqli_paths = [
                "/vulnerabilities/sqli/",
                "/vulnerabilities/sqli_blind/"
            ]
            for path in sqli_paths:
                vuln_url = f"{dvwa_url.rstrip('/')}{path}"
                # Optionally, check if a form was discovered for this URL
                forms = []
                for url, result in self.results.get("form_discovery", {}).items():
                    norm_url = url.split("?")[0].rstrip("/")
                    if norm_url == vuln_url.rstrip("/"):
                        forms.extend(result.get("forms", []))
                if not forms:
                    self.logger.warning(f"[pipeline] No forms found for {vuln_url} (SQLMap)")
                else:
                    for form in forms:
                        self.logger.info(f"[pipeline] Running SQLMap on DVWA form: {vuln_url} ({form.get('action')})")
                        self.run_stage(
                            "sqlmap",
                            [vuln_url],
                            forms=[form],          # or form=form, adapt to your driver
                            session=dvwa_session   # pass cookies/session for auth
                        )

       # 4) HydraHttp brute for auth_required but *no* static creds
        for url, result in self.results.get("form_discovery", {}).items():
            forms = result.get("forms", [])
            form_actions = [f.get('action') for f in forms]
            self.logger.info(f"Trying brute on: {url}, forms: {form_actions}")

            # Only brute if URL requires auth and doesn't have static creds
            url_for_auth = url.split("?")[0]  # normalize if needed
            if url_for_auth in auth_req and url_for_auth not in static_creds:
                for form in forms:
                    session = self.session_mgr.get(url_for_auth) if hasattr(self, 'session_mgr') else None
                    self.run_stage(
                        "hydra_http",
                        [url],
                        form=form,
                        userlist=self.config["hydra_userlist"],
                        passlist=self.config["hydra_passlist"],
                        session=session
                    )

                    creds = self.results.get("hydra_http", {}).get(url, {}).get("credentials", [])
                    if creds:
                        user, pw = creds[0]["username"], creds[0]["password"]
                        self.logger.info(f"[hydra_http] Credentials found: {user}:{pw} for {url}")
                        self.config.setdefault("auth_credentials", {})[url_for_auth] = {
                            "login_url":      form.get("action"),
                            "username_field": self.config.get("username_field", "username"),
                            "password_field": self.config.get("password_field", "password"),
                            "username":       user,
                            "password":       pw
                        }
                    else:
                        self.logger.info(f"[hydra_http] No credentials found for {url}")



        # 5) Dynamic auth with discovered creds
        #to_auth_dynamic = [t for t in targets if t in auth_req and t in self.config.get("auth_credentials", {})]
        #if to_auth_dynamic:
        #    self.run_stage("auth", to_auth_dynamic)

        
        
        # 6) SSH brute (unchanged)
        

        # ...
        # Before brute stage:
        brute_targets = [t for t in targets if is_plain_host(t)]
        if brute_targets:
            self.run_stage("brute", brute_targets)


        # --- Feedback block: print Hydra results to console ---
        for target, brute_data in self.results.get("brute", {}).items():
            creds = brute_data.get("credentials", [])
            if creds:
                print(f"[Hydra] Credentials found for {target}:")
                for c in creds:
                    print(f"  {c['username']}:{c['password']}")
            else:
                print(f"[Hydra] No credentials found for {target}.")

        # 7) SQLMap injection on every form
        # In pipeline.py, before appending unique_sqlmap_jobs
        # Deduplicate forms across all discovered URLs
        seen = set()
        unique_sqlmap_jobs = []

        for t, result in self.results.get("form_discovery", {}).items():
            forms = result.get("forms", [])
            for form in forms:
                action = form.get("action") or t
                if not action.startswith(("http://", "https://")):
                    action_url = urljoin(t if t.startswith("http") else f"http://{t}", action)
                else:
                    action_url = action

                # ADD FILTER HERE
                if should_skip_sqlmap_form(action_url, form):
                    self.logger.info(f"[pipeline] Skipping filtered form for SQLMap: {action_url}")
                    continue

                form_key = (action_url, tuple(sorted(form.get("fields", {}).keys())))
                if form_key in seen:
                    continue
                seen.add(form_key)
                unique_sqlmap_jobs.append((action_url, form))



        for action_url, form in unique_sqlmap_jobs:
            try:
                self.run_stage("sqlmap", [action_url], forms=[form])
            except Exception as e:
                # log the error, but DON'T remove from seen—never reschedule!
                self.logger.error(f"SQLMap failed on {action_url}: {e}")


        

        # 8) Exploit (Metasploit)
        rc_dir = self.config.get("metasploit_resource_dir", "modules/drivers/exploitation/msf_scripts")
        output_dir = self.config.get("metasploit_output_dir", "results/raw/metasploit")
        lhost = self.config.get("lhost") or "127.0.0.1"
        targets = list(targets)  # ensure it's a list if set
        clean_rc_dir(rc_dir)
        generate_per_exploit_rcs(targets, lhost, output_dir=rc_dir)
        rc_files = [os.path.join(rc_dir, f) for f in os.listdir(rc_dir) if f.endswith(".rc")]

        # -- Run all Metasploit jobs using the manager --
        msf_manager = MetasploitManager(
            msf_path=self.config.get("metasploit_path", "msfconsole"),
            rc_files=rc_files,
            output_dir=output_dir,
            timeout=self.config.get("msf_timeout", 300),
            logger=self.logger
        )

        # -- Run all exploits (writes output files) --
        msf_manager.run_all()

        # --- Map: { target_ip: [ {session_id, exploit, rc_file, out_file} ] } ---
        detailed_sessions_map = {}

        for rc_file in rc_files:
            exploit_name = os.path.basename(rc_file).split("_")[1]  # crude: 192_168_56_101_samba.rc → samba
            out_file = os.path.join(output_dir, os.path.basename(rc_file) + ".txt")
            sessions = msf_manager.parse_sessions_from_output(out_file)
            for sess in sessions:
                target_ip = sess["rhost"]
                detailed = {
                    "session_id": sess["id"],
                    "exploit": exploit_name,
                    "rc_file": rc_file,
                    "out_file": out_file,
                    "session_type": sess["type"],
                }
                detailed_sessions_map.setdefault(target_ip, []).append(detailed)

        print("[DEBUG] Detailed Metasploit session map:", json.dumps(detailed_sessions_map, indent=2))

        # -- Build simplified map for post-ex stages and session_targets list --
        session_targets = []
        simple_sessions_map = {}
        for t in targets:
            ip = get_ip(t)
            if ip in detailed_sessions_map:
                session_targets.append(t)
                # Keep only session_ids (old format)
                simple_sessions_map[ip] = [entry["session_id"] for entry in detailed_sessions_map[ip]]

        self.logger.info(f"Targets with sessions for post-exploitation: {session_targets}")

        # Save both maps for downstream use (EmpireDriver/DeliveryDriver may want exploit info)
        self.config["metasploit_sessions"] = simple_sessions_map
        self.config["metasploit_session_details"] = detailed_sessions_map

        if session_targets:
            # Pass extra context for post-exploitation if needed
            self.run_stage("postexploit", session_targets)
        else:
            self.logger.warning("Skipping post-exploitation; no sessions found.")


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
