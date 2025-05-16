import os
import subprocess
import logging
import xml.etree.ElementTree as ET

from tenacity import retry, stop_after_attempt, wait_fixed

from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult


class NmapDriver(BaseToolDriver):
    """
    Driver for Nmap discovery scans. Runs scans with service/version detection,
    OS detection, and common script scans, then parses XML output.
    """
    name = "nmap"

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)
        self.binary = config.get("nmap_binary", "nmap")
        self.args = config.get("nmap_args", ["-sV", "-O", "-A", "-Pn"])
        # Directory to store raw XML outputs
        self.output_dir = config.get("nmap_output_dir", "results/raw/nmap")
        os.makedirs(self.output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, timeout: int = 300) -> DriverResult:
        """
        Run an Nmap scan against the given target.

        :param target: Hostname or IP to scan
        :param timeout: Max seconds to wait for nmap process
        :return: DriverResult containing path to raw XML output
        """
        xml_filename = f"{target.replace(':', '_')}.xml"
        xml_path = os.path.join(self.output_dir, xml_filename)

        cmd = [self.binary, *self.args, "-oX", xml_path, target]
        self.logger.info(f"[NmapDriver] Running scan: {' '.join(cmd)}", extra={"target": target})

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )

        if proc.returncode not in (0, 1):
            # Nmap return code 1 = no hosts up (but XML may still be written)
            err = proc.stderr.decode(errors="ignore")
            self.logger.error(f"[NmapDriver] Scan failed: {err}", extra={"target": target})
            raise RuntimeError(f"Nmap scan error (code {proc.returncode})")

        self.logger.debug(f"[NmapDriver] Scan completed, XML at: {xml_path}", extra={"target": target})
        return DriverResult(raw_output=xml_path)

    def parse(self, raw_output_path: str) -> ParsedResult:
        """
        Parse Nmap XML and extract hosts, ports, services, OS details,
        *plus* NSE script outputs and explicit vulnerabilities.
        """
        import re
        tree = ET.parse(raw_output_path)
        root = tree.getroot()
        hosts = []

        for host in root.findall("host"):
            state_elem = host.find("status")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else None

            host_info = {
                "ip": ip,
                "status": state,
                "ports": [],
                "os": {},
            }

            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    portid = port.get("portid")
                    proto = port.get("protocol")
                    state_el = port.find("state")
                    port_state = state_el.get("state") if state_el is not None else "unknown"

                    svc = port.find("service")
                    svc_name = svc.get("name") if svc is not None else None
                    product  = svc.get("product") if svc is not None else None
                    version  = svc.get("version") if svc is not None else None
                    extrainfo= svc.get("extrainfo") if svc is not None else None

                    # collect scripts and vulnerabilities
                    scripts = []
                    vulns   = []
                    for script in port.findall("script"):
                        sid    = script.get("id")
                        output = script.get("output","")
                        scripts.append({"id": sid, "output": output})

                        # auto-extract CVEs from vulners
                        if sid == "vulners":
                            for cve in re.findall(r"(CVE-\d{4}-\d{4,7})", output):
                                vulns.append(cve)
                        # DH params vulnerability
                        if sid == "ssl-dh-params" and "VULNERABLE" in output:
                            vulns.append("Anonymous DH vulnerability")

                    host_info["ports"].append({
                        "port": int(portid) if portid else None,
                        "protocol": proto,
                        "state": port_state,
                        "service": svc_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "scripts": scripts,
                        "vulnerabilities": vulns
                    })

            # OS detection (unchanged)
            os_elem = host.find("os")
            if os_elem is not None:
                matches = os_elem.findall("osmatch")
                if matches:
                    best = matches[0]
                    osclass = best.find("osclass")
                    host_info["os"] = {
                        "name": best.get("name"),
                        "accuracy": best.get("accuracy"),
                        "osfamily": osclass.get("osfamily") if osclass is not None else None,
                    }

            hosts.append(host_info)

        return ParsedResult(data={"hosts": hosts})

