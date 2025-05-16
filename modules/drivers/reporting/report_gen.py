import json
import os
from datetime import datetime
from typing import Dict, Any, Callable

# Analyzer registry for tool-specific analysis functions\N_ANALYZERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
_ANALYZERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}

def register_analyzer(tool_name: str):
    """
    Decorator to register a tool-specific analyzer.
    Analyzer functions receive the tool's data ({target: data}) and
    return a dict {target: {"threats": [...], "severity": <int>}}.
    """
    def decorator(fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
        _ANALYZERS[tool_name] = fn
        return fn
    return decorator


class ReportGenerator:
    """
    Aggregates findings from multiple tools into a unified report structure,
    applies registered analysis functions, and emits a JSON report.
    """

    def __init__(self, logger, config: Dict[str, Any] = None):
        self.logger = logger
        self.config = config or {}
        # Raw findings: tool -> target -> data
        self.findings: Dict[str, Dict[str, Any]] = {}
        # Metadata: tool -> target -> {scanned_at, duration, ...}
        self.meta: Dict[str, Dict[str, Dict[str, Any]]] = {}
        # Per-target metadata (labels, asset owner, etc.)
        self.target_meta: Dict[str, Dict[str, Any]] = {}
        # Timestamp when the report generation started
        self.generated_at = datetime.utcnow().isoformat() + "Z"

    def add_tool_results(
        self,
        tool: str,
        results: Dict[str, Any],
        meta: Dict[str, Dict[str, Any]] = None
    ):
        """
        Store parsed results and optional metadata for a given tool.

        :param tool: Tool identifier (e.g., 'nmap', 'hydra')
        :param results: Mapping of target -> parsed result dict
        :param meta: Mapping of target -> metadata (e.g., scanned_at, duration)
        """
        self.findings[tool] = results
        if meta:
            self.meta[tool] = meta

    def add_target_metadata(self, target: str, metadata: Dict[str, Any]):
        """
        Attach additional context to a target (labels, owner info, etc.).
        """
        self.target_meta[target] = metadata

    def generate(self, output_path: str):
        """
        Build the final JSON report and write it to disk.

        Structure:
        {
          "report_metadata": {generated_at, config},
          "summary": { ... },
          "targets": {
             <target>: {
               "metadata": {...},
               <tool>: {scanned_at, duration, ...tool data...},
               "analysis": { "by_tool": {...}, "combined_severity": <int> }
             }
          }
        }
        """
        report: Dict[str, Any] = {
            "report_metadata": {
                "generated_at": self.generated_at,
                "config": self.config
            },
            "summary": {},
            "targets": {}
        }

        # Determine all targets across findings and metadata
        all_targets = set(self.target_meta.keys())
        for tool_results in self.findings.values():
            all_targets.update(tool_results.keys())

        # Build per-target entries
        for target in all_targets:
            entry: Dict[str, Any] = {}
            # Include target-level metadata
            if target in self.target_meta:
                entry["metadata"] = self.target_meta[target]

            # Include each tool's results
            for tool, results in self.findings.items():
                if target in results:
                    block: Dict[str, Any] = {}
                    # Attach scanning metadata
                    tool_meta = self.meta.get(tool, {}).get(target, {})
                    if "scanned_at" in tool_meta:
                        block["scanned_at"] = tool_meta["scanned_at"]
                    if "duration" in tool_meta:
                        block["duration"] = tool_meta["duration"]
                    # Merge the parsed data
                    block.update(results[target])
                    entry[tool] = block

            # Run analysis hooks for each tool
            analysis_by_tool: Dict[str, Any] = {}
            severities = []
            for tool, analyzer in _ANALYZERS.items():
                if tool in self.findings:
                    tool_data = self.findings.get(tool, {})
                    tool_analysis = analyzer(tool_data).get(target, {})
                    analysis_by_tool[tool] = tool_analysis
                    if "severity" in tool_analysis:
                        severities.append(tool_analysis["severity"])

            entry["analysis"] = {
                "by_tool": analysis_by_tool,
                "combined_severity": max(severities) if severities else 0
            }

            report["targets"][target] = entry

        # Build global summary
        threshold = self.config.get("critical_threshold", 7)
        critical_hosts = [
            t for t, data in report["targets"].items()
            if data["analysis"]["combined_severity"] >= threshold
        ]
        report["summary"] = {
            "total_targets": len(all_targets),
            "critical_threshold": threshold,
            "critical_hosts": critical_hosts,
            "critical_count": len(critical_hosts)
        }

        # Write JSON to disk
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"[ReportGenerator] Final report saved to {output_path}")
        except Exception as e:
            self.logger.error(f"[ReportGenerator] Failed to save report: {e}")
            raise


@register_analyzer("nmap")
def analyze_nmap(nmap_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Analyze Nmap results using NSE script outputs, explicit CVE lookup,
    and OS fingerprinting. Returns per-target {'threats': [...], 'severity': int}.
    """
    analysis = {}

    for target, payload in nmap_data.items():
        threats = []
        severity = 0.0
        # payload["hosts"] is a list; we’ll analyze each host block
        for host_info in payload.get("hosts", []):
            # 1) OS‐based risks
            osinfo = host_info.get("os", {})
            os_name = osinfo.get("name", "").lower()
            if "windows" in os_name:
                threats.append("Windows host detected; ensure latest patches are applied")
                severity += 2
            elif "linux" in os_name:
                # generally lower risk, but still note kernel versions
                threats.append(f"Linux host ({osinfo.get('name')}); verify kernel CVEs")
                severity += 1

            # 2) Service/port heuristics + script outputs
            for p in host_info.get("ports", []):
                port    = p.get("port")
                svc     = (p.get("service") or "").lower()
                scripts = p.get("scripts", [])

                # a) Standard heuristics
                if port == 22 and "ssh" in svc:
                    threats.append("SSH exposed; brute‐force risk")
                    severity += 3
                if port in (80, 443) and svc in ("http", "https"):
                    threats.append("Web server exposed; check for common web vulnerabilities")
                    severity += 2
                if port == 3389:
                    threats.append("RDP exposed; high remote code execution risk")
                    severity += 5

                # b) Process each NSE script result
                for s in scripts:
                    sid     = s.get("id")
                    output  = s.get("output", "")

                    if sid == "ssl-dh-params" and "VULNERABLE" in output:
                        threats.append("Anonymous DH vulnerability in TLS")
                        severity += 4

                    if sid == "http-enum":
                        # check if interesting folders found
                        if "/" in output and "Potentially interesting" in output:
                            threats.append("Web‐enum discovered directories (e.g. admin panels)")
                            severity += 2

                    if sid == "vulners":
                        # parse CVE lines; assume output like:
                        #    CVE-2023-52971   4.9   https://vulners.com/...
                        for line in output.splitlines():
                            parts = line.strip().split()
                            if parts and parts[0].startswith("CVE-"):
                                cve_id = parts[0]
                                try:
                                    cvss_score = float(parts[1])
                                except (IndexError, ValueError):
                                    cvss_score = 5.0
                                threats.append(f"{cve_id} (CVSS {cvss_score})")
                                severity += cvss_score / 2  # weight down so total caps at 10

                    # you can add more script cases here...

        # 3) Cap and dedupe
        severity = min(severity, 10.0)
        unique_threats = list(dict.fromkeys(threats))

        analysis[target] = {
            "threats": unique_threats,
            "severity": int(round(severity))
        }

    return analysis

