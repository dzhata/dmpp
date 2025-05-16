# modules/drivers/vuln/sqlmap_driver.py
import subprocess, json, os
from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class SQLMapDriver(BaseToolDriver):
    name = "sqlmap"

    def __init__(self, config, session_mgr, logger):
        super().__init__(config, session_mgr, logger)
        self.binary = config["sqlmap_binary"]
        self.args   = config["sqlmap_args"]
        self.outdir = config["sqlmap_output_dir"]
        os.makedirs(self.outdir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, forms: list, **kwargs) -> DriverResult:
        """
        Iterate over forms: build full URLs & POST data, invoke SQLMap in JSON mode.
        """
        raw_outputs = []
        for idx, f in enumerate(forms):
            url  = f["action"] or target
            data = "&".join(f"{k}={v}" for k,v in f["fields"].items())
            fn   = f"{target.replace('://','_')}_{idx}.json"
            path = os.path.join(self.outdir, fn)

            cmd = [self.binary, "-u", url, "--data", data, *self.args, "-oJ", "-"]
            self.logger.info(f"[SQLMap] {cmd}")
            proc = subprocess.run(cmd, capture_output=True, timeout=self.config["scan_timeout_sec"])
            with open(path, "wb") as out:
                out.write(proc.stdout)
            raw_outputs.append(path)

        return DriverResult(raw_output=raw_outputs)

    def parse(self, raw_output_paths) -> ParsedResult:
        """
        Read each JSON output, extract `injection` findings:
        e.g. vulnerable parameter, type, payload.
        """
        results = []
        for p in raw_output_paths:
            j = json.load(open(p))
            # SQLMap JSON uses keys like 'vulnerabilities' and 'injections'
            if "vulnerabilities" in j:
                results.extend(j["vulnerabilities"])
            if "injections" in j:
                results.extend(j["injections"])
        return ParsedResult(data={"injections": results})
