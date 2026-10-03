"""Offline adapter injection for Go/Python compatibility tests."""

import argparse
import os
import sys
from contextlib import redirect_stdout

from tests.platform.test_scan_service import FixtureAdapter
from vulnscan.contracts import ToolName
from vulnscan.core.rpc import ServiceRPC
from vulnscan.core.scan_service import ScanService
from vulnscan.scanners.base import AdapterRegistry
from vulnscan.scanners.process import run_command


class SlowAdapter(FixtureAdapter):
    def run(self, spec, *, workdir):
        run_command([sys.executable, "-c", "import time; time.sleep(60)"])
        return super().run(spec, workdir=workdir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", required=True)
    args = parser.parse_args()
    registry = AdapterRegistry()
    registry.register(FixtureAdapter())
    second = SlowAdapter() if os.environ.get("DEVSECOPS_FIXTURE_SLOW") else FixtureAdapter()
    second.tool = ToolName.GITLEAKS
    registry.register(second)
    with redirect_stdout(sys.stderr):
        service = ScanService(args.db_path, registry)
    ServiceRPC(service).serve()


if __name__ == "__main__":
    main()
