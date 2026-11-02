"""QR-23: a failed, skipped or cancelled prerequisite cannot pass the CI gate."""

import json
import os


def main() -> int:
    needs = json.loads(os.environ["CI_NEEDS_JSON"])
    if not isinstance(needs, dict) or not needs:
        print("No prerequisite results were supplied; CI remains failed.")
        return 1
    failed = []
    for name, job in needs.items():
        status = job.get("result") if isinstance(job, dict) else None
        print(f"{name}: {status}")
        if status != "success":
            failed.append(name)
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
