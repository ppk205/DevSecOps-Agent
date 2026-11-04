"""Compare the project CVSS v4.0 scorer with the locked cvss library. No model is called."""
import sys

from cvss import CVSS4

from vulnscan.assessment.cvss import score

sys.stdout.reconfigure(encoding="utf-8")
VECTORS = ["AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N","AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N","AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H","AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N","AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"]
for v in VECTORS:
    print(f"{v}\tproject={score('CVSS:4.0/' + v).base_score}\tlibrary={CVSS4('CVSS:4.0/' + v).base_score}")
