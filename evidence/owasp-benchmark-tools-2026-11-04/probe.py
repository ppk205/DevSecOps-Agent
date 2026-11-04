import sys,inspect
sys.stdout.reconfigure(encoding='utf-8')
from types import SimpleNamespace as NS
from vulnscan.assessment.cvss import score
for v,exp in [("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",9.3),("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",8.5),("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",10.0)]:
    r=score(v); print(v,'expected',exp,'got',r.base_score,r.qualitative,'missing',r.missing)
try:
    import cvss; print('cvss lib',cvss.__version__ if hasattr(cvss,'__version__') else 'yes')
except Exception as e: print('no cvss lib',e)
from vulnscan.ai.review import evidence_for
from vulnscan.assessment.validator import IndependentValidator
from vulnscan.contracts.enums import FindingStatus
from vulnscan.contracts.assessment import Assessment
print(list(Assessment.model_fields.keys()))
req={k:f for k,f in Assessment.model_fields.items() if f.is_required()}
print('required',list(req))
def run(verdict,conf,nobs):
    a=NS(proposed_status=verdict,confidence=conf,provider_id='p',model_id='m',assessment_id='a1')
    obs=[NS(location=NS(file_path='A.java',line_start=i+1),observation_id=f'o{i}',tool=NS(value='semgrep'),rule_id='r') for i in range(nobs)]
    f=NS(finding_id='f1',observations=obs,status=FindingStatus.UNPROCESSED,run_id='r')
    rec=evidence_for(f,a,'r')
    d=IndependentValidator().validate('f1',FindingStatus.UNPROCESSED,a,rec)
    return d.new_status.value
print('verdict conf nobs -> status')
for v,c,n in [('rejected',.95,0),('rejected',.95,1),('rejected',.5,1),('rejected',.95,2),('confirmed',.95,1),('confirmed',.5,1),('confirmed',.95,0),('unresolved',.4,1),('unresolved',.4,2),('unresolved',.4,3)]:
    print(v,c,n,'->',run(v,c,n))
