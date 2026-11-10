"""Project-fixture wrapper; all AF algorithms come from the frozen source."""
import argparse
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from caprls_core.final_af_admission_study import run_admission_study

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=run_admission_study(ROOT,a.output)
    if result['status']!='pass':raise SystemExit(1)
