"""
멀티프로세싱 없이 파일 하나만 직접 처리해서 진짜 에러를 확인하는 스크립트
"""
import sys, os
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import algorithms.netspa as NETSPA
import algorithms.tva as TVA
import config

filename = "5_5_lan25_uniform_0.25.json"

print("=== NETSPA 시도 ===")
try:
    NETSPA.build_model_graph(filename)
    print("NETSPA 성공!")
except Exception as e:
    import traceback
    traceback.print_exc()

print("\n=== TVA 시도 ===")
try:
    TVA.build_model_graph(filename)
    print("TVA 성공!")
except Exception as e:
    import traceback
    traceback.print_exc()