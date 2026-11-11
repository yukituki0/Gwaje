"""
ProcessPool 없이 순차적으로 모든 네트워크 파일에 대해 NETSPA/TVA 공격그래프 생성
"""
import os
import config
import algorithms.netspa as NETSPA
import algorithms.tva as TVA

network_files = [f for f in os.listdir(config.NETWORK_FOLDER if hasattr(config, "NETWORK_FOLDER") else "networks/") if f.endswith(".json")]
print(f"처리할 네트워크 파일 {len(network_files)}개")

if not os.path.exists(config.GRAPH_FOLDER):
    os.makedirs(config.GRAPH_FOLDER)

success, failed = 0, 0

for i, filename in enumerate(network_files, 1):
    netspa_out = config.GRAPH_FOLDER + "NETSPA_" + filename.split(".json")[0] + ".graphml"
    tva_out = config.GRAPH_FOLDER + "TVA_" + filename.split(".json")[0] + ".graphml"

    if not os.path.exists(netspa_out):
        try:
            NETSPA.build_model_graph(filename)
            print(f"[{i}/{len(network_files)}] NETSPA 성공: {filename}")
            success += 1
        except Exception as e:
            print(f"[{i}/{len(network_files)}] NETSPA 실패: {filename} -> {e}")
            failed += 1

    if not os.path.exists(tva_out):
        try:
            TVA.build_model_graph(filename)
            print(f"[{i}/{len(network_files)}] TVA 성공: {filename}")
            success += 1
        except Exception as e:
            print(f"[{i}/{len(network_files)}] TVA 실패: {filename} -> {e}")
            failed += 1

print(f"\n완료: 성공 {success}, 실패 {failed}")