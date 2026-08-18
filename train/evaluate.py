"""
학습된 GAT를 '학습에 안 쓴' vuln-net-ag 네트워크로 검증
실행: python -m train.evaluate
"""
import glob
import os
import torch
from scipy.stats import spearmanr
from core.graph.vulnet_loader import load_vulnet_graph
from core.detection.gat_model import RiskGAT, graph_to_pyg_data
from core.detection.external_labels import get_external_labels
from core.detection.gat_model import RiskGraphTransformer, graph_to_pyg_data

VULNET_NETWORK_DIR = "data/vulnet_networks"

# 학습엔 5_*.json만 썼으니, 검증은 10_*.json (완전히 다른 규모/한 번도 안 본 네트워크)
HOLDOUT_PATTERN = "50_*star*.json"  # star 토폴로지는 학습에서 뺐으니 완전히 새로운 검증


def main():
    model = RiskGraphTransformer()
    model.load_state_dict(torch.load("data/models/gat_model.pt", map_location="cpu"))
    model.eval()

    holdout_files = sorted(glob.glob(os.path.join(VULNET_NETWORK_DIR, HOLDOUT_PATTERN)))
    print(f"검증용 held-out 네트워크 {len(holdout_files)}개: {[os.path.basename(f) for f in holdout_files]}")

    all_actual, all_pred = [], []

    for path in holdout_files:
        G = load_vulnet_graph(path)
        all_cves = list({G.nodes[n]["cve"] for n in G.nodes if G.nodes[n].get("cve")})
        ext_labels = get_external_labels(all_cves) if all_cves else {}

        dummy_labels = {n: 0.0 for n in G.nodes}
        data, node_list = graph_to_pyg_data(G, dummy_labels)

        with torch.no_grad():
            pred = torch.sigmoid(model(data.x, data.edge_index, data.edge_attr))

        for i, n in enumerate(node_list):
            cve = G.nodes[n].get("cve")
            if cve and cve in ext_labels and ext_labels[cve]["epss"] is not None:
                all_actual.append(ext_labels[cve]["epss"])
                all_pred.append(pred[i].item())

    print(f"\n검증에 사용된 노드 수: {len(all_actual)}")

    if len(all_actual) >= 2:
        corr, _ = spearmanr(all_actual, all_pred)
        print(f"스피어만 순위상관계수 (held-out, 학습에 안 쓴 실제 네트워크): {corr:.4f}")
    else:
        print("검증 가능한 노드가 부족합니다.")

    print(f"\n{'실제 EPSS':>12s} {'GAT 예측':>12s}")
    for a, p in sorted(zip(all_actual, all_pred), key=lambda x: -x[0])[:15]:
        print(f"{a:12.4f} {p:12.4f}")


if __name__ == "__main__":
    main()