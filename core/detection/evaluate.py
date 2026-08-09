"""
학습된 GAT의 예측 결과를 실제 risk_score(정답) 순위와 비교하는 검증 스크립트
"""
import torch
from core.graph.network_builder import build_base_network
from core.detection.risk_score import compute_risk_scores
from core.detection.gat_model import RiskGAT, graph_to_pyg_data

G = build_base_network()
risk_labels = compute_risk_scores(G, "attacker")
data, node_list = graph_to_pyg_data(G, risk_labels)

model = RiskGAT()
model.load_state_dict(torch.load("data/models/gat_model.pt"))
model.eval()

with torch.no_grad():
    pred = model(data.x, data.edge_index, data.edge_attr)

main_path_nodes = {"web_dmz", "internal_srv01", "domain_controller", "db_srv"}

print(f"{'node':20s} {'실제(정답)':>10s} {'GAT예측':>10s}")
results = sorted(zip(node_list, risk_labels.values(), pred.tolist()), key=lambda x: -x[2])
for node, actual, predicted in results:
    marker = " <- 메인경로" if node in main_path_nodes else ""
    print(f"{node:20s} {actual:10.4f} {predicted:10.4f}{marker}")