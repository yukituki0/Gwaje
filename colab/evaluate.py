"""
학습된 GAT를 '학습에 안 쓴' 새 인스턴스로 검증
"""
import torch
from scipy.stats import spearmanr
from core.graph.network_builder import generate_instance
from core.detection.risk_score import compute_risk_scores
from core.detection.gat_model import RiskGAT, graph_to_pyg_data

# 학습에 안 쓴 seed (train.py는 base_seed=42, 0~29 사용했으니 그거랑 안 겹치는 seed)
G = generate_instance(seed=9999)
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

# 정량 지표: 정답 순위와 예측 순위가 얼마나 일치하는지 (스피어만 상관계수, -1~1, 1이면 완벽 일치)
actual_vals = [risk_labels[n] for n in node_list]
pred_vals = pred.tolist()
corr, _ = spearmanr(actual_vals, pred_vals)
print(f"\n스피어만 순위상관계수: {corr:.4f}")