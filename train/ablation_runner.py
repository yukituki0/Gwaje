"""
Ablation: 모델(GAT/Transformer) x 손실함수(MSE/BCE) 4개 조합을 모두 학습·검증
실행: python -m train.ablation_runner
"""
import glob
import os
import torch
from scipy.stats import spearmanr

from train.train import main as train_main
from core.graph.vulnet_loader import load_vulnet_graph
from core.detection.gat_model import RiskGAT, RiskGraphTransformer, graph_to_pyg_data
from core.detection.external_labels import get_external_labels

HOLDOUT_PATTERN = "50_*star*.json"
VULNET_NETWORK_DIR = "data/vulnet_networks"


def evaluate(model_type, weight_path):
    model = RiskGraphTransformer() if model_type == "transformer" else RiskGAT()
    model.load_state_dict(torch.load(weight_path, map_location="cpu"))
    model.eval()

    holdout_files = sorted(glob.glob(os.path.join(VULNET_NETWORK_DIR, HOLDOUT_PATTERN)))
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

    corr, _ = spearmanr(all_actual, all_pred)
    return corr


if __name__ == "__main__":
    results = {}
    for model_type in ["gat", "transformer"]:
        for loss_type in ["mse", "bce"]:
            print(f"\n{'='*50}\n조합: {model_type} + {loss_type}\n{'='*50}")
            weight_path = train_main(model_type, loss_type)
            corr = evaluate(model_type, weight_path)
            results[f"{model_type}+{loss_type}"] = corr
            print(f"  -> held-out 스피어만: {corr:.4f}")

    print(f"\n{'='*50}\n최종 Ablation 결과\n{'='*50}")
    for combo, corr in sorted(results.items(), key=lambda x: -x[1]):
        print(f"  {combo:20s} 스피어만={corr:.4f}")