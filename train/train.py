"""
GAT/Graph Transformer 오프라인 학습 스크립트 (ablation 지원)
실행: python -m train.train --model gat --loss mse
      python -m train.train --model transformer --loss bce
"""
import os
import sys
import glob
import argparse
import torch
from torch_geometric.data import Batch, Data
from core.graph.vulnet_loader import load_vulnet_graph
from core.detection.gat_model import RiskGAT, RiskGraphTransformer, graph_to_pyg_data
from core.detection.external_labels import get_external_labels

MAX_EPOCHS = 500
PATIENCE = 50
LR = 0.01
VULNET_NETWORK_DIR = "data/vulnet_networks"


def build_data_with_external_labels(G) -> Data:
    dummy_labels = {n: 0.0 for n in G.nodes}
    pyg_data, node_list = graph_to_pyg_data(G, dummy_labels)

    all_cves = list({G.nodes[n]["cve"] for n in G.nodes if G.nodes[n].get("cve")})
    ext_labels = get_external_labels(all_cves) if all_cves else {}

    y, mask = [], []
    for n in node_list:
        cve = G.nodes[n].get("cve")
        if cve and cve in ext_labels and ext_labels[cve]["epss"] is not None:
            y.append(ext_labels[cve]["epss"])
            mask.append(True)
        else:
            y.append(0.0)
            mask.append(False)

    pyg_data.y = torch.tensor(y, dtype=torch.float)
    pyg_data.mask = torch.tensor(mask, dtype=torch.bool)
    return pyg_data


def main(model_type="transformer", loss_type="bce", save_suffix=""):
    network_files = (
        sorted(glob.glob(os.path.join(VULNET_NETWORK_DIR, "5_*.json"))) +
        sorted(glob.glob(os.path.join(VULNET_NETWORK_DIR, "10_*.json"))) +
        sorted(glob.glob(os.path.join(VULNET_NETWORK_DIR, "50_*lan25*.json"))) +
        sorted(glob.glob(os.path.join(VULNET_NETWORK_DIR, "50_*powerlaw*.json")))
    )
    print(f"[{model_type}+{loss_type}] 학습 네트워크 {len(network_files)}개")

    data_list = [build_data_with_external_labels(load_vulnet_graph(p)) for p in network_files]
    batch = Batch.from_data_list(data_list)
    print(f"총 노드 {batch.num_nodes}개 중 실제 라벨 {batch.mask.sum().item()}개")

    model = RiskGraphTransformer() if model_type == "transformer" else RiskGAT()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = torch.nn.BCEWithLogitsLoss() if loss_type == "bce" else torch.nn.MSELoss()

    # MSE를 쓸 땐 라벨이 0~1 확률이라 그대로 두되, 모델 출력에 sigmoid를 씌워 비교해야 함
    use_sigmoid_for_mse = (loss_type == "mse")

    best_loss = float("inf")
    patience_counter = 0

    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        optimizer.zero_grad()
        raw_pred = model(batch.x, batch.edge_index, batch.edge_attr)
        pred = torch.sigmoid(raw_pred) if use_sigmoid_for_mse else raw_pred
        loss = loss_fn(pred[batch.mask], batch.y[batch.mask])
        loss.backward()
        optimizer.step()

        if loss.item() < best_loss - 1e-5:
            best_loss = loss.item()
            patience_counter = 0
        else:
            patience_counter += 1

        if epoch % 50 == 0 or epoch == 1:
            print(f"  epoch {epoch:3d}  loss={loss.item():.5f}")
        if patience_counter >= PATIENCE:
            print(f"  Early stopping at epoch {epoch} (best_loss={best_loss:.5f})")
            break

    os.makedirs("data/models", exist_ok=True)
    save_path = f"data/models/gat_model_{model_type}_{loss_type}{save_suffix}.pt"
    torch.save(model.state_dict(), save_path)
    print(f"저장 완료: {save_path}\n")
    return save_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=["gat", "transformer"], default="transformer")
    parser.add_argument("--loss", choices=["mse", "bce"], default="bce")
    args = parser.parse_args()
    main(args.model, args.loss)