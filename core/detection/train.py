"""
GAT 오프라인 학습 스크립트 (여러 그래프 인스턴스로 학습, 8.3절 과적합 완화 반영)
실행: python -m core.detection.train
결과: data/models/gat_model.pt 저장
"""
import os
import torch
from torch_geometric.data import Batch
from core.graph.network_builder import generate_multiple_instances
from core.detection.risk_score import compute_risk_scores
from core.detection.gat_model import RiskGAT, graph_to_pyg_data

MAX_EPOCHS = 300
PATIENCE = 30
LR = 0.01
N_INSTANCES = 30  # 배경 구성 다른 인스턴스 개수


def main():
    # 1) 여러 인스턴스 생성 + 각각 risk_score 라벨 계산 (8.3절)
    graphs = generate_multiple_instances(N_INSTANCES, base_seed=42)
    data_list = []
    for G in graphs:
        risk_labels = compute_risk_scores(G, "attacker")
        data, _ = graph_to_pyg_data(G, risk_labels)
        data_list.append(data)

    # 여러 그래프를 하나의 배치로 묶음 (그래프 간 엣지는 안 생김, 독립적으로 처리됨)
    batch = Batch.from_data_list(data_list)
    print(f"인스턴스 {N_INSTANCES}개 -> 총 노드 {batch.num_nodes}개, 엣지 {batch.num_edges}개로 학습")

    # 2) 모델/옵티마이저
    model = RiskGAT()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = torch.nn.MSELoss()

    # 3) 학습
    best_loss = float("inf")
    patience_counter = 0

    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        optimizer.zero_grad()
        pred = model(batch.x, batch.edge_index, batch.edge_attr)
        loss = loss_fn(pred, batch.y)
        loss.backward()
        optimizer.step()

        if loss.item() < best_loss - 1e-5:
            best_loss = loss.item()
            patience_counter = 0
        else:
            patience_counter += 1

        if epoch % 20 == 0 or epoch == 1:
            print(f"epoch {epoch:3d}  loss={loss.item():.5f}")

        if patience_counter >= PATIENCE:
            print(f"Early stopping at epoch {epoch} (best_loss={best_loss:.5f})")
            break

    # 4) 저장
    os.makedirs("data/models", exist_ok=True)
    torch.save(model.state_dict(), "data/models/gat_model.pt")
    print("저장 완료: data/models/gat_model.pt")


if __name__ == "__main__":
    main()