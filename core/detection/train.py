"""
GAT 오프라인 학습 스크립트 (Colab에서 실행 권장, 연구방법론_정리.md 9.2절)
실행: python -m core.detection.train
결과: data/models/gat_model.pt 저장
"""
import os
import torch
from core.graph.network_builder import build_base_network
from core.detection.risk_score import compute_risk_scores
from core.detection.gat_model import RiskGAT, graph_to_pyg_data

MAX_EPOCHS = 200
PATIENCE = 20  # early stopping (계획서 6.4.2.1)
LR = 0.01


def main():
    # 1) 그래프 생성 + risk_score 라벨 (4.3절)
    G = build_base_network()
    risk_labels = compute_risk_scores(G, "attacker")
    data, node_list = graph_to_pyg_data(G, risk_labels)

    print(f"노드 {data.num_nodes}개, 엣지 {data.num_edges}개로 학습 시작")

    # 2) 모델/옵티마이저
    model = RiskGAT()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = torch.nn.MSELoss()

    # 3) 학습 (노드가 18개뿐이라 train/val 분리 대신 전체를 보며 early stopping 기준만 확인)
    best_loss = float("inf")
    patience_counter = 0

    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        optimizer.zero_grad()
        pred = model(data.x, data.edge_index, data.edge_attr)
        loss = loss_fn(pred, data.y)
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