"""
앱(웹)에서 사용하는 추론 전용 모듈.
Colab에서 학습된 gat_model.pt를 로드해서, 그래프가 주어지면 위험도만 빠르게 계산.
절대 여기서 학습(loss.backward(), optimizer.step() 등)을 하지 않음.
"""
import torch
from core.detection.gat_model import RiskGAT, graph_to_pyg_data

_model = None


def load_model(weight_path: str = "data/models/gat_model.pt"):
    """앱 시작 시 1회만 호출 (연구방법론_정리.md 9.2절)"""
    global _model
    if _model is None:
        _model = RiskGAT()
        _model.load_state_dict(torch.load(weight_path, map_location="cpu"))
        _model.eval()
    return _model


def predict_risk(G) -> dict:
    """
    networkx 그래프를 받아 각 노드의 위험도를 GAT로 추론 (학습 없이 계산만)
    Returns: {node_id: risk_score}
    """
    model = load_model()
    dummy_labels = {n: 0.0 for n in G.nodes}
    data, node_list = graph_to_pyg_data(G, dummy_labels)

    with torch.no_grad():
        pred = model(data.x, data.edge_index, data.edge_attr)

    return {node: score for node, score in zip(node_list, pred.tolist())}