"""
앱(웹)에서 사용하는 추론 전용 모듈.
Colab에서 학습된 gat_model.pt(Graph Transformer + BCE, 14.10절)를 로드해서 추론만 수행.
"""
import torch
from core.detection.gat_model import RiskGraphTransformer, graph_to_pyg_data

_model = None


def load_model(weight_path: str = "data/models/gat_model.pt"):
    global _model
    if _model is None:
        _model = RiskGraphTransformer()
        _model.load_state_dict(torch.load(weight_path, map_location="cpu"))
        _model.eval()
    return _model


def predict_risk(G) -> dict:
    model = load_model()
    dummy_labels = {n: 0.0 for n in G.nodes}
    data, node_list = graph_to_pyg_data(G, dummy_labels)

    with torch.no_grad():
        raw_pred = model(data.x, data.edge_index, data.edge_attr)
        pred = torch.sigmoid(raw_pred)   # BCE로 학습했으니 추론 시 sigmoid 필요 (14.10절)

    return {node: score for node, score in zip(node_list, pred.tolist())}