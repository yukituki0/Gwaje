"""
GATv2 기반 위험도 예측 모델 (edge-aware, 연구방법론_정리.md 4.5, 2.4절)
입력: 노드 feature(5종) + 엣지 feature(attack_cost, success_prob, protocol 원핫)
"""
import torch
import torch.nn as nn
from torch_geometric.nn import GATv2Conv

class RiskGAT(nn.Module):
    def __init__(self, node_in_dim: int, edge_in_dim: int, hidden_dim: int = 32, heads: int = 8):
        super().__init__()
        # TODO: GATv2Conv(node_in_dim, hidden_dim, heads=heads, edge_dim=edge_in_dim)
        raise NotImplementedError

    def forward(self, x, edge_index, edge_attr):
        raise NotImplementedError
