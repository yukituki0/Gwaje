"""
GATv2 기반 위험도 예측 모델 (edge-aware, 연구방법론_정리.md 2.4, 4.5절)

입력:
    노드 feature (5종): vulnerability_score, privilege_level, importance, is_compromised, patch_status
    엣지 feature: attack_cost, success_prob, protocol(원-핫)
출력:
    각 노드의 risk_score 예측값 (0~1)
"""
import torch
import torch.nn as nn
import networkx as nx
from torch_geometric.nn import GATv2Conv
from torch_geometric.data import Data
from torch_geometric.nn import TransformerConv

# 네트워크에 등장하는 프로토콜 종류 고정 (4.2절 - 나중에 추가 대비해 OTHER 포함)
PROTOCOLS = ["HTTPS", "SMB", "RPC", "TDS", "SMTP", "HTTP", "IPP", "SNMP", "OTHER"]
EDGE_FEATURE_DIM = 2 + len(PROTOCOLS)  # attack_cost, success_prob + protocol one-hot

# 흔한 CWE(취약점 유형) 목록 + 미분류 대비 OTHER (4.2절 protocol 인코딩과 같은 패턴)
CWE_VOCAB = [
    "CWE-79",   # XSS
    "CWE-89",   # SQL Injection
    "CWE-200",  # 정보노출
    "CWE-269",  # 부적절한 권한관리
    "CWE-284",  # 부적절한 접근통제
    "CWE-287",  # 부적절한 인증
    "CWE-352",  # CSRF
    "CWE-434",  # 무제한 파일업로드
    "CWE-502",  # 역직렬화
    "CWE-611",  # XXE
    "CWE-732",  # 부적절한 권한 할당
    "CWE-798",  # 하드코딩된 자격증명
    "CWE-863",  # 부적절한 인가
    "CWE-917",  # 표현식 언어 인젝션
    "OTHER",
]

NODE_FEATURE_DIM = 5 + len(CWE_VOCAB)  # 기존 5개 + CWE 원핫


class RiskGAT(nn.Module):
    def __init__(self, node_in_dim=NODE_FEATURE_DIM, edge_in_dim=EDGE_FEATURE_DIM,
                 hidden_dim=32, heads=8, num_layers=2, dropout=0.1):
        super().__init__()
        self.layers = nn.ModuleList()

        # 1층: node_in_dim -> hidden_dim (heads개 병렬, concat)
        self.layers.append(
            GATv2Conv(node_in_dim, hidden_dim, heads=heads, edge_dim=edge_in_dim, dropout=dropout)
        )
        in_dim = hidden_dim * heads

        # 중간층 (num_layers - 2개, 있다면)
        for _ in range(num_layers - 2):
            self.layers.append(
                GATv2Conv(in_dim, hidden_dim, heads=heads, edge_dim=edge_in_dim, dropout=dropout)
            )
            in_dim = hidden_dim * heads

        # 마지막층: heads=1로 합쳐서 단일 스칼라로 (오버스무딩 방지 위해 2~3층 권장, 2.5절)
        self.layers.append(
            GATv2Conv(in_dim, hidden_dim, heads=1, edge_dim=edge_in_dim, dropout=dropout)
        )

        self.out = nn.Linear(hidden_dim, 1)
        self.activation = nn.ELU()

    def forward(self, x, edge_index, edge_attr):
        h = x
        for i, layer in enumerate(self.layers):
            h = layer(h, edge_index, edge_attr)
            if i < len(self.layers) - 1:
                h = self.activation(h)
        logits = self.out(h)  # sigmoid 제거, raw logit 그대로 반환
        return logits.squeeze(-1)

class RiskGraphTransformer(nn.Module):
    """
    Graph Transformer 기반 위험도 예측 모델.
    GAT(이웃 어텐션)보다 더 풍부한 Query-Key-Value 어텐션 메커니즘 사용.
    (지도교수 피드백: 더 최신 GNN 아키텍처 검토 요청 대응, 14.9절)
    """
    def __init__(self, node_in_dim=NODE_FEATURE_DIM, edge_in_dim=EDGE_FEATURE_DIM,
                 hidden_dim=32, heads=8, num_layers=2, dropout=0.1):
        super().__init__()
        self.layers = nn.ModuleList()

        self.layers.append(
            TransformerConv(node_in_dim, hidden_dim, heads=heads, edge_dim=edge_in_dim, dropout=dropout)
        )
        in_dim = hidden_dim * heads

        for _ in range(num_layers - 2):
            self.layers.append(
                TransformerConv(in_dim, hidden_dim, heads=heads, edge_dim=edge_in_dim, dropout=dropout)
            )
            in_dim = hidden_dim * heads

        self.layers.append(
            TransformerConv(in_dim, hidden_dim, heads=1, edge_dim=edge_in_dim, dropout=dropout)
        )

        self.out = nn.Linear(hidden_dim, 1)
        self.activation = nn.ELU()

    def forward(self, x, edge_index, edge_attr):
        h = x
        for i, layer in enumerate(self.layers):
            h = layer(h, edge_index, edge_attr)
            if i < len(self.layers) - 1:
                h = self.activation(h)
        logits = self.out(h)   # BCE용 raw logit (sigmoid 없음)
        return logits.squeeze(-1)

def graph_to_pyg_data(G: nx.DiGraph, risk_labels: dict) -> Data:
    node_list = list(G.nodes)
    node_idx = {n: i for i, n in enumerate(node_list)}

    x = []
    y = []
    for n in node_list:
        attrs = G.nodes[n]
        base_features = [
            attrs.get("vulnerability_score", 0.0),
            attrs.get("privilege_level", 0) / 2.0,
            attrs.get("importance", 0.0),
            float(attrs.get("is_compromised", False)),
            float(attrs.get("patch_status", False)),
        ]
        # CWE 원-핫 인코딩 추가
        cwe = attrs.get("cwe")
        cwe_onehot = [1.0 if cwe == c else 0.0 for c in CWE_VOCAB]
        if cwe and sum(cwe_onehot) == 0:  # 알려진 CWE 목록에 없는 경우 -> OTHER
            cwe_onehot[-1] = 1.0
        x.append(base_features + cwe_onehot)
        y.append(risk_labels[n])

    edge_index = []
    edge_attr = []
    for u, v, data in G.edges(data=True):
        edge_index.append([node_idx[u], node_idx[v]])
        protocol_onehot = [1.0 if data.get("protocol") == p else 0.0 for p in PROTOCOLS]
        if sum(protocol_onehot) == 0:
            protocol_onehot[-1] = 1.0
        edge_attr.append([data["attack_cost"], data["success_prob"]] + protocol_onehot)

    return Data(
        x=torch.tensor(x, dtype=torch.float),
        edge_index=torch.tensor(edge_index, dtype=torch.long).t().contiguous(),
        edge_attr=torch.tensor(edge_attr, dtype=torch.float),
        y=torch.tensor(y, dtype=torch.float),
    ), node_list