"""
18개 노드 기반 공격 그래프 생성 (연구방법론_정리.md 6장 참고)
- 골격: DMZ / 내부망 / 핵심자산 구조 (표준 기업 네트워크 참조)
- MITRE ATT&CK 6단계 메인 공격경로를 골격 위에 배치 (5장 참고)

노드 속성 (계획서 6.1.2.2, feature 5종):
    vulnerability_score : float (0~1, CVSS 정규화)
    privilege_level      : int  (0=없음, 1=사용자, 2=관리자)
    importance            : float (0~1, 자산 중요도)
    is_compromised        : bool
    patch_status           : bool (True=패치됨)

엣지 속성 (계획서 6.1.3.2):
    attack_cost   : float (0~1, 낮을수록 공격 쉬움)
    success_prob  : float (0~1, 높을수록 성공 가능성 높음)
    protocol       : str  (원-핫 인코딩은 GAT 입력 변환 단계에서 처리)
"""
import random
import networkx as nx

NODES = {
    "attacker":          dict(zone="external", vulnerability_score=0.0, privilege_level=0, importance=0.0, is_compromised=False, patch_status=False, cve=None),

    "web_dmz":            dict(zone="dmz", vulnerability_score=0.98, privilege_level=1, importance=0.6, is_compromised=False, patch_status=False, cve="CVE-2021-26855"),
    "mail_dmz":  dict(zone="dmz", vulnerability_score=0.15, privilege_level=1, importance=0.5, is_compromised=False, patch_status=True, cve="CVE-2024-0646"),
    "vpn_dmz":            dict(zone="dmz", vulnerability_score=0.45, privilege_level=1, importance=0.5, is_compromised=False, patch_status=False, cve="CVE-2019-11510"),

    "internal_srv01":    dict(zone="internal", vulnerability_score=0.93, privilege_level=1, importance=0.7, is_compromised=False, patch_status=False, cve="CVE-2017-0144"),
    "file_srv":  dict(zone="internal", vulnerability_score=0.30, privilege_level=1, importance=0.5, is_compromised=False, patch_status=True, cve="CVE-2023-38039"),
    "print_srv": dict(zone="internal", vulnerability_score=0.20, privilege_level=1, importance=0.2, is_compromised=False, patch_status=True, cve="CVE-2024-21626"),
    "webapp_srv":         dict(zone="internal", vulnerability_score=0.55, privilege_level=1, importance=0.5, is_compromised=False, patch_status=False, cve="CVE-2021-44228"),
    "backup_srv":    dict(zone="internal", vulnerability_score=0.35, privilege_level=1, importance=0.6, is_compromised=False, patch_status=True, cve="CVE-2021-3156"),

    "pc01":                dict(zone="internal", vulnerability_score=0.40, privilege_level=1, importance=0.3, is_compromised=False, patch_status=False, cve="CVE-2017-11882"),
    "pc02":                dict(zone="internal", vulnerability_score=0.38, privilege_level=1, importance=0.3, is_compromised=False, patch_status=False, cve="CVE-2023-23397"),
    "pc03":          dict(zone="internal", vulnerability_score=0.25, privilege_level=1, importance=0.2, is_compromised=False, patch_status=True, cve="CVE-2021-3449"),
    "pc04":          dict(zone="internal", vulnerability_score=0.22, privilege_level=1, importance=0.2, is_compromised=False, patch_status=True, cve="CVE-2022-3602"),
    "pc05":                dict(zone="internal", vulnerability_score=0.28, privilege_level=1, importance=0.2, is_compromised=False, patch_status=False, cve="CVE-2021-26411"),

    "domain_controller":  dict(zone="core", vulnerability_score=0.96, privilege_level=2, importance=1.0, is_compromised=False, patch_status=False, cve="CVE-2020-1472"),
    "db_srv":              dict(zone="core", vulnerability_score=0.60, privilege_level=2, importance=1.0, is_compromised=False, patch_status=True, cve="CVE-2012-2122"),

    "router":        dict(zone="network", vulnerability_score=0.20, privilege_level=0, importance=0.4, is_compromised=False, patch_status=True, cve="CVE-2022-22965"),
    "switch_backup": dict(zone="network", vulnerability_score=0.18, privilege_level=0, importance=0.3, is_compromised=False, patch_status=True, cve="CVE-2023-4863"),
}

MAIN_PATH_EDGES = [
    ("attacker", "web_dmz",                  dict(attack_cost=0.15, success_prob=0.90, protocol="HTTPS", cve="CVE-2021-26855")),
    ("web_dmz", "internal_srv01",            dict(attack_cost=0.25, success_prob=0.80, protocol="SMB",   cve="CVE-2017-0144")),
    ("internal_srv01", "pc01",               dict(attack_cost=0.20, success_prob=0.75, protocol="SMB",   cve=None)),
    ("internal_srv01", "domain_controller",  dict(attack_cost=0.10, success_prob=0.85, protocol="RPC",   cve="CVE-2020-1472")),
    ("domain_controller", "db_srv",          dict(attack_cost=0.20, success_prob=0.70, protocol="TDS",   cve=None)),
]

BACKGROUND_EDGES = [
    ("attacker", "mail_dmz",         dict(attack_cost=0.85, success_prob=0.10, protocol="SMTP", cve=None)),
    ("attacker", "vpn_dmz",          dict(attack_cost=0.55, success_prob=0.40, protocol="HTTPS", cve=None)),
    ("web_dmz", "webapp_srv",        dict(attack_cost=0.45, success_prob=0.50, protocol="HTTP",  cve=None)),
    ("vpn_dmz", "file_srv",          dict(attack_cost=0.50, success_prob=0.45, protocol="SMB",   cve=None)),
    ("webapp_srv", "file_srv",       dict(attack_cost=0.40, success_prob=0.50, protocol="SMB",   cve=None)),
    ("file_srv", "backup_srv",       dict(attack_cost=0.35, success_prob=0.55, protocol="SMB",   cve=None)),
    ("internal_srv01", "pc02",       dict(attack_cost=0.22, success_prob=0.72, protocol="SMB",   cve=None)),
    ("internal_srv01", "print_srv",  dict(attack_cost=0.60, success_prob=0.30, protocol="IPP",   cve=None)),
    ("pc01", "pc03",                 dict(attack_cost=0.70, success_prob=0.25, protocol="SMB",   cve=None)),
    ("pc02", "pc04",                 dict(attack_cost=0.72, success_prob=0.22, protocol="SMB",   cve=None)),
    ("file_srv", "pc05",             dict(attack_cost=0.65, success_prob=0.28, protocol="SMB",   cve=None)),
    ("router", "internal_srv01",     dict(attack_cost=0.50, success_prob=0.40, protocol="SNMP",  cve=None)),
    ("switch_backup", "file_srv",    dict(attack_cost=0.55, success_prob=0.35, protocol="SNMP",  cve=None)),
    ("vpn_dmz", "domain_controller", dict(attack_cost=0.35, success_prob=0.55, protocol="RDP", cve=None)),
]


def build_base_network() -> nx.DiGraph:
    """기본 골격(DMZ-내부망-핵심자산) + 메인 공격경로가 반영된 방향성 그래프 생성"""
    G = nx.DiGraph()
    for node_id, attrs in NODES.items():
        G.add_node(node_id, **attrs)
    for u, v, attrs in MAIN_PATH_EDGES + BACKGROUND_EDGES:
        G.add_edge(u, v, **attrs)
    return G


# ---- 8.3절: 배경 다중 인스턴스 생성 (과적합 완화) ----

MAIN_PATH_NODES = {"attacker", "web_dmz", "internal_srv01", "domain_controller", "db_srv"}
MAIN_PATH_EDGE_PAIRS = {(u, v) for u, v, _ in MAIN_PATH_EDGES}


def generate_instance(seed: int = None) -> nx.DiGraph:
    """
    메인 공격경로는 고정, 배경 노드/엣지 속성만 통제된 범위(±0.15) 내에서 흔든 인스턴스 생성.
    (8.3절 과적합 완화책 - 동일 스토리라인, 다른 배경 맥락)
    """
    rng = random.Random(seed)
    G = build_base_network()

    for n in G.nodes:
        if n in MAIN_PATH_NODES:
            continue
        attrs = G.nodes[n]
        jitter = rng.uniform(-0.15, 0.15)
        attrs["vulnerability_score"] = min(1.0, max(0.0, attrs["vulnerability_score"] + jitter))

    for u, v, data in G.edges(data=True):
        if (u, v) in MAIN_PATH_EDGE_PAIRS:
            continue
        jitter_cost = rng.uniform(-0.1, 0.1)
        jitter_prob = rng.uniform(-0.1, 0.1)
        data["attack_cost"] = min(1.0, max(0.01, data["attack_cost"] + jitter_cost))
        data["success_prob"] = min(1.0, max(0.01, data["success_prob"] + jitter_prob))

    return G


def generate_multiple_instances(n: int, base_seed: int = 0) -> list:
    """n개의 서로 다른 배경 구성 인스턴스 생성"""
    return [generate_instance(seed=base_seed + i) for i in range(n)]

def apply_real_cvss(G: nx.DiGraph):
    """
    각 노드의 vulnerability_score를, 임의로 넣은 값 대신 NVD의 실제 CVSS로 덮어씀.
    (지도교수 피드백: 입력 특성값도 근거 없는 임의값이었던 문제 대응)
    """
    from core.detection.external_labels import get_real_cvss_scores

    cve_list = [G.nodes[n]["cve"] for n in G.nodes if G.nodes[n].get("cve")]
    real_scores = get_real_cvss_scores(cve_list)

    for n in G.nodes:
        cve = G.nodes[n].get("cve")
        if cve and real_scores.get(cve) is not None:
            G.nodes[n]["vulnerability_score"] = real_scores[cve]
        # cve가 없는 노드(attacker)나 조회 실패 시 기존 값 유지
    return G

if __name__ == "__main__":
    G = build_base_network()
    print(f"노드 수: {G.number_of_nodes()}, 엣지 수: {G.number_of_edges()}")
    main_path = ["attacker", "web_dmz", "internal_srv01", "domain_controller", "db_srv"]
    print("메인 경로:", " -> ".join(main_path))