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
import networkx as nx

# 6.3절 노드 구성표를 그대로 옮김
NODES = {
    # 외부
    "attacker":          dict(zone="external", vulnerability_score=0.0, privilege_level=0, importance=0.0, is_compromised=False, patch_status=False),

    # DMZ (3) - 메인경로: web_dmz / 배경: mail_dmz(안전), vpn_dmz(중간)
    "web_dmz":            dict(zone="dmz", vulnerability_score=0.98, privilege_level=1, importance=0.6, is_compromised=False, patch_status=False),  # CVE-2021-26855
    "mail_dmz":           dict(zone="dmz", vulnerability_score=0.15, privilege_level=1, importance=0.5, is_compromised=False, patch_status=True),
    "vpn_dmz":            dict(zone="dmz", vulnerability_score=0.45, privilege_level=1, importance=0.5, is_compromised=False, patch_status=False),

    # 내부서버 (5) - 메인경로: internal_srv01 / 배경: file/print/webapp/backup
    "internal_srv01":    dict(zone="internal", vulnerability_score=0.93, privilege_level=1, importance=0.7, is_compromised=False, patch_status=False),  # CVE-2017-0144
    "file_srv":           dict(zone="internal", vulnerability_score=0.30, privilege_level=1, importance=0.5, is_compromised=False, patch_status=True),
    "print_srv":          dict(zone="internal", vulnerability_score=0.20, privilege_level=1, importance=0.2, is_compromised=False, patch_status=True),
    "webapp_srv":         dict(zone="internal", vulnerability_score=0.55, privilege_level=1, importance=0.5, is_compromised=False, patch_status=False),
    "backup_srv":         dict(zone="internal", vulnerability_score=0.35, privilege_level=1, importance=0.6, is_compromised=False, patch_status=True),

    # 사용자 PC (5) - 메인경로 연결: pc01, pc02 / 배경: pc03~05
    "pc01":                dict(zone="internal", vulnerability_score=0.40, privilege_level=1, importance=0.3, is_compromised=False, patch_status=False),
    "pc02":                dict(zone="internal", vulnerability_score=0.38, privilege_level=1, importance=0.3, is_compromised=False, patch_status=False),
    "pc03":                dict(zone="internal", vulnerability_score=0.25, privilege_level=1, importance=0.2, is_compromised=False, patch_status=True),
    "pc04":                dict(zone="internal", vulnerability_score=0.22, privilege_level=1, importance=0.2, is_compromised=False, patch_status=True),
    "pc05":                dict(zone="internal", vulnerability_score=0.28, privilege_level=1, importance=0.2, is_compromised=False, patch_status=False),

    # 핵심자산 (2) - 메인경로: 둘 다
    "domain_controller":  dict(zone="core", vulnerability_score=0.96, privilege_level=2, importance=1.0, is_compromised=False, patch_status=False),  # CVE-2020-1472
    "db_srv":              dict(zone="core", vulnerability_score=0.60, privilege_level=2, importance=1.0, is_compromised=False, patch_status=True),

    # 네트워크장비 (2) - 배경
    "router":              dict(zone="network", vulnerability_score=0.20, privilege_level=0, importance=0.4, is_compromised=False, patch_status=True),
    "switch_backup":       dict(zone="network", vulnerability_score=0.18, privilege_level=0, importance=0.3, is_compromised=False, patch_status=True),
}

# 메인 공격경로 엣지 (5장 6단계 매핑, CVE 기반이라 성공확률 높음/비용 낮음)
MAIN_PATH_EDGES = [
    ("attacker", "web_dmz",                  dict(attack_cost=0.15, success_prob=0.90, protocol="HTTPS", cve="CVE-2021-26855")),
    ("web_dmz", "internal_srv01",            dict(attack_cost=0.25, success_prob=0.80, protocol="SMB",   cve="CVE-2017-0144")),
    ("internal_srv01", "pc01",               dict(attack_cost=0.20, success_prob=0.75, protocol="SMB",   cve=None)),
    ("internal_srv01", "domain_controller",  dict(attack_cost=0.10, success_prob=0.85, protocol="RPC",   cve="CVE-2020-1472")),
    ("domain_controller", "db_srv",          dict(attack_cost=0.20, success_prob=0.70, protocol="TDS",   cve=None)),
]

# 배경/가짜경로 엣지 (막다른 길, 우회 가능하지만 비용 큰 경로 등 - 8.2절 다양성 원칙)
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
]


def build_base_network() -> nx.DiGraph:
    """기본 골격(DMZ-내부망-핵심자산) + 메인 공격경로가 반영된 방향성 그래프 생성"""
    G = nx.DiGraph()

    for node_id, attrs in NODES.items():
        G.add_node(node_id, **attrs)

    for u, v, attrs in MAIN_PATH_EDGES + BACKGROUND_EDGES:
        G.add_edge(u, v, **attrs)

    return G


if __name__ == "__main__":
    G = build_base_network()
    print(f"노드 수: {G.number_of_nodes()}, 엣지 수: {G.number_of_edges()}")
    main_path = ["attacker", "web_dmz", "internal_srv01", "domain_controller", "db_srv"]
    print("메인 경로:", " -> ".join(main_path))