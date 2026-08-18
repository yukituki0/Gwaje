"""
vuln-net-ag(Palma & Bonomi, 2025)의 devices/edges JSON을 우리 NetworkX 파이프라인 형식으로 변환.
검증된 생성기가 만든 실제 NVD 기반 네트워크를 사용해 지도교수 피드백(합성 데이터 지적)에 대응.
CWE(취약점 유형)도 로컬 JSON에 이미 있는 데이터에서 추출 (API 호출 불필요, 14.14절).
"""
import json
import networkx as nx
from core.detection.external_labels import get_external_labels


def _best_cve_cwe_and_score(device: dict, vuln_lookup: dict) -> tuple:
    """디바이스가 가진 여러 CVE 중, CVSS가 가장 높은 것을 대표로 선정 (CVE, CWE, CVSS 반환)"""
    best_cve, best_cwe, best_score = None, None, -1.0
    for iface in device.get("network_interfaces", []):
        for port in iface.get("ports", []):
            for svc in port.get("services", []):
                for cve in svc.get("cve_list", []):
                    v = vuln_lookup.get(cve)
                    if not v:
                        continue
                    metrics = v.get("metrics", {})
                    score = 0.0
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics:
                            score = metrics[key][0]["cvssData"]["baseScore"]
                            break
                    if score > best_score:
                        best_score, best_cve = score, cve
                        cwe = None
                        for w in v.get("weaknesses", []):
                            for desc in w.get("description", []):
                                if desc["value"].startswith("CWE-"):
                                    cwe = desc["value"]
                                    break
                            if cwe:
                                break
                        best_cwe = cwe
    return best_cve, best_cwe, max(best_score, 0.0)


def _privilege_level(device_type: str) -> int:
    if device_type in ("gateway", "server", "database"):
        return 2
    return 1


def load_vulnet_graph(network_path: str) -> nx.DiGraph:
    with open(network_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vuln_lookup = {v["id"]: v for v in data["vulnerabilities"]}
    G = nx.DiGraph()

    for device in data["devices"]:
        node_id = device["hostname"]
        cve, cwe, cvss = _best_cve_cwe_and_score(device, vuln_lookup)

        G.add_node(
            node_id,
            zone=device.get("type", "unknown"),
            cve=cve,
            cwe=cwe,
            vulnerability_score=cvss / 10.0,
            privilege_level=_privilege_level(device.get("type", "")),
            importance=0.5,
            is_compromised=False,
            patch_status=False,
        )

    all_cves = list({G.nodes[n]["cve"] for n in G.nodes if G.nodes[n].get("cve")})
    ext_labels = get_external_labels(all_cves) if all_cves else {}

    for edge in data["edges"]:
        u, v = edge["host_link"]
        if u not in G.nodes or v not in G.nodes:
            continue

        target_cve = G.nodes[v].get("cve")
        target_cvss = G.nodes[v].get("vulnerability_score", 0.5)

        success_prob = 0.3
        if target_cve and target_cve in ext_labels and ext_labels[target_cve]["epss"] is not None:
            success_prob = ext_labels[target_cve]["epss"]

        attack_cost = max(0.05, 1.0 - target_cvss)

        G.add_edge(u, v, attack_cost=attack_cost, success_prob=success_prob, protocol="TCP")

    return G


if __name__ == "__main__":
    G = load_vulnet_graph("data/vulnet_networks/5_5_lan25_uniform_0.25.json")
    print(f"노드 {G.number_of_nodes()}개, 엣지 {G.number_of_edges()}개")
    for n in list(G.nodes)[:3]:
        print(n, G.nodes[n])