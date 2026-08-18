"""
외부에서 독립적으로 검증된 라벨(EPSS, CISA KEV)을 가져와 학습 라벨로 사용.
지도교수 피드백(inner-loop 문제) 대응: risk_score를 더 이상 우리가 만든
휴리스틱 공식으로 계산하지 않고, FIRST.org EPSS(실제 악용확률)와
CISA KEV(실제 야생 악용 확인 여부)를 그대로 가져와서 씀.
"""
import requests
import json
import os

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_PATH = "data/external_labels_cache.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_epss(cve_ids: list[str]) -> dict:
    """실제 EPSS 점수(0~1, 30일 내 악용 확률)를 CVE별로 가져옴"""
    cve_str = ",".join(cve_ids)
    resp = requests.get(EPSS_API, params={"cve": cve_str}, timeout=15)
    resp.raise_for_status()
    data = resp.json()["data"]
    return {row["cve"]: float(row["epss"]) for row in data}

def fetch_cvss(cve_id: str) -> float | None:
    """NVD에서 실제 CVSS v3.1(없으면 v3.0/v2) 기본 점수를 가져와 0~1로 정규화"""
    resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=15)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return None

    metrics = vulns[0]["cve"].get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics:
            base_score = metrics[key][0]["cvssData"]["baseScore"]
            return base_score / 10.0  # CVSS는 0~10 스케일이므로 0~1로 정규화

    return None

def get_real_cvss_scores(cve_ids: list[str]) -> dict:
    """{cve: cvss_0to1} 형태로 반환 (NVD rate limit 있으니 호출 간 대기 필요)"""
    import time
    scores = {}
    for cve in cve_ids:
        scores[cve] = fetch_cvss(cve)
        time.sleep(1.0)  # 무인증 시 요청 제한(약 5회/30초) 대비
    return scores

def fetch_kev_set() -> set[str]:
    """CISA KEV(실제 야생 악용 확인된 CVE) 목록을 가져와 집합으로 반환"""
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    vulns = resp.json()["vulnerabilities"]
    return {v["cveID"] for v in vulns}


def get_external_labels(cve_ids: list[str], use_cache: bool = True) -> dict:
    """
    {cve: {"epss": float, "in_kev": bool}} 형태로 외부 라벨 반환.
    캐시를 써서 API를 매번 호출하지 않도록 함 (하루 1회 정도면 충분, EPSS는 매일 갱신됨).
    """
    if use_cache and os.path.exists(CACHE_PATH):
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            cached = json.load(f)
        if set(cve_ids).issubset(set(cached.keys())):
            return {k: v for k, v in cached.items() if k in cve_ids}

    epss_scores = fetch_epss(cve_ids)
    kev_set = fetch_kev_set()

    labels = {}
    for cve in cve_ids:
        labels[cve] = {
            "epss": epss_scores.get(cve, None),  # 없으면 EPSS 미등재
            "in_kev": cve in kev_set,
        }

    os.makedirs("data", exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(labels, f, ensure_ascii=False, indent=2)

    return labels


if __name__ == "__main__":
    # 우리 메인 경로 3개 CVE로 테스트
    test_cves = [
        # 기존 메인경로 3개
        "CVE-2021-26855", "CVE-2017-0144", "CVE-2020-1472",
        # 이번에 새로 배정하려는 낮은 EPSS 후보 3개
        "CVE-2024-0646", "CVE-2023-38039", "CVE-2024-21626",
        # 나머지 5개 노드(pc03, pc04, backup_srv, router, switch_backup)용 후보 -- 확인해볼 것들
        "CVE-2021-3156",   # sudo Baron Samedit
        "CVE-2022-22965",  # Spring4Shell
        "CVE-2023-4863",   # libwebp
        "CVE-2022-3602",   # OpenSSL punycode
        "CVE-2021-3449",   # OpenSSL DoS
    ]
    labels = get_external_labels(test_cves, use_cache=False)
    for cve, info in labels.items():
        print(f"{cve}: EPSS={info['epss']}, KEV등재={info['in_kev']}")