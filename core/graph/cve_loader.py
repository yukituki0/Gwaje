"""
NVD/CVE 데이터 로딩 및 노드별 배정
- 메인 경로: CVE-2021-26855, CVE-2017-0144, CVE-2020-1472 (5장 확정)
- 배경 노드: NVD에서 검색한 CVE로 배정, 위험도 분포가 골고루 퍼지도록 (8.2절 원칙)
"""

def fetch_cve_info(cve_id: str) -> dict:
    """NVD API에서 CVSS 점수 등 CVE 메타데이터 조회"""
    # TODO: requests로 https://services.nvd.nist.gov/rest/json/cves/2.0 호출
    raise NotImplementedError

def assign_background_cves(n: int) -> list:
    """배경 노드용 CVE n개를 위험도 분포가 균형있게 선정"""
    raise NotImplementedError
