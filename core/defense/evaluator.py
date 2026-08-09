"""
CISA 공식 가이드 기반 방어전략 검증 (연구방법론_정리.md 7.2, 7.4절)
"""

CISA_CHECKLIST = {
    "CVE-2021-26855": ["패치", "Test-ProxyLogon", "EOMT"],
    "CVE-2017-0144": ["패치", "SMBv1 비활성화", "포트 445 차단"],
    "CVE-2020-1472": ["패치", "FullSecureChannelProtection"],
}

def match_rate(cve: str, generated_text: str) -> float:
    """생성된 방어전략이 공식 체크리스트와 얼마나 겹치는지 비율 반환"""
    raise NotImplementedError
