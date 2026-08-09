"""
CISA 공식 가이드 기반 방어전략 검증 (연구방법론_정리.md 7.2, 7.4절)
"""

CISA_CHECKLIST = {
    "CVE-2021-26855": ["패치", "Test-ProxyLogon", "EOMT"],
    "CVE-2017-0144": ["패치", "SMBv1", "445"],
    "CVE-2020-1472": ["패치", "FullSecureChannelProtection", "레지스트리"],
}


def match_rate(cve: str, generated: dict) -> float:
    """생성된 방어전략(immediate+long_term)이 CISA 체크리스트 키워드를 얼마나 포함하는지 비율"""
    if cve not in CISA_CHECKLIST:
        return None  # 배경 노드 등 정답표 없는 경우

    keywords = CISA_CHECKLIST[cve]
    full_text = " ".join(generated.get("immediate_actions", []) + generated.get("long_term_actions", []) + [generated.get("summary", "")])

    matched = sum(1 for kw in keywords if kw.lower() in full_text.lower())
    return matched / len(keywords)