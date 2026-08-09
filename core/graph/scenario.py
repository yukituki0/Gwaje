"""
MITRE ATT&CK 기반 6단계 공격 체인 정의 (연구방법론_정리.md 5장)
"""

ATTACK_CHAIN = [
    {"stage": 1, "tactic": "Initial Access", "technique": "T1190", "cve": "CVE-2021-26855"},
    {"stage": 2, "tactic": "Discovery", "technique": "T1046/T1018", "cve": None},
    {"stage": 3, "tactic": "Credential Access", "technique": "T1003/T1555", "cve": None},
    {"stage": 4, "tactic": "Lateral Movement", "technique": "T1021", "cve": "CVE-2017-0144"},
    {"stage": 5, "tactic": "Privilege Escalation", "technique": "T1078", "cve": "CVE-2020-1472"},
    {"stage": 6, "tactic": "Impact", "technique": None, "cve": None},
]
