# data/ 폴더 안내

용량 문제로 원본 데이터는 git에서 제외했습니다. 아래 순서로 직접 생성하세요:

1. `python -m train.train` → data/models/gat_model.pt 생성
2. vuln-net-ag(https://github.com/ds-square/vuln-net-ag)에서 networks.zip 다운로드 → data/vulnet_networks/에 압축 해제
3. API 키 설정 후 `python -m train.run_defense` → defense_strategies.jsonl 생성