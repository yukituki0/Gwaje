# 딥러닝 기반 동적 공격 그래프 경로 분석 및 방어 전략 시각화 연구

전체 방법론은 `연구방법론_정리.md` 참고.

## 구조
- `core/` : 웹과 무관한 순수 로직 (그래프 생성, 탐지, 방어전략 생성)
- `data/` : 그래프 스냅샷, 학습된 가중치(.pt), 방어전략(.jsonl)
- `api/` : FastAPI 기반 웹 연동 계층 (core를 호출만 함)
- `web/` : 프론트엔드 시각화
- `notebooks/` : Colab 등에서 실험/학습용

## 실행 순서 (연구방법론_정리.md 10장 참고)
1. `core/graph/network_builder.py` - 그래프 생성
2. `core/graph/cve_loader.py` - CVE 데이터 배정
3. `core/detection/dijkstra.py` - 경로 탐색
4. `core/detection/risk_score.py` - 라벨 생성
5. `core/detection/train.py` - GAT 학습 (Colab 권장, GPU 필요)
6. `core/defense/` - LLM 방어전략 생성
7. `api/`, `web/` - 시각화

## 학습 환경 (Colab)
`notebooks/colab_train_starter.ipynb` 참고 — GitHub clone, 의존성 설치, Drive 마운트, 학습, 가중치 저장까지 포함.