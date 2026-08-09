# 딥러닝 기반 동적 공격 그래프 경로 분석 및 방어 전략 시각화 연구

전체 연구 방법론(이론적 배경, 설계 근거, 선행연구)은 `연구방법론_정리.md` 참고.
이 문서는 **코드가 실제로 어떻게 나뉘어 있고, 뭘 실행하면 되는지**를 위한 실행 가이드.

---

## 핵심 원칙: 3개의 세계

이 프로젝트는 "누가 언제 실행하는가"에 따라 코드가 3개 영역으로 명확히 나뉘어 있음.

| 영역 | 실행 주체 | 특징 |
|---|---|---|
| `colab/` | **Colab (GPU)** | 무거운 연산 (GAT 학습, LLM 방어전략 생성). 결과만 파일로 저장하고 끝. 앱과 무관. |
| `core/` | 양쪽 공용 | 그래프 정의, 알고리즘 로직. Colab과 앱(로컬) 둘 다 이 코드를 가져다 씀. |
| `app/`, `api/`, `web/` | **로컬/서버 (웹앱)** | 실제 사용자가 만지는 부분. **학습이나 LLM 즉석 호출을 절대 하지 않음** — Colab이 미리 만들어둔 결과(가중치, 방어전략 파일)를 읽기만 함. |

이렇게 나눈 이유: 비전공자가 쓸 웹앱은 무거운 AI 연산 없이 **가볍고 안정적으로** 돌아가야 하기 때문. 무거운 건 Colab이 미리 다 끝내둠.

---

## 폴더별 상세

### `colab/` — Colab에서만 실행 (로컬에서 실행 금지, 무겁고 느림)

| 파일 | 역할 | 실행 명령어 |
|---|---|---|
| `train.py` | GAT 모델 학습. 여러 그래프 인스턴스로 학습 후 `data/models/gat_model.pt` 저장 | `python -m colab.train` |
| `evaluate.py` | 학습된 GAT가 실제로 위험 노드를 잘 잡는지 검증 (스피어만 상관계수) | `python -m colab.evaluate` |
| `llm_client.py` | LLM 호출 함수 (`generate_defense`). 모델 교체 가능하게 감싸둠 | (직접 실행 안 함, run_defense.py가 사용) |
| `run_defense.py` | 위험 노드마다 방어전략 생성 → `data/defense_strategies.jsonl` 저장 | `python -m colab.run_defense` |

### `core/` — 공용 로직 (Colab과 앱 둘 다 사용)

| 파일 | 역할 | 누가 쓰나 |
|---|---|---|
| `graph/network_builder.py` | 18노드 그래프 생성, 다중 인스턴스 생성 | Colab(학습용), 앱(현재 그래프 상태) |
| `detection/dijkstra.py` | 최적 공격경로 탐색 | Colab, 앱 둘 다 |
| `detection/gat_model.py` | GAT 모델 구조 정의 (클래스만, 가중치 없음) | Colab(학습 시), 앱(추론 시 이 틀에 가중치만 로드) |
| `detection/risk_score.py` | PageRank+Dijkstra 공식으로 **학습용 정답 라벨** 생성 | **Colab 전용** — 앱은 이 무거운 공식을 다시 계산하지 않고 GAT 예측값만 사용 |
| `defense/prompt_builder.py` | LLM 프롬프트 생성 (CISA 가이드 포함) | **Colab 전용** (run_defense.py가 사용) |
| `defense/evaluator.py` | 생성된 방어전략을 CISA 체크리스트와 대조 | **Colab 전용** |

### `app/` — 웹앱이 실제로 사용하는 코드 (가볍고 빠름, 학습/LLM 없음)

| 파일 | 역할 |
|---|---|
| `inference.py` | `gat_model.pt` 로드 후 그래프를 넣으면 위험도만 계산 (학습 없음) |
| `defense_lookup.py` | `defense_strategies.jsonl`에서 노드별 방어전략을 찾아서 반환 (LLM 호출 없음) |
| `pipeline.py` | 위 둘 + Dijkstra를 묶어서 "그래프 → 경로+위험도+방어전략" 한번에 반환하는 메인 진입점 |

### `api/`, `web/` — 서버와 화면

| 파일 | 역할 |
|---|---|
| `api/main.py` | FastAPI 서버 시작점. 시작 시 GAT 가중치 1회 로드 |
| `api/routes.py` | `/api/graph`, `/api/analysis` 엔드포인트. `app/pipeline.py`를 호출만 함 |
| `web/index.html` | 그래프 시각화 화면 (위험도 색상, 공격경로 강조, 클릭 시 방어전략 표시) |

### `data/` — 결과물 저장 (git에는 안 올라감, 직접 옮겨야 함)

| 경로 | 내용 | 어떻게 채우나 |
|---|---|---|
| `models/gat_model.pt` | 학습된 GAT 가중치 | Colab에서 `colab/train.py` 실행 후 다운로드해서 이 경로에 넣기 |
| `defense_strategies.jsonl` | 사전생성된 방어전략 | Colab에서 `colab/run_defense.py` 실행 후 다운로드해서 이 경로에 넣기 |
| `graphs/` | (현재 미사용) | 향후 동적 그래프 타임스텝 스냅샷을 저장할 자리로 비워둠 |

---

## 전체 실행 순서

### A. Colab에서 (최초 1회 또는 그래프/모델을 바꿀 때마다)

```bash
python -m colab.train          # GAT 학습 -> data/models/gat_model.pt
python -m colab.evaluate       # 검증 (선택)
python -m colab.run_defense    # 방어전략 생성 -> data/defense_strategies.jsonl
```
생성된 `gat_model.pt`, `defense_strategies.jsonl`을 로컬 `data/`에 다운로드.

### B. 로컬에서 (웹앱 실행, 매번)

```bash
python -m uvicorn api.main:app --reload
```
브라우저에서 `http://127.0.0.1:8000` 접속.

---

## 지금 상태 (진행 체크리스트)

- [x] 그래프 생성, Dijkstra, risk_score, GAT 학습 — 완료, 검증됨 (스피어만 0.98)
- [x] 웹 시각화 (위험도 색상/공격경로 강조/클릭 시 방어전략) — 완료
- [ ] LLM 품질 개선 (현재 Qwen2.5-1.5B 소형모델 → 언어 혼입, CISA 일치율 편차 문제 있음. Claude API 전환 검토 중)
- [ ] 보고서 작성

## 알려진 한계 (정직하게 기록)

- GAT 학습 데이터는 단일 MITRE ATT&CK 체인의 변형 30개뿐 — 이 시나리오 범위 내 일반화만 검증됨 (8.3절)
- 로컬 소형 LLM(Qwen2.5-1.5B)은 CISA 가이드 반영이 불안정하고 간헐적으로 언어가 섞임