"""
GAT 오프라인 학습 스크립트 (Colab에서 실행, 연구방법론_정리.md 9.2절)
실행: python core/detection/train.py
결과: data/models/gat_model.pt 저장
"""

def main():
    # TODO: 1) network_builder로 그래프 생성
    # TODO: 2) risk_score로 라벨 생성
    # TODO: 3) PyG Data 형태로 변환
    # TODO: 4) RiskGAT 학습 (Adam, MSE Loss, max epoch 200, early stopping - 계획서 6.4.2.1)
    # TODO: 5) torch.save(model.state_dict(), "data/models/gat_model.pt")
    raise NotImplementedError

if __name__ == "__main__":
    main()
