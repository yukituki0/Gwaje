"""
FastAPI 앱 진입점. 시작 시 GAT 가중치를 로드(추론 전용, 9.2절), core/app 로직을 호출만 함.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.inference import load_model
from api.routes import router

app = FastAPI(title="Attack Graph Defense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

# web/ 폴더를 정적 파일로 서빙 (index.html 등)
app.mount("/", StaticFiles(directory="web", html=True), name="web")


@app.on_event("startup")
def startup():
    load_model()  # 서버 시작 시 1회만 가중치 로드 (학습 아님, 9.2절)
    print("GAT 모델 로드 완료. 서버 준비됨.")