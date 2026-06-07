"""전역 설정 — 보안 강화 기반값 포함.

데모용 기본 키를 코드에 두되, 운영에선 환경변수로 덮어쓴다.
(설계서 §1.5 저장 암호화 / §3.4 OTP 토큰)
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PW_", env_file=".env", extra="ignore")

    # DB
    db_path: str = str(BASE_DIR / "data" / "fraud_case.db")

    # Z2(PII) 컬럼 암호화 키 (Fernet, base64 32B). 운영선 반드시 교체.
    # 데모 기본키 — 절대 운영 사용 금지.
    fernet_key: str = "oFh0gFB6vGLPm8eMW6jZ8Fm3vT1ujM_y4_Kb66hHm1c="

    # step-up 토큰 서명/만료 (보안 강화: 단명·동작 한정)
    stepup_secret: str = "demo-stepup-secret-change-in-prod"
    stepup_ttl_seconds: int = 120  # 토큰 유효 2분

    # ETL 적재 표본 크기 (전체 130만 행 중)
    etl_sample_size: int = 5000
    etl_fraud_oversample: bool = True  # 사기 케이스 비율 끌어올려 데모 가시성↑

    sparkov_train_csv: str = str(BASE_DIR / "archive" / "fraudTrain.csv")


settings = Settings()
