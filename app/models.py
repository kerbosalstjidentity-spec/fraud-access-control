"""사기 판정 케이스 모델 — 민감도 4구역. 설계서 §2.2.

한 행(fraud_case) = 한 건의 사기 판정. 구역(Z1~Z4)별로 민감도가 다르며
Z2(PII) 컬럼은 암호화 저장(`*_enc`). 접근 시 정책(§3)이 구역×동작×인증을
평가해 복호화/마스킹 여부를 결정한다.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class FraudCase(Base):
    __tablename__ = "fraud_case"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(20), unique=True, index=True)

    # ── Z1 거래 사실 (G1 내부) ─────────────────────────────
    trans_num: Mapped[str] = mapped_column(String(64), index=True)
    trans_ts: Mapped[datetime] = mapped_column(DateTime)
    amt: Mapped[float] = mapped_column(Float)
    merchant: Mapped[str] = mapped_column(String(128), default="")
    category: Mapped[str] = mapped_column(String(64), default="")
    merch_lat: Mapped[float] = mapped_column(Float, default=0.0)
    merch_long: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Z2 당사자 식별 (G2 PII) 🔒 암호화 저장 ──────────────
    cc_num_enc: Mapped[str] = mapped_column(Text, default="")     # 카드번호(암호화)
    name_enc: Mapped[str] = mapped_column(Text, default="")       # 실명(암호화)
    dob_enc: Mapped[str] = mapped_column(Text, default="")        # 생년월일(암호화)
    address_enc: Mapped[str] = mapped_column(Text, default="")    # 주소(암호화)
    gender: Mapped[str] = mapped_column(String(8), default="")
    job: Mapped[str] = mapped_column(String(128), default="")
    cust_lat: Mapped[float] = mapped_column(Float, default=0.0)
    cust_long: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Z3 FDS 판정 (G3 기밀·모델내부) — S2에서 채움 ────────
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    decision: Mapped[str] = mapped_column(String(16), default="")  # allow/review/block
    triggered_rules: Mapped[str] = mapped_column(Text, default="[]")  # JSON 배열
    shap_top: Mapped[str] = mapped_column(Text, default="[]")         # JSON 배열
    ground_truth: Mapped[int] = mapped_column(Integer, default=0)     # is_fraud (운영선 숨김)

    # ── Z4 조사 기록 (G4 제한·배정자) — S2에서 일부 시드 ────
    assigned_to: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open/closed
    disposition: Mapped[str] = mapped_column(String(32), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
