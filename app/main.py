r"""S6 데모 웹 — 페르소나 전환 시 같은 case 가 다르게 보임 + step-up 발동 시연.

실행:
    .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8030 --reload
    → http://localhost:8030

기존 PayWise 프로젝트(8010/8020/3020)와 포트가 겹치지 않게 8030 사용.
한 화면에서 S3(정책)·S5(필터)를 시연한다. S4(OTP)는 미구현이라 '현재 인증등급'을
사용자가 직접 골라 step-up 발동(인증 미달) 장면을 흉내낸다.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import policy as P
from app.crypto import decrypt
from app.db import SessionLocal
from app.filter import filter_zone
from app.models import FraudCase
from app.policy import CaseContext, Principal, evaluate

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="3축 접근통제 데모 (보안 강화)")

# 드롭다운 선택지
PERSONAS = [
    (P.P1_CUSTOMER, "P1 고객(본인)"),
    (P.P2_INVESTIGATOR, "P2 조사관(배정)"),
    (P.P3_MANAGER, "P3 팀장"),
    (P.P4_AUDITOR, "P4 감사"),
    (P.P5_EXTERNAL, "P5 외부/가맹점"),
]
ZONES = [(P.Z1, "Z1 거래사실"), (P.Z2, "Z2 PII"),
         (P.Z3, "Z3 모델판정"), (P.Z4, "Z4 조사기록")]
VERBS = [P.VIEW_MASKED, P.VIEW_FULL, P.UNMASK, P.DECIDE, P.ANNOTATE, P.EXPORT]
LEVELS = [0, 1, 2, 3, 4]


def _default_case_id(db) -> str:
    c = (db.query(FraudCase)
         .filter(FraudCase.decision == "block", FraudCase.assigned_to != "")
         .first()) or db.query(FraudCase).first()
    return c.case_id if c else ""


@app.get("/", response_class=HTMLResponse)
def demo(
    request: Request,
    persona: str = P.P2_INVESTIGATOR,
    case_id: str = "",
    zone: str = P.Z2,
    verb: str = P.UNMASK,
    level: int = 4,
    intruder: bool = False,
):
    db = SessionLocal()
    try:
        if not case_id:
            case_id = _default_case_id(db)
        case = db.query(FraudCase).filter(FraudCase.case_id == case_id).first()

        result = None
        decision = None
        if case is not None:
            owner = decrypt(case.cc_num_enc)        # 데모: 고객 식별자 = 카드번호
            ctx = CaseContext(case_id=case.case_id,
                              owner_id=owner, assigned_to=case.assigned_to,
                              risk_score=case.risk_score or 0.0)
            # 페르소나별 신원 부여 (intruder 면 일부러 권한 없는 신원)
            if persona == P.P1_CUSTOMER:
                sid = "wrong-customer" if intruder else owner
            elif persona == P.P2_INVESTIGATOR:
                sid = "inv-999" if intruder else case.assigned_to
            else:
                sid = persona
            principal = Principal(subject_id=sid, persona=persona, current_level=level)

            decision = evaluate(principal, zone, verb, ctx)
            result = filter_zone(case, decision)

        return templates.TemplateResponse(request=request, name="demo.html", context={
            "personas": PERSONAS, "zones": ZONES, "verbs": VERBS, "levels": LEVELS,
            "sel": {"persona": persona, "case_id": case_id, "zone": zone,
                    "verb": verb, "level": level, "intruder": intruder},
            "case": case,
            "decision": decision,
            "result_json": json.dumps(result, ensure_ascii=False, indent=2,
                                      default=str) if result else None,
        })
    finally:
        db.close()
