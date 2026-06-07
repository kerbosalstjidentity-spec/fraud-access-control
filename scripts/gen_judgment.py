r"""S2 — FDS 판정(Z3) + 조사기록(Z4) 생성. 설계서 §5 S2 / 결정로그 D9.

실행:
    .\.venv\Scripts\python.exe -m scripts.gen_judgment

원칙(D9 — 투명 스코어링):
  블랙박스 모델 대신 **룰 기반 가산 스코어링**으로 risk_score 를 만든다.
  → 어떤 룰이 왜 점수를 올렸는지(triggered_rules·shap_top)가 그대로 설명이 된다.
  ground_truth(is_fraud)는 S1 이 이미 보관했고 운영선 숨김(§2.2). 스코어러는
  ground_truth 를 **보지 않고** Z1/Z2 피처만으로 독립 판정한다(현실적 분리).

결정론:
  점수는 데이터에서 결정론적으로 계산되고, 배정은 case_id 해시로 안정 배정.
  → 재실행해도 동일 결과. ETL 과 달리 drop 하지 않고 Z3·Z4 만 UPDATE 한다.
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import SessionLocal  # noqa: E402
from app.models import FraudCase  # noqa: E402

# ── 조사관 풀 (Z4 배정 대상) ──────────────────────────────────
INVESTIGATORS = [f"inv-{100 + k}" for k in range(1, 11)]  # inv-101 .. inv-110

# ── 판정 임계 (risk_score → decision) ────────────────────────
BLOCK_THRESHOLD = 0.70
REVIEW_THRESHOLD = 0.35


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """두 좌표 간 거리(km). 거주지↔가맹점 위치 괴리 룰용."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def score(case: FraudCase) -> tuple[float, list[dict], list[dict]]:
    """룰 기반 가산 스코어링. (risk_score, triggered_rules, shap_top) 반환.

    각 룰은 (id, 설명, 가중치). 발화한 룰의 기여도를 그대로 설명(shap_top)으로 노출.
    """
    rules = []  # (rule_id, label, weight)

    # R1 고액 거래
    if case.amt >= 500:
        rules.append(("R1", "고액거래(>=$500)", 0.30))
    # R2 초고액 (R1 위에 가산)
    if case.amt >= 1000:
        rules.append(("R2", "초고액거래(>=$1000)", 0.20))
    # R3 심야 거래 (00~05시)
    hour = case.trans_ts.hour
    if 0 <= hour <= 5:
        rules.append(("R3", f"심야거래({hour:02d}시)", 0.20))
    # R4 비대면 업종
    if case.category.endswith("_net"):
        rules.append(("R4", f"비대면업종({case.category})", 0.20))
    # R5 원거리 거래 (거주지↔가맹점 > 100km)
    dist = _haversine_km(case.cust_lat, case.cust_long, case.merch_lat, case.merch_long)
    if dist > 100:
        rules.append(("R5", f"원거리거래({dist:.0f}km)", 0.25))

    raw = sum(w for _, _, w in rules)
    risk = min(1.0, round(raw, 4))

    triggered = [{"id": rid, "label": lbl} for rid, lbl, _ in rules]
    # shap_top: 기여도 큰 순 상위 3
    top = sorted(rules, key=lambda x: x[2], reverse=True)[:3]
    shap_top = [{"feature": lbl, "contribution": w} for _, lbl, w in top]
    return risk, triggered, shap_top


def decide(risk: float) -> str:
    if risk >= BLOCK_THRESHOLD:
        return "block"
    if risk >= REVIEW_THRESHOLD:
        return "review"
    return "allow"


def assign(case_id: str) -> str:
    """case_id 해시로 안정적 라운드로빈 배정 (재실행 안정)."""
    h = sum(ord(c) for c in case_id)
    return INVESTIGATORS[h % len(INVESTIGATORS)]


def run() -> None:
    db = SessionLocal()
    try:
        cases = db.query(FraudCase).all()
        print(f"[S2] {len(cases):,} cases 로드")

        counts = {"allow": 0, "review": 0, "block": 0}
        assigned = 0

        for c in cases:
            risk, triggered, shap_top = score(c)
            d = decide(risk)

            # ── Z3 채움 ──
            c.risk_score = risk
            c.decision = d
            c.triggered_rules = json.dumps(triggered, ensure_ascii=False)
            c.shap_top = json.dumps(shap_top, ensure_ascii=False)
            counts[d] += 1

            # ── Z4 채움: review/block 만 조사 대상으로 배정 ──
            if d in ("review", "block"):
                c.assigned_to = assign(c.case_id)
                c.status = "open"
                c.disposition = ""
                c.notes = f"자동 생성 — 트리거 룰: {', '.join(r['id'] for r in triggered) or '없음'}"
                assigned += 1
            else:
                c.assigned_to = ""
                c.status = "open"
                c.disposition = ""
                c.notes = ""

        db.commit()
        print(f"[S2] Z3 판정: allow {counts['allow']} / review {counts['review']} / block {counts['block']}")
        print(f"[S2] Z4 배정: {assigned} cases → {len(INVESTIGATORS)} investigators")
        print("[S2] DONE")
    finally:
        db.close()


if __name__ == "__main__":
    run()
