"""S5 응답 필터 — 정책이 허용한 데이터를 obligations 대로 깎아 출력. 설계서 §4 ④.

S3 정책엔진은 *판단*(permit/deny + obligations)만 한다. 이 모듈은 그 판단대로
실제 DB 레코드를 **복호화 / 마스킹 / 숨김** 처리해 사용자에게 내보내는 *손*이다.

핵심: DB에는 case 가 하나로 저장되지만, 누가(페르소나) 어떤 인증등급으로 보느냐에
따라 같은 필드가 다르게 출력된다 — "DB는 하나, 보이는 건 제각각"(데모 핵심 장면).

obligations(=S3가 Decision 에 실어 보냄)을 그대로 집행:
    decrypt:Z2        → Z2 PII 평문 노출 (unmask)
    mask:Z2           → Z2 PII 마스킹 (앞6뒤4 / 성·이니셜 / 생년 등)
    mask:Z1|Z3|Z4     → 해당 구역 일부 필드 가림 (view.masked)
    hide:ground_truth → is_fraud 정답 라벨 제거 (운영선 항상 숨김)
    require:reason / require:two_person → 절차 의무(인증단계 S4 책임) — 표시엔 영향 없음
"""
from __future__ import annotations

import json

from app import policy as P
from app.crypto import decrypt, mask_card, mask_name
from app.models import FraudCase
from app.policy import Decision

# ── 구역 → 모델 필드 (설계서 §2.2) ───────────────────────────
ZONE_FIELDS: dict[str, list[str]] = {
    P.Z1: ["trans_num", "trans_ts", "amt", "merchant", "category",
           "merch_lat", "merch_long"],
    P.Z2: ["cc_num_enc", "name_enc", "dob_enc", "address_enc",
           "gender", "job", "cust_lat", "cust_long"],
    P.Z3: ["risk_score", "decision", "triggered_rules", "shap_top", "ground_truth"],
    P.Z4: ["assigned_to", "status", "disposition", "notes"],
}


def _mask_dob(dob: str) -> str:
    """생년월일 → 출생연도만 (1968-03-19 → 1968-**-**)."""
    return f"{dob[:4]}-**-**" if len(dob) >= 4 else "****"


def _mask_address(addr: str) -> str:
    """주소 → 시/도만 (상세주소·우편번호 가림)."""
    parts = [p.strip() for p in addr.split(",")]
    return parts[1] if len(parts) >= 2 else "***"


def _view_z2(case: FraudCase, *, full: bool) -> dict:
    """Z2(PII) 출력. full=True 면 평문(unmask), False 면 마스킹."""
    cc = decrypt(case.cc_num_enc)
    name = decrypt(case.name_enc)
    dob = decrypt(case.dob_enc)
    addr = decrypt(case.address_enc)
    if full:
        out = {"cc_num": cc, "name": name, "dob": dob, "address": addr,
               "gender": case.gender, "job": case.job,
               "cust_lat": case.cust_lat, "cust_long": case.cust_long}
    else:
        out = {"cc_num": mask_card(cc), "name": mask_name(name),
               "dob": _mask_dob(dob), "address": _mask_address(addr),
               "gender": case.gender, "job": case.job}  # 정밀 좌표는 가림
    return out


def _view_z1(case: FraudCase, *, masked: bool) -> dict:
    out = {"trans_num": case.trans_num, "trans_ts": str(case.trans_ts),
           "amt": case.amt, "merchant": case.merchant, "category": case.category}
    if not masked:  # view.full 만 정밀 가맹점 좌표 공개
        out["merch_lat"] = case.merch_lat
        out["merch_long"] = case.merch_long
    return out


def _view_z3(case: FraudCase, *, masked: bool, hide_gt: bool) -> dict:
    out = {"risk_score": case.risk_score, "decision": case.decision}
    if not masked:  # view.full 만 모델 내부(룰·설명) 공개
        out["triggered_rules"] = json.loads(case.triggered_rules or "[]")
        out["shap_top"] = json.loads(case.shap_top or "[]")
    if not hide_gt:  # 기본은 숨김; 평가용으로만 노출
        out["ground_truth"] = case.ground_truth
    return out


def _view_z4(case: FraudCase, *, masked: bool) -> dict:
    out = {"status": case.status, "assigned_to": case.assigned_to}
    if not masked:
        out["disposition"] = case.disposition
        out["notes"] = case.notes
    return out


def filter_zone(case: FraudCase, decision: Decision) -> dict:
    """허용된 Decision 에 대해, 해당 구역 데이터를 obligations 대로 가공해 반환.

    permit 이 아니면 데이터를 주지 않는다(거부 표식만). S5는 *정책 통과 후*의
    출력 게이트이므로, deny/step_up 은 여기서 데이터로 새지 않는다.
    """
    if decision.effect != P.PERMIT:
        return {"_zone": decision.zone, "_access": decision.effect,
                "_reason": decision.reason}

    obs = set(decision.obligations)
    zone = decision.zone

    if zone == P.Z2:
        data = _view_z2(case, full="decrypt:Z2" in obs)
    elif zone == P.Z1:
        data = _view_z1(case, masked="mask:Z1" in obs)
    elif zone == P.Z3:
        data = _view_z3(case, masked="mask:Z3" in obs,
                        hide_gt="hide:ground_truth" in obs)
    elif zone == P.Z4:
        data = _view_z4(case, masked="mask:Z4" in obs)
    else:
        data = {}

    return {"_zone": zone, "_access": "permit", "_verb": decision.verb,
            "_level": decision.required_level, "data": data}
