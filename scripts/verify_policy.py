r"""S3 정책 엔진 검증 — 설계서 §3.5 정책 정본과 일치하는지 시나리오로 확인.

실행:  .\.venv\Scripts\python.exe -m scripts.verify_policy
모든 시나리오 PASS 면 종료코드 0.
"""
from __future__ import annotations

import sys

from app import policy as P
from app.policy import CaseContext, Principal, evaluate

OWNER = "cust-007"       # 이 case 의 당사자
INVESTIGATOR = "inv-101"  # 이 case 의 배정 조사관
CTX = CaseContext(case_id="C-0001", owner_id=OWNER, assigned_to=INVESTIGATOR)


def princ(persona: str, sid: str = "u", level: int = P.L4) -> Principal:
    """기본은 인증강도 L4(충분) — effect/level 자체를 검증하기 위함."""
    return Principal(subject_id=sid, persona=persona, current_level=level)


# (이름, principal, zone, verb, 기대 effect, 기대 required_level)
SCENARIOS = [
    # ── §3.5 매트릭스 허용 칸 (요구 인증등급 검증) ──────────────
    ("P1 본인 Z1 view.full = L0",
     princ(P.P1_CUSTOMER, OWNER), P.Z1, P.VIEW_FULL, P.PERMIT, P.L0),
    ("P1 본인 Z2 view.masked = L2",
     princ(P.P1_CUSTOMER, OWNER), P.Z2, P.VIEW_MASKED, P.PERMIT, P.L2),
    ("P2 배정 Z1 view.full = L2",
     princ(P.P2_INVESTIGATOR, INVESTIGATOR), P.Z1, P.VIEW_FULL, P.PERMIT, P.L2),
    ("P2 배정 Z2 unmask = L3",
     princ(P.P2_INVESTIGATOR, INVESTIGATOR), P.Z2, P.UNMASK, P.PERMIT, P.L3),
    ("P2 배정 Z3 view.full = L2",
     princ(P.P2_INVESTIGATOR, INVESTIGATOR), P.Z3, P.VIEW_FULL, P.PERMIT, P.L2),
    ("P2 배정 Z4 annotate = L2",
     princ(P.P2_INVESTIGATOR, INVESTIGATOR), P.Z4, P.ANNOTATE, P.PERMIT, P.L2),
    ("P3 팀장 Z3 decide = L4",
     princ(P.P3_MANAGER), P.Z3, P.DECIDE, P.PERMIT, P.L4),
    ("P3 팀장 Z2 unmask = L3",
     princ(P.P3_MANAGER), P.Z2, P.UNMASK, P.PERMIT, P.L3),
    ("P4 감사 Z1 view.masked = L2",
     princ(P.P4_AUDITOR), P.Z1, P.VIEW_MASKED, P.PERMIT, P.L2),
    ("P4 감사 Z3 view.full = L2",
     princ(P.P4_AUDITOR), P.Z3, P.VIEW_FULL, P.PERMIT, P.L2),
    ("P5 외부 Z1 view.masked = L1",
     princ(P.P5_EXTERNAL), P.Z1, P.VIEW_MASKED, P.PERMIT, P.L1),

    # ── 기본 거부 칸 (❌) ────────────────────────────────────
    ("P1 Z3 = 거부(default-deny)",
     princ(P.P1_CUSTOMER, OWNER), P.Z3, P.VIEW_MASKED, P.DENY, P.L0),
    ("P4 감사 Z2 = 거부(메타만)",
     princ(P.P4_AUDITOR), P.Z2, P.UNMASK, P.DENY, P.L0),
    ("P5 외부 Z3 = 거부",
     princ(P.P5_EXTERNAL), P.Z3, P.VIEW_FULL, P.DENY, P.L0),

    # ── 소유/배정 위반 ──────────────────────────────────────
    ("P1 타인 case Z1 = 거부(소유 아님)",
     princ(P.P1_CUSTOMER, "cust-999"), P.Z1, P.VIEW_FULL, P.DENY, P.L0),
    ("P2 미배정 case Z3 = 거부(배정 아님)",
     princ(P.P2_INVESTIGATOR, "inv-999"), P.Z3, P.VIEW_FULL, P.DENY, P.L0),

    # ── step-up 발동 (인증강도 미달) ─────────────────────────
    ("P2 Z2 unmask 인데 L0 보유 → step_up(L3)",
     princ(P.P2_INVESTIGATOR, INVESTIGATOR, level=P.L0), P.Z2, P.UNMASK, P.STEP_UP, P.L3),
    ("P3 Z3 decide 인데 L2 보유 → step_up(L4)",
     princ(P.P3_MANAGER, level=P.L2), P.Z3, P.DECIDE, P.STEP_UP, P.L4),
]


def main() -> int:
    passed = failed = 0
    for name, p, zone, verb, exp_effect, exp_level in SCENARIOS:
        d = evaluate(p, zone, verb, CTX)
        ok = d.effect == exp_effect and (
            exp_effect == P.DENY or d.required_level == exp_level)
        tag = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        obs = ",".join(d.obligations) if d.obligations else "-"
        print(f"[{tag}] {name}")
        print(f"       -> effect={d.effect} L{d.required_level} obs=[{obs}] ({d.reason})")
        if not ok:
            print(f"       !! expected effect={exp_effect} L{exp_level}")

    print(f"\n총 {passed+failed}건: PASS {passed} / FAIL {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
