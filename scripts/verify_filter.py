r"""S5 응답 필터 검증/데모 — 같은 case 를 페르소나별로 다르게 출력.

실행:  .\.venv\Scripts\python.exe -m scripts.verify_filter

DB 에서 실제 case 한 건을 꺼내, (페르소나 × 구역 × 동작)을 S3 정책으로 평가하고
S5 필터로 가공해 출력한다. "DB는 하나, 보이는 건 제각각"을 눈으로 확인.

주의: 인증등급(current_level)은 S4(OTP) 미구현이라 '이미 충족' 으로 가정한다.
      여기서 검증하는 것은 *필터 출력 차등* 이지 step-up 발동이 아니다.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import policy as P  # noqa: E402
from app.crypto import decrypt  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.filter import filter_zone  # noqa: E402
from app.models import FraudCase  # noqa: E402
from app.policy import CaseContext, Principal, evaluate  # noqa: E402


def show(title: str, principal: Principal, zone: str, verb: str, ctx: CaseContext):
    d = evaluate(principal, zone, verb, ctx)
    out = filter_zone(  # permit 일 때만 데이터, 아니면 거부표식
        SHOW_CASE, d) if d.effect == P.PERMIT else {
            "_zone": zone, "_access": d.effect, "_reason": d.reason}
    print(f"\n● {title}  [{zone}/{verb}]")
    print("  " + json.dumps(out, ensure_ascii=False, default=str))


def run() -> None:
    global SHOW_CASE
    db = SessionLocal()
    try:
        # review/block 이면서 배정된 흥미로운 case 한 건 선택
        SHOW_CASE = (db.query(FraudCase)
                     .filter(FraudCase.decision == "block",
                             FraudCase.assigned_to != "")
                     .first())
        if SHOW_CASE is None:
            print("케이스 없음 — 먼저 gen_judgment 실행 필요")
            return

        owner = decrypt(SHOW_CASE.cc_num_enc)        # 데모: 고객 식별자 = 카드번호
        assignee = SHOW_CASE.assigned_to
        ctx = CaseContext(case_id=SHOW_CASE.case_id,
                          owner_id=owner, assigned_to=assignee)

        print("=" * 64)
        print(f"대상 case = {SHOW_CASE.case_id}  (decision={SHOW_CASE.decision}, "
              f"assigned={assignee})")
        print("=" * 64)

        # 인증 충족 가정 (S4 미구현)
        p1 = Principal("본인고객", P.P1_CUSTOMER, current_level=P.L4)
        p1.subject_id = owner  # 본인이어야 소유 통과
        p2 = Principal(assignee, P.P2_INVESTIGATOR, current_level=P.L4)
        p3 = Principal("팀장", P.P3_MANAGER, current_level=P.L4)
        p4 = Principal("감사", P.P4_AUDITOR, current_level=P.L4)

        # ── 같은 Z2(PII)를 페르소나별로 ──
        print("\n[Z2 PII — 같은 카드번호가 누구냐에 따라 다르게 보임]")
        show("P1 고객(본인) — 마스킹만", p1, P.Z2, P.VIEW_MASKED, ctx)
        show("P2 조사관(배정) — unmask 전체", p2, P.Z2, P.UNMASK, ctx)
        show("P4 감사 — Z2 접근 자체 거부", p4, P.Z2, P.UNMASK, ctx)

        # ── 같은 Z3(모델판정) ──
        print("\n[Z3 모델판정 — 깊이 차등 + ground_truth 숨김]")
        show("P2 조사관 — view.full (룰·설명 공개)", p2, P.Z3, P.VIEW_FULL, ctx)
        show("P3 팀장 — view.masked (판정만)", p3, P.Z3, P.VIEW_MASKED, ctx)

        # ── 소유/배정 위반 ──
        print("\n[소유/배정 위반 — 정책에서 차단되어 필터까지 못 감]")
        intruder = Principal("타인조사관", P.P2_INVESTIGATOR, current_level=P.L4)
        intruder.subject_id = "inv-999"
        show("배정 안 된 조사관 — Z2 unmask 시도", intruder, P.Z2, P.UNMASK, ctx)

        print("\n" + "=" * 64)
        print("확인: 동일 case_id 가 페르소나별로 복호화/마스킹/거부로 다르게 출력됨")
    finally:
        db.close()


if __name__ == "__main__":
    run()
