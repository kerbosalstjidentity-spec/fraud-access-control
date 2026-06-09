"""S3 정책 엔진 — 3축(페르소나 × 구역 × 동작) → permit / deny / step_up(Lₙ).

설계서 §3.5 정책 정본 + §4 평가 흐름의 ②③⑤ 단계를 구현한다.

핵심(D5): 출력은 단순 허용/거부가 아니라 **결정 객체**다.
    Decision(effect, required_level, obligations, ...)
  - `required_level`  → S4 인증 사다리(OTP)가 반응하는 필드
  - `obligations`     → S5 응답 필터(복호화/마스킹/숨김)가 반응하는 필드
  - `reason`/감사필드 → §4 ⑤ 감사 로그
이렇게 필드를 분리해 두면 S4/S5/S6은 S3를 고치지 않고 *끼워* 붙는다.

이 모듈은 순수 함수다 — DB·crypto·HTTP에 의존하지 않는다.
소유/배정 판단에 필요한 정보는 호출자가 `CaseContext`로 주입한다(테스트 용이).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── 축 ① 페르소나 (설계서 §3.1) ──────────────────────────────
P1_CUSTOMER = "P1"      # 고객 — 본인 case 만
P2_INVESTIGATOR = "P2"  # 조사관 — 배정 case 만
P3_MANAGER = "P3"       # 팀장
P4_AUDITOR = "P4"       # 감사
P5_EXTERNAL = "P5"      # 외부/가맹점

# ── 축 ② 구역 (설계서 §2.2 / §3.2) ───────────────────────────
Z1 = "Z1"  # 거래 사실
Z2 = "Z2"  # 당사자 식별 (PII, 암호화)
Z3 = "Z3"  # FDS 판정 (모델 내부)
Z4 = "Z4"  # 조사 기록

# ── 축 ③ 동작 verb (설계서 §3.3) ─────────────────────────────
VIEW_MASKED = "view.masked"
VIEW_FULL = "view.full"
UNMASK = "unmask"
DECIDE = "decide"
ANNOTATE = "annotate"
EXPORT = "export"

# ── 인증 강도 사다리 (설계서 §3.4) ───────────────────────────
L0, L1, L2, L3, L4 = 0, 1, 2, 3, 4

# ── effect ───────────────────────────────────────────────────
PERMIT = "permit"
DENY = "deny"
STEP_UP = "step_up"

# ── 정책 정본 (설계서 §3.5) ───────────────────────────────────
# (페르소나, 구역) → {허용 verb: 요구 인증등급}.
# 표에 없는 (페르소나×구역×verb) 조합은 **기본 거부**(default-deny, §1.5).
POLICY: dict[tuple[str, str], dict[str, int]] = {
    # P1 고객(본인) — Z1 본인거래 전체조회, Z2 마스킹만, Z3·Z4 ❌
    (P1_CUSTOMER, Z1): {VIEW_MASKED: L0, VIEW_FULL: L0},
    (P1_CUSTOMER, Z2): {VIEW_MASKED: L2},

    # P2 조사관(배정) — Z2 unmask(L3), Z4 annotate, Z1·Z3 전체조회
    (P2_INVESTIGATOR, Z1): {VIEW_MASKED: L0, VIEW_FULL: L2},
    (P2_INVESTIGATOR, Z2): {VIEW_MASKED: L2, UNMASK: L3},
    (P2_INVESTIGATOR, Z3): {VIEW_MASKED: L0, VIEW_FULL: L2},
    (P2_INVESTIGATOR, Z4): {VIEW_MASKED: L2, VIEW_FULL: L2, ANNOTATE: L2},

    # P3 팀장 — Z3 decide(L4, 최고위험), Z2 unmask, Z1·Z4 전체조회
    (P3_MANAGER, Z1): {VIEW_MASKED: L0, VIEW_FULL: L2},
    (P3_MANAGER, Z2): {VIEW_MASKED: L2, UNMASK: L3},
    (P3_MANAGER, Z3): {VIEW_MASKED: L2, VIEW_FULL: L2, DECIDE: L4},
    (P3_MANAGER, Z4): {VIEW_MASKED: L2, VIEW_FULL: L2},

    # P4 감사 — Z1 마스킹만, Z2 ❌(메타만), Z3·Z4 전체조회(읽기), export
    (P4_AUDITOR, Z1): {VIEW_MASKED: L2, EXPORT: L3},
    (P4_AUDITOR, Z3): {VIEW_MASKED: L2, VIEW_FULL: L2, EXPORT: L3},
    (P4_AUDITOR, Z4): {VIEW_MASKED: L2, VIEW_FULL: L2, EXPORT: L3},

    # P5 외부/가맹점 — Z1 마스킹만(약한 step-up), 나머지 ❌
    (P5_EXTERNAL, Z1): {VIEW_MASKED: L1},
}

# ── 위험 적응형 가산 (결정 D10) ───────────────────────────────
# 매트릭스가 정한 '기본' 요구등급 위에, 대상 case 가 고위험이면 **민감 동작에
# 한해** 인증등급을 1단계 올린다 (floor=매트릭스, 절대 내리지 않음).
# → risk_score 가 '보호 대상 데이터'이자 '인증 강도 가산 신호'로 쓰이는 지점.
#   정적 매트릭스(≈RBAC) → 위험 인식(risk-adaptive) ABAC 로의 한 걸음.
RISK_ADAPTIVE_VERBS: frozenset[str] = frozenset({UNMASK, DECIDE, EXPORT})
RISK_ADAPTIVE_THRESHOLD = 0.70  # gen_judgment 의 BLOCK 임계(0.70)와 정렬


def _adaptive_required(base: int, verb: str, risk_score: float) -> tuple[int, bool]:
    """매트릭스 기본등급(base) → 고위험·민감동작이면 +1 (상한 L4).

    반환 (요구등급, 가산여부). 비민감 동작이거나 저위험이면 base 그대로.
    """
    if verb in RISK_ADAPTIVE_VERBS and risk_score >= RISK_ADAPTIVE_THRESHOLD:
        bumped = min(L4, base + 1)
        return bumped, bumped > base
    return base, False


@dataclass
class Principal:
    """요청 주체 — 신원 + 페르소나 속성 (설계서 §3.1)."""
    subject_id: str
    persona: str
    authenticated: bool = True
    current_level: int = L0  # 현재 보유한 인증 강도 (step-up 토큰 충족 시 상승)


@dataclass
class CaseContext:
    """정책 판단에 필요한 case 측 속성 (소유/배정).

    순수성 유지를 위해 호출자가 주입한다. 실제 운영(S6)에선
    owner_id 는 복호화된 cc_num 등에서 유도한다.
    """
    case_id: str
    owner_id: str = ""      # 이 case 당사자(고객) 식별자 — P1 소유 검사
    assigned_to: str = ""   # 배정 조사관 — P2 배정 검사
    risk_score: float = 0.0  # 이 case 의 Z3 위험도 — 위험 적응형 가산(D10) 입력


@dataclass
class Decision:
    """정책 평가 결과 — S4/S5/S6이 각자 다른 필드에 반응한다(D5)."""
    effect: str                       # permit | deny | step_up
    required_level: int               # L0..L4 — S4가 반응
    obligations: list[str] = field(default_factory=list)  # S5가 반응
    reason: str = ""                  # 감사 로그용
    # 감사 컨텍스트 (§4 ⑤)
    persona: str = ""
    zone: str = ""
    verb: str = ""
    case_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.effect == PERMIT


def _build_obligations(zone: str, verb: str, level: int) -> list[str]:
    """결정에 수반되는 의무 — S5 응답 필터가 집행한다(§4 ④).

    표시 의무(zone 단위 복호화/마스킹/숨김) + 절차 의무(사유/2인 승인).
    """
    obs: list[str] = []

    # 표시 의무 — verb 가 결정하는 출력 깊이
    if zone == Z2:
        if verb == UNMASK:
            obs.append("decrypt:Z2")          # 평문 PII 노출
        elif verb == VIEW_MASKED:
            obs.append("mask:Z2")             # 앞6뒤4 / 성·이니셜
    if zone == Z3:
        obs.append("hide:ground_truth")        # is_fraud 는 운영선 항상 숨김
    if verb == VIEW_MASKED and zone in (Z1, Z3, Z4):
        obs.append(f"mask:{zone}")

    # 절차 의무 — 인증 강도가 결정 (§3.4)
    if level >= L3:
        obs.append("require:reason")           # L3: 사유 입력 → 감사 결합
    if level >= L4:
        obs.append("require:two_person")       # L4: 2인 승인(4-eye)

    return obs


def _ownership_ok(principal: Principal, ctx: CaseContext) -> bool:
    """① 소유/배정 검사 (§4 ①). P1=본인, P2=배정. 나머지는 제약 없음."""
    if principal.persona == P1_CUSTOMER:
        return bool(ctx.owner_id) and ctx.owner_id == principal.subject_id
    if principal.persona == P2_INVESTIGATOR:
        return bool(ctx.assigned_to) and ctx.assigned_to == principal.subject_id
    return True


def evaluate(
    principal: Principal,
    zone: str,
    verb: str,
    ctx: CaseContext,
) -> Decision:
    """한 요청을 평가한다 (설계서 §4 평가 흐름 ⓪→②).

    반환은 항상 결정 객체. step_up 일 때도 required_level·obligations 를
    채워 보내, S4(인증)·S5(필터)가 동일 객체로 후속 처리할 수 있게 한다.
    """
    audit = dict(persona=principal.persona, zone=zone, verb=verb, case_id=ctx.case_id)

    # ⓪ 신원 검증 (§4 ⓪) — 없으면 즉시 거부
    if principal is None or not principal.authenticated:
        return Decision(DENY, L0, reason="no identity", **audit)

    # ② 매트릭스 조회 — 기본 거부 (§1.5 default-deny)
    cell = POLICY.get((principal.persona, zone))
    if cell is None or verb not in cell:
        return Decision(DENY, L0, reason="default-deny: no matrix entry", **audit)

    # ① 소유/배정 검사 (§4 ①)
    if not _ownership_ok(principal, ctx):
        return Decision(DENY, L0, reason="ownership/assignment failed", **audit)

    required = cell[verb]
    # 위험 적응형 가산 (D10) — 매트릭스 기본등급 위로만 올림(고위험·민감동작)
    required, bumped = _adaptive_required(required, verb, ctx.risk_score)
    obligations = _build_obligations(zone, verb, required)
    risk_note = f" · 위험가산+1(risk={ctx.risk_score:.2f})" if bumped else ""

    # ③ 인증 강도 충족? 미달이면 step-up 발동 (§4 ③)
    if principal.current_level < required:
        return Decision(STEP_UP, required, obligations,
                        reason=f"step-up required L{required}{risk_note}", **audit)

    # 충족 → 허용 (§4 ④ 데이터 반환은 S5가 obligations 보고 집행)
    return Decision(PERMIT, required, obligations, reason=f"permit{risk_note}", **audit)
