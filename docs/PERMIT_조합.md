# 3축 접근통제 — PERMIT 조합 정리 (데모/발표용)

> 정책 정본: `app/policy.py` 의 `POLICY` 테이블 (= 설계서 §3.5).
> 핵심 원칙: **기본 거부(default-deny).** 아래 표에 *명시된 칸만* 허용되고 나머지는 전부 거부.
> 그래서 "대부분 deny"가 정상 — 허용은 need-to-know로 박힌 것만.

---

## ✅ PERMIT 되는 조합 전체 (페르소나 × 구역 × 동작 → 요구 인증등급)

| 페르소나 | 구역 | 허용 동작 | 요구 인증등급 |
|---|---|---|---|
| **P1 고객(본인)** | Z1 거래사실 | view.masked | L0 |
| | Z1 거래사실 | view.full | L0 |
| | Z2 PII | view.masked | L2 |
| **P2 조사관(배정)** | Z1 거래사실 | view.masked | L0 |
| | Z1 거래사실 | view.full | L2 |
| | Z2 PII | view.masked | L2 |
| | Z2 PII | **unmask** | **L3** |
| | Z3 모델판정 | view.masked | L0 |
| | Z3 모델판정 | view.full | L2 |
| | Z4 조사기록 | view.masked | L2 |
| | Z4 조사기록 | view.full | L2 |
| | Z4 조사기록 | annotate | L2 |
| **P3 팀장** | Z1 거래사실 | view.masked | L0 |
| | Z1 거래사실 | view.full | L2 |
| | Z2 PII | view.masked | L2 |
| | Z2 PII | unmask | L3 |
| | Z3 모델판정 | view.masked | L2 |
| | Z3 모델판정 | view.full | L2 |
| | Z3 모델판정 | **decide** | **L4** |
| | Z4 조사기록 | view.masked | L2 |
| | Z4 조사기록 | view.full | L2 |
| **P4 감사** | Z1 거래사실 | view.masked | L2 |
| | Z1 거래사실 | export | L3 |
| | Z3 모델판정 | view.masked | L2 |
| | Z3 모델판정 | view.full | L2 |
| | Z3 모델판정 | export | L3 |
| | Z4 조사기록 | view.masked | L2 |
| | Z4 조사기록 | view.full | L2 |
| | Z4 조사기록 | export | L3 |
| **P5 외부/가맹점** | Z1 거래사실 | view.masked | L1 |

> **위 표에 없는 모든 조합 = 거부(❌).**
> 대표적 거부 칸: P1의 Z3·Z4 / P4의 Z2(PII는 메타만) / P5의 Z2·Z3·Z4.

---

## ⚠️ PERMIT 이 안 나오는 3가지 이유

1. **그 칸에 그 동작이 없음** → `deny`
   - 예: `P2 / Z2 / decide` → Z2엔 view.masked·unmask만 있음 → 거부
2. **현재 인증등급 < 요구 등급** → `step_up`(거부 아님)
   - 예: `P2 / Z2 / unmask`는 L3 필요. 현재 L0이면 → 🔒 STEP-UP (OTP 요구)
3. **침입자(소유/배정 위반)** → `deny`
   - P1은 본인 case, P2는 배정된 case 여야 함. '침입자' 체크 시 거부

---

## 🎬 발표용 "확실한 PERMIT" 빠른 조합

| 설정 (persona / zone / verb / level) | 결과 | 보여줄 메시지 |
|---|---|---|
| `P2 / Z2 / unmask / L4` | ✅ 카드번호 **전체** | 배정 조사관 + 충분한 인증 → PII 평문 |
| `P1 / Z2 / view.masked / L4` | ✅ `418981***4741` | 같은 카드인데 고객은 **마스킹**만 |
| `P1 / Z1 / view.full / L0` | ✅ 본인 거래 전체 | 본인 거래는 기본 인증으로 |
| `P3 / Z3 / decide / L4` | ✅ 차단 결정 | **팀장만** 최고위험 동작(L4) |
| `P4 / Z3 / view.full / L4` | ✅ 모델판정(ground_truth 숨김) | 감사는 판정 보되 정답라벨·PII는 ❌ |

### 대비용 "의도된 거부/단계인증" 장면
| 설정 | 결과 | 메시지 |
|---|---|---|
| `P4 / Z2 / unmask / L4` | ⛔ DENY | 감사는 PII 접근 자체 불가(메타만) |
| `P2 / Z2 / unmask / L0` | 🔒 STEP-UP | 민감 동작은 그 자리에서 OTP 재인증 |
| `P2 / Z2 / unmask / L4` + 침입자 ✅ | ⛔ DENY | 배정 안 된 케이스는 못 봄 |

---

## 한 줄 요약 (발표 멘트)
> **"대부분 거부되는 게 정상입니다 — 기본 거부 원칙이라 허용은 매트릭스에 명시된 칸만 열립니다.
> 게다가 같은 칸이라도 민감할수록 더 높은 인증등급(L3·L4)을 그 자리에서 다시 요구합니다."**
