# 사기 판정 데이터 3축 접근통제 (보안 레이어)

> **PayWise 플랫폼의 보안 거버넌스 레이어.** 사기 판정 데이터 한 건 안에서도 민감도가 제각각인 점에 착안해,
> **누가(페르소나) · 무엇을(구역) · 어떻게(동작)** 를 칸 단위로 통제하고, 민감한 동작일수록 그 자리에서 인증을 다시 요구한다.

🔗 **상위 플랫폼:** [PayWise (`cap_stone`)](https://github.com/kerbosalstjidentity-spec/cap_stone) — 사기 *탐지* · 자산/소비 분석 · 교육
이 프로젝트는 그 **판정 데이터의 *접근을 거버넌스*** 한다. (탐지 → 거버넌스)

## 라이브 데모
- 이 서비스: https://fraud-access-control.onrender.com
- PayWise(연결): https://cap-stone-neon.vercel.app → 상단 "🔐 사기 접근통제"

## 빠른 실행 (로컬)
```bash
python -m uvicorn app.main:app --port 8030      # http://localhost:8030
# 또는: docker compose up --build
```

## 구성
| 단계 | 파일 | 내용 |
|---|---|---|
| S1 적재 | `scripts/etl_sparkov.py` | Sparkov → 4구역 케이스, Z2(PII) 암호화 |
| S2 판정 | `scripts/gen_judgment.py` | 룰 기반 투명 스코어링 → Z3/Z4 |
| S3 정책 | `app/policy.py` | (페르소나×구역×동작) → permit/deny/step_up + obligations |
| S5 필터 | `app/filter.py` | obligations 집행: 복호화/마스킹/숨김 |
| S6 데모 | `app/main.py` + `templates/` | 웹 데모(8030) |

## 문서
- `docs/NEW_DESIGN_사기판정_접근통제_3축.md` — 설계 정본
- `docs/PERMIT_조합.md` — 데모용 PERMIT 조합표
- `docs/DEMO_RUNBOOK.md` — 시연 런북
- `docs/CHECKPOINT.md` — 구현 진행 현황
