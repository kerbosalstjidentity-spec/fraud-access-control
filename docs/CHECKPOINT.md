# 구현 체크포인트 — 2026-05-31

> 작업 폴더: `C:\Users\alstj\Downloads\캡스톤_프로젝트_후속\`
> 설계 정본: `docs/NEW_DESIGN_사기판정_접근통제_3축.md`
> 스택: FastAPI + SQLAlchemy + SQLite + pyotp(OTP) + cryptography/Fernet(Z2 암호화), Python 3.14 (venv=`.venv`)

---

## 진행 현황

| 단계 | 상태 | 산출물 | 검증 |
|---|---|---|---|
| **S1 데이터 적재** | ✅ 완료 | `scripts/etl_sparkov.py`, `app/models.py`, `app/crypto.py`, `app/db.py`, `app/config.py` | 5,000건(사기 2,500) → `data/fraud_case.db`. Z2 암호화 저장→복호화→마스킹 동작 확인 |
| **S2 판정 생성** | ✅ 완료(재구현 2026-06-01) | `scripts/gen_judgment.py` | Z3 채움(allow 3,463/review 1,020/block 517) + Z4 배정 1,537. 룰 R1~R5 기반 투명 스코어링(D9). block 중 실제사기 98% |
| **S3 정책 엔진** | ✅ 완료(재구현 2026-06-01) | `app/policy.py`, `scripts/verify_policy.py` | 18 시나리오 §3.5와 일치. default-deny·소유/배정·step-up(L1/L2/L3/L4)·obligations 정상 |
| **S4 인증 사다리(OTP)** | ⏳ 다음 | (예정) `app/auth.py` | pyotp 기반 단명·동작한정 step-up 토큰 발급/검증 |

> ⚠️ **2026-06-01 정정:** 이전 체크포인트는 S2·S3 완료로 적혀 있었으나, 실제 디스크엔 `gen_judgment.py`/`policy.py`/`verify_policy.py` **소스가 없었음**(지난 세션 환경 불안정 중 저장 누락 추정). DB(`data/fraud_case.db`)는 5,000건 Z3·Z4 까지 채워져 **데이터 산출물은 보존**됨. S3 정책 엔진은 이번에 **출력 계약**(`Decision.required_level`=S4용, `Decision.obligations`=S5용 필드 분리)을 갖춰 재구현·검증함. **S2 `gen_judgment.py`도 2026-06-01 재구현·재실행 완료** — 룰 R1(고액)·R2(초고액)·R3(심야)·R4(비대면)·R5(원거리) 가산 스코어링, 결정론적(재실행 안정). ground_truth 는 보지 않고 Z1/Z2 피처만으로 독립 판정.
| **S5 응답 필터** | ✅ 완료(2026-06-01) | `app/filter.py`, `scripts/verify_filter.py` | obligations 집행: Z2 복호화/마스킹, Z3 깊이차등+ground_truth 숨김, Z1/Z4 차등. FC-000001 페르소나별 출력 차등 확인 |
| **S6 데모 UI** | ✅ 완료(2026-06-01) | `app/main.py` + `templates/demo.html` | FastAPI 데모 웹(포트 8030). 페르소나·구역·동작·인증등급 선택 → 정책+필터 결과. permit/deny/step_up 배지 + 필터 출력. 4시나리오 curl 검증 |

진척: **5 / 6 단계** (S1·S2·S3·S5·S6 완료 / S4 인증만 남음)
> S4(인증)는 의도적으로 보류 중 — S6 데모는 '현재 인증등급'을 수동 선택해 step-up 발동을 흉내냄.

## 두 프로젝트 통합 (Docker, 나란히 동시 실행)
- 기존 PayWise(`C:\Users\alstj\Downloads\캡스톤_프로젝트`)는 **수정 안 함** — 자체 compose 그대로.
- 후속(보안) 컨테이너화: `Dockerfile`, `.dockerignore`, `docker-compose.yml`(단독, 8030).
- `docker-compose.all.yml` = `include` 로 기존 compose 끌어오고 security-demo 추가 → 한 명령으로 둘 다.
  - `docker compose -f docker-compose.all.yml config` 검증 통과(7 서비스 인식). 실제 build 는 미실행(데몬 off).
- 포트: 3020 PayWise프론트 / 8020 백엔드 / 8010 fraud-service / **8030 보안데모**. 데이터는 각자 분리.

---

## 재개 방법 (다음 세션)

```powershell
cd C:\Users\alstj\Downloads\캡스톤_프로젝트_후속
.\.venv\Scripts\python.exe -m scripts.gen_judgment            # (필요시) 판정 재생성
.\.venv\Scripts\python.exe -X utf8 -m scripts.verify_policy   # 정책 18 시나리오 검증
.\.venv\Scripts\python.exe -X utf8 -m scripts.verify_filter   # 필터 페르소나별 출력 데모

# 데모 웹 (S6) — http://localhost:8030
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8030 --reload

# Docker: 후속만        →  docker compose up --build
#         둘 다 동시에   →  docker compose -f docker-compose.all.yml up --build
```
- DB(`data/fraud_case.db`)가 남아있으면 S1·S2 재실행 불필요.
- `-X utf8` 안 붙이면 콘솔 한글이 cp949 로 깨짐(로직 무관, 표시만).

## 다음 작업 (S4)
- `app/auth.py`: TOTP 시크릿 발급 + OTP 검증 → 통과 시 **step-up 토큰** 발급
  (서명·만료, payload = `{case_id, zone, verb, level, exp}`; TTL=`settings.stepup_ttl_seconds`=120s)
- 정책 엔진의 `Decision.required_level` 과 연결: STEP_UP 이면 토큰 요구 → 재평가 시 `current_level` 상승

---

## 알려진 이슈 (사소 — 데이터 영향 없음)
- `scripts/etl_sparkov.py` 의 `print` 문 em대시(`—`) 가 Windows cp949 콘솔에서 인코딩 에러. **출력 메시지만** 깨지고 적재는 정상. → print 를 ASCII(`-`)로 교체 권장.
- 이 세션 중 도구 출력이 일부 뒤섞이는 환경 불안정 발생. 값은 파일 덤프 후 Read 로 재확인하며 진행함.

---

## 발표 준비 메모 (TODO — 구현과 별개로 챙길 것)
- 설계서 §1(개요/차별점/비유), §3.5(매트릭스 1장), §7(결정 로그 D1~D9)이 발표 핵심 자료.
- 데모는 **눈에 보이는 3장면**: ① 페르소나 전환 시 Z2 마스킹 변화 ② 민감 동작 시 OTP step-up 발동 ③ 같은 case가 P1/P2/P4에게 다르게 보임.
- "보안 강화 기반"의 전송/저장 암호화는 화면에 안 보이므로 슬라이드로 설명(§1.5), 데모는 3축+OTP에 집중. (※ "제로 트러스트"로 크게 내걸지 않고 "기존 대비 보안 강화"로 톤 다운 — 2026-06-01 결정)
- 해시체인은 이번 발표 배제(D7).
- **최종 발표 전 한 번 전체 정리/리허설 필요** (사용자 요청).
