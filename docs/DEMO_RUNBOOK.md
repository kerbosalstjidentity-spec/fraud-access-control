# 시현 런북 (로컬) — 3축 접근통제 보안 데모

> 발표/시연용. 가장 안전한 경로는 **로컬 실행**. 인터넷·콜드스타트 변수 없음.

---

## 0. 사전 준비 (발표 전 1회, 미리!)

1. **Docker Desktop 켜고 "Docker Desktop is running" 까지 대기** (고래 아이콘 안정).
   - `docker info` 가 에러 없이 나오면 준비 완료. (Linux 엔진이 떠야 함)
2. **포트 비우기**: 8030(보안데모), 3020/8020/8010(PayWise)에 떠 있는 dev 프로세스 종료.
   - 8030 확인: PowerShell `Get-NetTCPConnection -LocalPort 8030 -State Listen`
3. **미리 빌드** (첫 빌드는 pip/npm 때문에 수 분 소요 — 발표 직전 말고 미리):
   - `docker compose build`

---

## 1. 실행 모드 3가지 (택1)

### A. 보안 데모만 — 가장 가볍고 빠름 ⭐ 추천
```powershell
cd C:\Users\alstj\Downloads\캡스톤_프로젝트_후속
docker compose up --build
```
→ 브라우저 **http://localhost:8030**

### B. PayWise 전체만
```powershell
cd C:\Users\alstj\Downloads\캡스톤_프로젝트
docker compose up --build
```
→ 프론트 **http://localhost:3020** (Kafka 포함이라 기동 30초+ 소요)

### C. 둘 다 동시에 (나란히 시연)
```powershell
cd C:\Users\alstj\Downloads\캡스톤_프로젝트_후속
docker compose -f docker-compose.all.yml up --build
```
→ PayWise(3020) + 보안데모(8030) 동시. (가장 무겁움 — 미리 띄워두기)

---

## 2. Docker 없이도 됨 — 백업 플랜 (검증 완료)

Docker가 말썽이면 이걸로:
```powershell
cd C:\Users\alstj\Downloads\캡스톤_프로젝트_후속
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8030
```
→ http://localhost:8030 (Docker와 동일 화면)

---

## 3. 데모 클릭 동선 (보안데모, localhost:8030)

"DB는 하나, 보이는 건 제각각" 을 페르소나만 바꿔가며 보여준다:

| 순서 | 설정 | 보여줄 것 |
|---|---|---|
| ① | P2 조사관 / Z2 / unmask / L4 | 카드번호 **전체** 노출 (PERMIT) |
| ② | **페르소나만 P1 고객**으로 | 같은 카드가 **마스킹** (`418981***4741`) |
| ③ | **P4 감사**로 | Z2 접근 **거부** (감사는 메타만) |
| ④ | 다시 P2 / **인증등급 L0**으로 | **STEP-UP(OTP) 발동** — 데이터 미반환 |
| ⑤ | **침입자 체크박스** ON | 소유/배정 위반 → **거부** |
| ⑥ | P2 / Z3 / view.full | 모델 룰·설명 공개, **ground_truth는 숨김** |

→ 메시지: 같은 case_id 하나가 누가·무엇을·어떻게·어느 인증등급이냐에 따라 다르게 통제됨.

---

## 4. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| `failed to connect to the docker API ... dockerDesktopLinuxEngine` | Docker Desktop Linux 엔진 미기동 → 완전히 켜질 때까지 대기 후 재시도 |
| 8030 `address already in use` | dev 서버가 떠 있음 → 종료 후 재실행 |
| PayWise 첫 화면이 안 뜸 | Kafka 헬스체크 대기(30초+) → 잠시 후 새로고침 |
| 콘솔 한글 깨짐 | 표시만 깨짐(cp949), 로직 무관. 스크립트엔 `-X utf8` |

---

## 5. 발표 직전 체크리스트
- [ ] Docker Desktop "running" 확인 (또는 백업 plan: uvicorn)
- [ ] 미리 `docker compose build` 완료 (빌드 대기 없이 `up`만)
- [ ] 8030 포트 비어있음
- [ ] http://localhost:8030 한 번 열어 화면 확인
- [ ] 데모 동선 ①~⑥ 1회 리허설
