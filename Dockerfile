# 후속(보안) 프로젝트 — 3축 접근통제 데모 웹
# 기존 PayWise 와 나란히 띄우기 위한 단일 컨테이너. 포트 8030.
FROM python:3.12-slim

WORKDIR /app

# 의존성 먼저 (레이어 캐시)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 + 이미 생성된 데모 DB(data/fraud_case.db) 포함
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY templates/ ./templates/
COPY data/ ./data/

EXPOSE 8030

# 0.0.0.0 바인딩 + 포트는 배포 플랫폼이 주는 $PORT 사용(없으면 8030).
# → 로컬(docker compose: PORT 미설정 → 8030)과 외부 배포(Render/HF 등: $PORT) 양쪽 호환.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8030}"]
