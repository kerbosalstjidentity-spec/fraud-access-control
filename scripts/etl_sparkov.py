"""S1 — Sparkov CSV → fraud_case 4구역 적재 + Z2(PII) 암호화. 설계서 §5 S1.

실행:
    python -m scripts.etl_sparkov

- 전체 130만 행 중 표본(settings.etl_sample_size)만 적재 (데모용)
- etl_fraud_oversample=True 면 사기 케이스 비율을 끌어올려 데모 가시성 확보
- Z1(거래사실)·Z2(PII)만 채움. Z3(판정)·Z4(조사)는 S2에서 생성.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.crypto import encrypt  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.models import FraudCase  # noqa: E402


def _sample(df: pd.DataFrame, n: int, oversample: bool) -> pd.DataFrame:
    if not oversample:
        return df.sample(n=min(n, len(df)), random_state=42)
    frauds = df[df["is_fraud"] == 1]
    legit = df[df["is_fraud"] == 0]
    n_fraud = min(len(frauds), n // 2)          # 표본의 절반까지 사기로
    n_legit = min(len(legit), n - n_fraud)
    out = pd.concat([
        frauds.sample(n=n_fraud, random_state=42),
        legit.sample(n=n_legit, random_state=42),
    ])
    return out.sample(frac=1, random_state=42)   # 셔플


def run() -> None:
    csv = settings.sparkov_train_csv
    print(f"[S1] reading {csv} …")
    df = pd.read_csv(csv)
    print(f"[S1] total rows = {len(df):,}")

    df = _sample(df, settings.etl_sample_size, settings.etl_fraud_oversample)
    print(f"[S1] sampled = {len(df):,}  (fraud={int(df['is_fraud'].sum())})")

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    db = SessionLocal()
    try:
        for i, (_, r) in enumerate(df.iterrows(), start=1):
            address = f"{r['street']}, {r['city']}, {r['state']} {r['zip']}"
            case = FraudCase(
                case_id=f"FC-{i:06d}",
                # Z1
                trans_num=str(r["trans_num"]),
                trans_ts=pd.to_datetime(r["trans_date_trans_time"]).to_pydatetime(),
                amt=float(r["amt"]),
                merchant=str(r["merchant"]),
                category=str(r["category"]),
                merch_lat=float(r["merch_lat"]),
                merch_long=float(r["merch_long"]),
                # Z2 (암호화)
                cc_num_enc=encrypt(str(r["cc_num"])),
                name_enc=encrypt(f"{r['first']} {r['last']}"),
                dob_enc=encrypt(str(r["dob"])),
                address_enc=encrypt(address),
                gender=str(r["gender"]),
                job=str(r["job"]),
                cust_lat=float(r["lat"]),
                cust_long=float(r["long"]),
                # Z3 ground_truth만 보관 (나머지는 S2)
                ground_truth=int(r["is_fraud"]),
            )
            db.add(case)
            if i % 1000 == 0:
                db.commit()
                print(f"[S1]   {i:,} rows committed")
        db.commit()
        print(f"[S1] DONE — {len(df):,} cases → {settings.db_path}")
    finally:
        db.close()


if __name__ == "__main__":
    run()
