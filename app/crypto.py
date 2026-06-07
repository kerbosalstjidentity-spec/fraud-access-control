"""Z2(PII) 컬럼 암호화 — 저장 암호화(at rest). 설계서 §1.5 / §2.2 / D3.

Fernet(AES-128-CBC + HMAC) 대칭 암호화. 복호화는 정책이 허용한
요청에서만 수행하고(§4 ④단계), 표시할 때 verb 에 따라 재마스킹한다.
"""
from __future__ import annotations

from cryptography.fernet import Fernet

from app.config import settings

_fernet = Fernet(settings.fernet_key.encode())


def encrypt(plaintext: str | None) -> str:
    """평문 → 암호문(str). None/빈값은 빈 문자열."""
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(token: str | None) -> str:
    """암호문 → 평문. 빈값은 빈 문자열."""
    if not token:
        return ""
    return _fernet.decrypt(token.encode()).decode()


def mask_card(pan: str) -> str:
    """카드번호 앞6뒤4만 노출 (view.masked)."""
    digits = "".join(ch for ch in pan if ch.isdigit())
    if len(digits) <= 10:
        return "*" * len(digits)
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def mask_name(name: str) -> str:
    """실명 → 성/이니셜만 (view.masked)."""
    parts = name.split()
    return " ".join((p[0] + "*" * (len(p) - 1)) if len(p) > 1 else p for p in parts)
