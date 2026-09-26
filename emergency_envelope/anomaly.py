"""규칙 기반 열람 이상 탐지. 공식 증거로 여는 개봉은 막지 않고 사람의 요청 경로와 계정 행위만 제한한다."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

from .audit import AuditEntry, AuditType
from .common import KST

WINDOW = timedelta(hours=1)
MAX_ABANDONS = 2
MAX_DENIED_OPENS = 3
MAX_NIGHT_OFFICIAL_ATTEMPTS = 2


@dataclass(frozen=True)
class Finding:
    actor: str
    rule: str
    count: int


def analyze(entries: list[AuditEntry], now: datetime) -> list[Finding]:
    recent = [e for e in entries if e.at >= now - WINDOW]
    out: list[Finding] = []
    for actor, n in Counter(e.actor for e in recent if e.type is AuditType.ABANDONED).items():
        if n >= MAX_ABANDONS:
            out.append(Finding(actor, "수락·포기 반복", n))
    for actor, n in Counter(e.actor for e in recent if e.type is AuditType.OPEN_DENIED).items():
        if n >= MAX_DENIED_OPENS:
            out.append(Finding(actor, "개봉 거부 반복 (격자 밖·근거 없는 시도)", n))
    night = Counter(e.actor for e in recent
                    if e.type is AuditType.OPEN_DENIED and e.detail.startswith("OFFICIAL") and e.at.astimezone(KST).hour < 6)
    for actor, n in night.items():
        if n >= MAX_NIGHT_OFFICIAL_ATTEMPTS:
            out.append(Finding(actor, "비정상 시간대 관리자 조회 집중", n))
    return out
