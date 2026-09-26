"""해시 체인 감사 로그와 당사자 통지."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Iterable, Protocol

from .common import fields, hm, iso

GENESIS = "0" * 64


class AuditType(Enum):
    REGISTERED = "등록"
    EVIDENCE_ACCEPTED = "증거 수신"
    EVIDENCE_REJECTED = "증거 거부"
    STAGE_CHANGED = "단계 변경"
    OPEN_GRANTED = "개봉 허가"
    OPEN_DENIED = "개봉 거부"
    OFFERED = "출동 요청"
    ACCEPTED = "수락"
    ABANDONED = "포기"
    ARRIVED = "도착"
    VIEWED = "열람"
    RESEALED = "재봉인"
    ACCOUNT_SUSPENDED = "계정 정지"


@dataclass(frozen=True)
class AuditEntry:
    """해시 체인 한 칸. hash = SHA-256(prev_hash ‖ 내용)."""

    seq: int
    at: datetime
    type: AuditType
    household_id: str | None
    actor: str
    detail: str
    prev_hash: str
    hash: str


class AnchorSink(Protocol):
    """체인 끝 해시를 받아 적는 외부 기관 (열쇠 보관 기관)."""

    name: str

    def record_anchor(self, seq: int, hash_: str) -> None: ...

    def anchor_at(self, seq: int) -> str | None: ...

    def latest_anchor_seq(self) -> int: ...


def _hash(seq: int, at: datetime, type_: AuditType, hid: str | None, actor: str, detail: str, prev: str) -> str:
    return hashlib.sha256(fields(prev, seq, iso(at), type_.name, hid, actor, detail)).hexdigest()


class HashChainLog:
    """모든 판정·개봉·열람을 해시 체인으로 묶는다. 체인 끝 해시를 보관 기관들에 주기적으로
    기록해 두면 메인 DB 관리자가 과거 기록을 고치거나 지워도 드러난다."""

    def __init__(self, clock):
        self.clock = clock
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    def append(self, type_: AuditType, household_id: str | None, actor: str, detail: str) -> AuditEntry:
        with self._lock:
            prev = self._entries[-1].hash if self._entries else GENESIS
            seq, at = len(self._entries), self.clock.now()
            e = AuditEntry(seq, at, type_, household_id, actor, detail, prev,
                           _hash(seq, at, type_, household_id, actor, detail, prev))
            self._entries.append(e)
            return e

    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def head(self) -> AuditEntry | None:
        with self._lock:
            return self._entries[-1] if self._entries else None

    def anchor_to(self, sinks: Iterable[AnchorSink]) -> None:
        h = self.head()
        if h:
            for s in sinks:
                s.record_anchor(h.seq, h.hash)

    def verify_chain(self) -> bool:
        return _verify(self.entries())

    def verify_against(self, sinks: Iterable[AnchorSink]) -> bool:
        entries = self.entries()
        if not _verify(entries):
            return False
        for s in sinks:
            if s.latest_anchor_seq() >= len(entries):
                return False  # 앵커 이후 기록이 잘려 나감
            for i, e in enumerate(entries):
                anchored = s.anchor_at(i)
                if anchored is not None and anchored != e.hash:
                    return False
        return True

    # 테스트용: DB 관리자가 기록을 조작하는 상황
    def _tamper(self, index: int, **changes) -> None:
        with self._lock:
            self._entries[index] = replace(self._entries[index], **changes)

    def _truncate(self, size: int) -> None:
        with self._lock:
            del self._entries[size:]


def _verify(entries: list[AuditEntry]) -> bool:
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.seq != i or e.prev_hash != prev:
            return False
        if _hash(e.seq, e.at, e.type, e.household_id, e.actor, e.detail, prev) != e.hash:
            return False
        prev = e.hash
    return True


def notifications_for(log: HashChainLog, household_id: str) -> list[str]:
    """당사자 통지: "22:14, 확장 조력자 A 1명 열람 (호수·탈출 경로), 근거: 공식 침수경보"."""
    out = []
    for e in log.entries():
        if e.household_id != household_id:
            continue
        if e.type is AuditType.VIEWED:
            out.append(f"{hm(e.at)}, {e.detail}")
        elif e.type is AuditType.OPEN_DENIED:
            out.append(f"{hm(e.at)}, 열람 시도 거부됨")
        elif e.type is AuditType.RESEALED:
            out.append(f"{hm(e.at)}, 재봉인 완료")
    return out
