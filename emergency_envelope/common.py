"""공통 타입과 인코딩."""
from __future__ import annotations

import json
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class Denied(Exception):
    """보안 검사에서 거부된 요청. 메시지는 사용자에게 보여도 되는 사유만 담는다."""


def fields(*parts: object) -> bytes:
    """길이 접두 인코딩. 서명·AAD·해시 입력이 구분자 충돌로 모호해지지 않게 한다."""
    out = [struct.pack(">I", len(parts))]
    for p in parts:
        b = ("" if p is None else str(p)).encode("utf-8")
        out.append(struct.pack(">I", len(b)))
        out.append(b)
    return b"".join(out)


def encode_json(obj: dict) -> bytes:
    """봉투 평문 직렬화. pickle 대신 JSON만 쓴다."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")


def decode_json(data: bytes) -> dict:
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("잘못된 봉투 평문")
    return obj


def random_hex(nbytes: int) -> str:
    return secrets.token_hex(nbytes)


def random_token() -> str:
    return secrets.token_urlsafe(32)


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat()


KST = timezone(timedelta(hours=9))


def hm(t: datetime) -> str:
    return t.astimezone(KST).strftime("%H:%M")


@dataclass(frozen=True)
class GridCell:
    """500m 격자 셀. 평문으로 저장되는 유일한 위치 정보다."""

    row: int
    col: int
    SIZE_M = 500

    @classmethod
    def parse(cls, cell_id: str) -> "GridCell":
        r, c = cell_id.split(":")
        return cls(int(r), int(c))

    @property
    def id(self) -> str:
        return f"{self.row}:{self.col}"

    def distance(self, other: "GridCell") -> int:
        """체비셰프 거리(칸 수)."""
        return max(abs(self.row - other.row), abs(self.col - other.col))

    def direction_from(self, origin: "GridCell") -> str:
        """도착 전 조력자에게 보여주는 대략적 방향. 정확한 주소는 드러내지 않는다."""
        dr, dc = self.row - origin.row, self.col - origin.col
        if dr == 0 and dc == 0:
            return "현재 격자 안 (500m 이내)"
        ns = "북" if dr > 0 else "남" if dr < 0 else ""
        ew = "동" if dc > 0 else "서" if dc < 0 else ""
        return f"{ns}{ew}쪽 약 {self.distance(origin) * self.SIZE_M}m"


class Capability(Enum):
    GENERAL = "일반 동행"
    MOBILITY_AID = "이동 보조"
    WHEELCHAIR = "휠체어"
    VISUAL = "시각 보조"
    HEARING = "청각 보조"


class HelperKind(Enum):
    """조력자 자격. 가구별 신뢰 등급은 이 자격과 지정 관계로 정해진다."""

    PARTNER = "동행파트너·대피도우미"
    CITIZEN = "활동 서약 시민"


class TrustTier(Enum):
    """가구에 대한 조력자의 신뢰 등급. 정의 순서가 배정 우선순위다."""

    DESIGNATED = "지정 조력자"
    EXTENDED_A = "확장 조력자 A"
    EXTENDED_B = "확장 조력자 B"

    @staticmethod
    def of(kind: HelperKind, helper_id: str, designated_id: str | None) -> "TrustTier":
        """요청자 주장이 아니라 자격과 지정 관계로 계산한다."""
        if kind is HelperKind.PARTNER:
            return TrustTier.DESIGNATED if helper_id == designated_id else TrustTier.EXTENDED_A
        return TrustTier.EXTENDED_B


class Stage(Enum):
    PEACETIME = (0, "평시")
    PREPARE = (1, "준비")
    OPEN = (2, "공개")

    @property
    def rank(self) -> int:
        return self.value[0]

    @property
    def label(self) -> str:
        return self.value[1]

    def at_least(self, other: "Stage") -> bool:
        return self.rank >= other.rank


class MutableClock:
    """시연·테스트용 시계. 강우 기록 재생 시 시간을 앞으로 돌린다."""

    def __init__(self, start: datetime):
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)
