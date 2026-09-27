"""공개 매트릭스와 전달 서비스 (도착 확인, 단기 토큰, 워터마크)."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta
from enum import Enum

from .audit import AuditType, HashChainLog
from .common import Capability, Denied, GridCell, Position, Stage, TrustTier, hm, random_token
from .matching import HelperRegistry

MAX_ARRIVAL_ATTEMPTS = 5
ARRIVAL_RADIUS_M = 50.0


class Field(Enum):
    DIRECTION = ("방향", False)
    NEED_TYPE = ("필요 유형", False)
    UNIT = ("호수", True)
    STATUS = ("상태", True)
    ESCAPE_ROUTE = ("탈출 경로", True)
    EMERGENCY_CONTACT = ("비상연락처", True)

    @property
    def label(self) -> str:
        return self.value[0]

    @property
    def consentable(self) -> bool:
        """당사자가 공개 여부를 고르는 항목인가."""
        return self.value[1]


_PRE_ARRIVAL = (Field.DIRECTION, Field.NEED_TYPE)
_EXTENDED_B_MINIMUM = {Field.UNIT, Field.ESCAPE_ROUTE}


def visible_fields(tier: TrustTier, stage: Stage, arrived: bool, consented: set[Field]) -> list[Field]:
    """공개 매트릭스 (신뢰 등급 × 위험 단계 × 도착 여부). 결과는 항상 당사자 동의 항목과의 교집합."""
    if stage is not Stage.OPEN:
        return []
    out = list(_PRE_ARRIVAL)
    if tier is TrustTier.DESIGNATED or arrived:
        for f in Field:
            if not f.consentable or f not in consented:
                continue
            if tier is TrustTier.EXTENDED_B and f not in _EXTENDED_B_MINIMUM:
                continue
            out.append(f)
    return out


@dataclass(frozen=True)
class HelperView:
    """조력자 화면 응답. 웹 계층은 Cache-Control: no-store로 내보내고 브라우저 저장소에 남기지 않으며
    워터마크를 화면에 겹쳐 그린다."""

    fields: dict[Field, str]
    arrived: bool
    watermark: str
    expires_at: datetime


@dataclass
class _Session:
    household_id: str
    helper_id: str
    tier: TrustTier
    device_id: str
    cell: GridCell
    position: Position
    need: Capability
    record: dict[Field, str]
    consented: set[Field]
    expires_at: datetime
    basis: str
    arrived: bool = False
    failed_arrivals: int = 0
    last_logged: frozenset[Field] = frozenset()
    lock: threading.Lock = dc_field(default_factory=threading.Lock)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class DisclosureService:
    """복호화된 봉투 2는 이 서비스의 메모리에만 머물고 단기 토큰(기기 바인딩)으로만 조회된다.
    도착 전에는 방향과 필요 유형만, 도착 확인 후 신뢰 등급이 허용하는 항목만 연다."""

    def __init__(self, helpers: HelperRegistry, log: HashChainLog, clock, token_ttl: timedelta):
        self.helpers, self.log, self.clock, self.token_ttl = helpers, log, clock, token_ttl
        self._sessions: dict[str, _Session] = {}

    def issue(self, household_id: str, helper_id: str, tier: TrustTier, device_id: str, cell: GridCell,
              position: Position, need: Capability, record: dict[Field, str], consented: set[Field], evidence_valid_until: datetime,
              basis: str) -> str:
        """단기 토큰 발급. 토큰 원문은 저장하지 않고 해시만 보관한다."""
        expires = min(evidence_valid_until, self.clock.now() + self.token_ttl)
        token = random_token()
        self._sessions[_digest(token)] = _Session(household_id, helper_id, tier, device_id, cell, position, need,
                                                  dict(record), set(consented), expires, basis)
        return token

    def _session(self, token: str | None, device_id: str) -> _Session:
        if not token:
            raise Denied("토큰 없음")
        s = self._sessions.get(_digest(token))
        if s is None:
            raise Denied("유효하지 않거나 폐기된 토큰")
        if self.clock.now() >= s.expires_at:
            self._sessions.pop(_digest(token), None)
            raise Denied("만료된 토큰")
        if s.device_id != device_id:
            raise Denied("다른 기기에서의 토큰 사용")
        if self.helpers.is_suspended(s.helper_id):
            raise Denied("정지된 계정")
        return s

    def view(self, token: str, device_id: str) -> HelperView:
        s = self._session(token, device_id)
        with s.lock:
            h = self.helpers.find(s.helper_id)
            out: dict[Field, str] = {}
            for f in visible_fields(s.tier, Stage.OPEN, s.arrived, s.consented):
                if f is Field.DIRECTION:
                    out[f] = s.cell.direction_from(h.cell)
                elif f is Field.NEED_TYPE:
                    out[f] = s.need.value
                elif f in s.record:
                    out[f] = s.record[f]
            details = frozenset(f for f in out if f.consentable)
            if details and details != s.last_logged:
                s.last_logged = details
                items = "·".join(f.label for f in Field if f in details)
                self.log.append(AuditType.VIEWED, s.household_id, s.helper_id,
                                f"{s.tier.value} 1명 열람 ({items}), 근거: {s.basis}")
            return HelperView(out, s.arrived, f"{s.helper_id} · {hm(self.clock.now())}", s.expires_at)

    def confirm_arrival(self, token: str, device_id: str, helper_position: Position) -> None:
        """조력자가 집 반경 50m 안에 들어오면 도착으로 인정한다 (별도 코드 입력 없음).
        위치를 바꿔 가며 집을 더듬어 찾는 시도를 막기 위해 실패는 5회까지만 허용하고 모두 기록한다."""
        s = self._session(token, device_id)
        with s.lock:
            if s.failed_arrivals >= MAX_ARRIVAL_ATTEMPTS:
                raise Denied("도착 확인 시도 초과로 잠김")
            if helper_position.distance_m(s.position) > ARRIVAL_RADIUS_M:
                s.failed_arrivals += 1
                self.log.append(AuditType.ARRIVAL_FAILED, s.household_id, s.helper_id,
                                f"도착 위치 불일치 ({s.failed_arrivals}/{MAX_ARRIVAL_ATTEMPTS})")
                raise Denied("아직 도착 위치가 아님")
            s.arrived = True
            self.log.append(AuditType.ARRIVED, s.household_id, s.helper_id, f"{s.tier.value} 도착 인식 (반경 50m)")

    def reseal(self, household_id: str) -> None:
        for k in [k for k, s in self._sessions.items() if s.household_id == household_id]:
            del self._sessions[k]

    def active_sessions(self) -> int:
        return len(self._sessions)
