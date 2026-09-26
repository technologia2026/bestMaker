"""공개 매트릭스와 전달 서비스 (도착 확인, 단기 토큰, 워터마크)."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta
from enum import Enum

from .audit import AuditType, HashChainLog
from .common import Capability, Denied, GridCell, Stage, TrustTier, hm, random_token
from .evidence import DeviceRegistry, verify_arrival_code
from .matching import HelperRegistry

MAX_ARRIVAL_ATTEMPTS = 5


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

    def __init__(self, helpers: HelperRegistry, devices: DeviceRegistry, log: HashChainLog, clock,
                 token_ttl: timedelta):
        self.helpers, self.devices, self.log, self.clock, self.token_ttl = helpers, devices, log, clock, token_ttl
        self._sessions: dict[str, _Session] = {}

    def issue(self, household_id: str, helper_id: str, tier: TrustTier, device_id: str, cell: GridCell,
              need: Capability, record: dict[Field, str], consented: set[Field], evidence_valid_until: datetime,
              basis: str) -> str:
        """단기 토큰 발급. 토큰 원문은 저장하지 않고 해시만 보관한다."""
        expires = min(evidence_valid_until, self.clock.now() + self.token_ttl)
        token = random_token()
        self._sessions[_digest(token)] = _Session(household_id, helper_id, tier, device_id, cell, need,
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

    def confirm_arrival(self, token: str, device_id: str, helper_cell: GridCell, code: str) -> None:
        """위치 격자 일치 + 가정 기기 일회용 코드. 반복 실패 시 세션 잠금."""
        s = self._session(token, device_id)
        with s.lock:
            if s.failed_arrivals >= MAX_ARRIVAL_ATTEMPTS:
                raise Denied("도착 확인 시도 초과로 잠김")
            dev = self.devices.for_household(s.household_id)
            code_ok = dev is not None and verify_arrival_code(dev.arrival_secret, s.household_id,
                                                              self.clock.now(), code)
            # 가정 기기가 없는 가구는 확장 A까지만 위치로 도착 인정, 확장 B는 불가
            fallback = dev is None and s.tier is not TrustTier.EXTENDED_B
            if helper_cell != s.cell or not (code_ok or fallback):
                s.failed_arrivals += 1
                raise Denied("도착 확인 실패")
            s.arrived = True
            self.log.append(AuditType.ARRIVED, s.household_id, s.helper_id, f"{s.tier.value} 도착 확인")

    def reseal(self, household_id: str) -> None:
        for k in [k for k, s in self._sessions.items() if s.household_id == household_id]:
            del self._sessions[k]

    def active_sessions(self) -> int:
        return len(self._sessions)
