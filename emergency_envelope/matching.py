"""조력자 매칭: 지정 → 확장 A → 확장 B, 선착순 잠금 배정, 동시 1건."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from .audit import AuditType, HashChainLog
from .common import Capability, Denied, GridCell, HelperKind, TrustTier

CANDIDATES_PER_ROUND = 3


@dataclass(frozen=True)
class Helper:
    """조력자. 시민 조력자는 가구 정보 없이 풀에만 등록된다."""

    id: str
    kind: HelperKind
    cell: GridCell
    capabilities: frozenset[Capability] = frozenset()

    def can_serve(self, need: Capability) -> bool:
        return need is Capability.GENERAL or need in self.capabilities

    def tier_for(self, designated_id: str | None) -> TrustTier:
        return TrustTier.of(self.kind, self.id, designated_id)

    def moved_to(self, cell: GridCell) -> "Helper":
        return replace(self, cell=cell)


class HelperRegistry:
    """조력자 자격 명부 (담당 공무원이 관리). 보관 기관도 이 자격을 직접 확인한다."""

    def __init__(self) -> None:
        self._helpers: dict[str, Helper] = {}
        self._suspended: set[str] = set()

    def register(self, h: Helper) -> None:
        self._helpers[h.id] = h

    def update(self, h: Helper) -> None:
        if h.id in self._helpers:
            self._helpers[h.id] = h

    def find(self, helper_id: str | None) -> Helper | None:
        return self._helpers.get(helper_id) if helper_id else None

    def is_qualified(self, helper_id: str | None) -> bool:
        return helper_id in self._helpers and helper_id not in self._suspended

    def suspend(self, helper_id: str) -> None:
        self._suspended.add(helper_id)

    def is_suspended(self, helper_id: str) -> bool:
        return helper_id in self._suspended

    def active(self) -> list[Helper]:
        return [h for h in self._helpers.values() if h.id not in self._suspended]


@dataclass(frozen=True)
class HouseholdNeed:
    """매칭 입력. 격자 위치와 필요 유형뿐이라 매칭 엔진은 개인정보를 보지 않는다.
    designated_helper_id가 None이면 봉인형 가구다."""

    household_id: str
    cell: GridCell
    need: Capability
    designated_helper_id: str | None
    risk: float


@dataclass(frozen=True)
class Offer:
    """조력자 화면의 출동 요청. 주소 없이 방향과 필요 유형만."""

    household_id: str
    tier: TrustTier
    direction: str
    need_label: str


@dataclass(frozen=True)
class Assignment:
    household_id: str
    helper_id: str
    tier: TrustTier
    at: datetime


@dataclass
class _Dispatch:
    need: HouseholdNeed
    tier: TrustTier | None = None
    notified: set[str] = field(default_factory=set)
    declined: set[str] = field(default_factory=set)
    offered_at: datetime | None = None
    assignment: Assignment | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


def _next_tier(t: TrustTier | None) -> TrustTier:
    if t is None:
        return TrustTier.DESIGNATED
    return TrustTier.EXTENDED_A if t is TrustTier.DESIGNATED else TrustTier.EXTENDED_B


class MatchingEngine:
    def __init__(self, helpers: HelperRegistry, log: HashChainLog, clock, response_timeout: timedelta,
                 max_distance_cells: int):
        self.helpers, self.log, self.clock = helpers, log, clock
        self.response_timeout, self.max_distance = response_timeout, max_distance_cells
        self._dispatches: dict[str, _Dispatch] = {}
        self._busy: dict[str, str] = {}  # helper_id → household_id
        self._busy_lock = threading.Lock()

    def dispatch(self, needs: list[HouseholdNeed]) -> None:
        """위험도가 높은 가구부터 출동 요청을 보낸다."""
        for n in sorted(needs, key=lambda n: n.risk, reverse=True):
            d = self._dispatches.setdefault(n.household_id, _Dispatch(n))
            with d.lock:
                if d.assignment is None and d.tier is None:
                    self._start_round(d, TrustTier.DESIGNATED)

    def offers_for(self, helper_id: str) -> list[Offer]:
        """조력자 화면에 보일 요청 목록. 이미 배정된 가구는 지워진다."""
        h = self.helpers.find(helper_id)
        if h is None or helper_id in self._busy:
            return []
        out = []
        for d in list(self._dispatches.values()):
            with d.lock:
                if d.assignment is None and helper_id in d.notified and helper_id not in d.declined:
                    out.append(Offer(d.need.household_id, h.tier_for(d.need.designated_helper_id),
                                     d.need.cell.direction_from(h.cell), d.need.need.value))
        return out

    def accept(self, helper_id: str, household_id: str) -> Assignment:
        d = self._dispatches.get(household_id)
        if d is None:
            raise Denied("출동 요청 없음")
        with d.lock:
            if d.assignment is not None:
                raise Denied("이미 다른 조력자가 수락함")
            if helper_id not in d.notified or helper_id in d.declined:
                raise Denied("이 조력자에게 온 요청이 아님")
            h = self.helpers.find(helper_id)
            if h is None or self.helpers.is_suspended(helper_id):
                raise Denied("정지된 계정")
            with self._busy_lock:
                if helper_id in self._busy:
                    raise Denied("동시에 1건만 수락 가능")
                self._busy[helper_id] = household_id
            tier = h.tier_for(d.need.designated_helper_id)
            d.assignment = Assignment(household_id, helper_id, tier, self.clock.now())
            self.log.append(AuditType.ACCEPTED, household_id, helper_id, tier.value)
            return d.assignment

    def abandon(self, helper_id: str, household_id: str) -> None:
        """수락 후 포기: 자동으로 다음 조력자에게 넘긴다."""
        d = self._dispatches.get(household_id)
        if d is None:
            return
        with d.lock:
            if d.assignment is None or d.assignment.helper_id != helper_id:
                raise Denied("배정되지 않은 조력자")
            with self._busy_lock:
                self._busy.pop(helper_id, None)
            d.assignment = None
            d.declined.add(helper_id)
            self.log.append(AuditType.ABANDONED, household_id, helper_id, "포기")
            self._continue_round(d)

    def decline(self, helper_id: str, household_id: str) -> None:
        d = self._dispatches.get(household_id)
        if d is None:
            return
        with d.lock:
            d.declined.add(helper_id)
            if d.assignment is None and d.notified <= d.declined:
                self._continue_round(d)

    def tick(self) -> None:
        """응답 시간 초과 처리. 주기적으로 호출한다."""
        now = self.clock.now()
        for d in list(self._dispatches.values()):
            with d.lock:
                if d.assignment is None and d.offered_at and now >= d.offered_at + self.response_timeout:
                    self._continue_round(d)

    def assignment(self, household_id: str) -> Assignment | None:
        d = self._dispatches.get(household_id)
        return d.assignment if d else None

    def unassigned(self) -> list[str]:
        return [hid for hid, d in self._dispatches.items() if d.assignment is None]

    def release(self, household_id: str) -> None:
        """가구 단위 재봉인: 요청과 배정을 지우고 조력자를 풀어 준다."""
        d = self._dispatches.pop(household_id, None)
        if d and d.assignment:
            with self._busy_lock:
                self._busy.pop(d.assignment.helper_id, None)

    def _continue_round(self, d: _Dispatch) -> None:
        # 같은 등급에 아직 안 부른 후보가 있으면 추가로, 없으면 다음 등급으로
        if d.tier is TrustTier.EXTENDED_B or not self._notify(d, d.tier):
            self._start_round(d, _next_tier(d.tier))

    def _start_round(self, d: _Dispatch, tier: TrustTier) -> None:
        t = tier
        while True:
            d.tier = t
            if self._notify(d, t) or t is TrustTier.EXTENDED_B:
                return
            t = _next_tier(t)

    def _available(self, h: Helper) -> bool:
        return not self.helpers.is_suspended(h.id) and h.id not in self._busy

    def _notify(self, d: _Dispatch, t: TrustTier) -> bool:
        """등급 t의 후보에게 요청을 보낸다. 새로 부른 사람이 있으면 True."""
        if t is TrustTier.DESIGNATED:
            h = self.helpers.find(d.need.designated_helper_id)
            candidates = [h] if h and h.kind is HelperKind.PARTNER and self._available(h) and h.id not in d.notified else []
        else:
            candidates = sorted(
                (h for h in self.helpers.active()
                 if h.tier_for(d.need.designated_helper_id) is t and self._available(h)
                 and h.id not in d.notified and h.can_serve(d.need.need)
                 and h.cell.distance(d.need.cell) <= self.max_distance),
                key=lambda h: h.cell.distance(d.need.cell))[:CANDIDATES_PER_ROUND]
        if not candidates:
            return False
        d.offered_at = self.clock.now()
        for h in candidates:
            d.notified.add(h.id)
            self.log.append(AuditType.OFFERED, d.need.household_id, h.id, t.value)
        return True
