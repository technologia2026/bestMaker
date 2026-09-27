from datetime import datetime, timedelta, timezone

import pytest

from emergency_envelope.common import Capability, GridCell, HelperKind, MutableClock, Position
from emergency_envelope.disclosure import Field
from emergency_envelope.evidence import AlertLevel
from emergency_envelope.matching import Helper
from emergency_envelope.policy import BuildingProfile
from emergency_envelope.system import EmergencyEnvelopeSystem, Registration

CELL = GridCell(10, 20)
NEXT = GridCell(10, 21)
FAR = GridCell(40, 40)
BASE = Position(37.48760, 126.91330)
POS_REL = BASE.offset(0, -480)
POS_SEALED = BASE.offset(200, 150)


class Fixture:
    """가상 인물·가구로 구성한 테스트 환경."""

    def __init__(self):
        self.clock = MutableClock(datetime(2026, 7, 15, 12, 40, tzinfo=timezone.utc))
        self.sys = EmergencyEnvelopeSystem(self.clock)
        s = self.sys
        s.register_helper(Helper("P-1", HelperKind.PARTNER, CELL, frozenset({Capability.WHEELCHAIR})))
        s.register_helper(Helper("P-2", HelperKind.PARTNER, NEXT, frozenset({Capability.WHEELCHAIR})))
        s.register_helper(Helper("C-1", HelperKind.CITIZEN, CELL))
        s.register_helper(Helper("C-2", HelperKind.CITIZEN, NEXT))
        s.register_building(BuildingProfile("B-1", CELL.id, True, True, True, 1200))
        s.register_building(BuildingProfile("B-2", NEXT.id, False, False, False, 200))
        self.relational = s.register(Registration(
            CELL, POS_REL, "B-1", Capability.WHEELCHAIR,
            {Field.UNIT: "B01호", Field.STATUS: "휠체어", Field.ESCAPE_ROUTE: "창문 쪽 방",
             Field.EMERGENCY_CONTACT: "010-0000-0000"},
            frozenset(f for f in Field if f.consentable), "P-1"))
        self.sealed = s.register(Registration(
            NEXT, POS_SEALED, "B-2", Capability.GENERAL,
            {Field.UNIT: "201호", Field.STATUS: "거동 불편", Field.ESCAPE_ROUTE: "현관",
             Field.EMERGENCY_CONTACT: "010-1111-1111"},
            frozenset(f for f in Field if f.consentable), None))

    def warning(self, *cells):
        return self.sys.alert_issuer.issue(AlertLevel.WARNING, {c.id for c in cells}, timedelta(hours=2))

    def advisory(self, *cells):
        return self.sys.alert_issuer.issue(AlertLevel.ADVISORY, {c.id for c in cells}, timedelta(hours=2))


@pytest.fixture
def f():
    return Fixture()
