import threading
from datetime import timedelta

import pytest

from conftest import CELL, FAR, NEXT
from emergency_envelope.common import Denied, Stage, TrustTier
from emergency_envelope.crypto import Layer
from emergency_envelope.custodian import OpenRequest, Requester
from emergency_envelope.disclosure import MAX_ARRIVAL_ATTEMPTS, Field
from emergency_envelope.evidence import SignalType
from emergency_envelope.policy import RainObservation


def wrong_code(dev):
    return "111111" if dev.arrival_code() == "000000" else "000000"


def to_citizen(f):
    f.sys.ingest(f.warning(NEXT))
    f.sys.evaluate()
    f.sys.decline("P-1", f.sealed)
    f.sys.decline("P-2", f.sealed)


def test_advisory_prepares_without_disclosing(f):
    f.sys.ingest(f.advisory(CELL, NEXT))
    stages = f.sys.evaluate()
    assert stages[f.relational] is Stage.PREPARE and stages[f.sealed] is Stage.PREPARE
    assert f.sys.offers_for("P-1") == []
    notices = f.sys.standby_notices()
    assert notices["P-1"] == "담당 가구 대기 요청"
    assert "주소 없음" in notices["C-1"]


def test_static_building_risk_alone_does_not_escalate(f):
    f.sys.ingest(f.advisory(CELL))
    f.sys.observe_rain(RainObservation(CELL.id, 0, 0, 0))
    assert f.sys.evaluate()[f.relational] is Stage.PREPARE


def test_advisory_plus_heavy_rain_escalates_high_risk_building_only(f):
    f.sys.ingest(f.advisory(CELL, NEXT))
    f.sys.observe_rain(RainObservation(CELL.id, 15, 50, 25))
    f.sys.observe_rain(RainObservation(NEXT.id, 15, 50, 25))
    stages = f.sys.evaluate()
    assert stages[f.relational] is Stage.OPEN
    assert stages[f.sealed] is Stage.PREPARE  # 저위험 건물은 준비 유지


def test_conservative_mode_opens_advisory_grid_when_feed_is_lost(f):
    f.sys.ingest(f.advisory(NEXT))
    f.sys.policy.feed_healthy = False
    assert f.sys.evaluate()[f.sealed] is Stage.OPEN


def test_designated_first_then_escalates_on_timeout(f):
    f.sys.ingest(f.warning(CELL))
    f.sys.evaluate()
    assert f.sys.offers_for("P-1")[0].tier is TrustTier.DESIGNATED
    assert f.sys.offers_for("P-2") == []
    f.clock.advance(timedelta(minutes=3))
    f.sys.tick()
    assert f.sys.offers_for("P-2")[0].tier is TrustTier.EXTENDED_A


def test_sealed_household_goes_to_partners_before_citizens(f):
    f.sys.ingest(f.warning(NEXT))
    f.sys.evaluate()
    assert f.sys.offers_for("P-1")[0].tier is TrustTier.EXTENDED_A
    assert f.sys.offers_for("P-2")[0].tier is TrustTier.EXTENDED_A
    assert f.sys.offers_for("C-2") == []


def test_designated_sees_consented_fields_immediately(f):
    f.sys.ingest(f.warning(CELL))
    f.sys.evaluate()
    v = f.sys.view(f.sys.accept("P-1", f.relational, "phone-1"), "phone-1")
    assert v.fields[Field.UNIT] == "B01호"
    assert v.fields[Field.EMERGENCY_CONTACT] == "010-0000-0000"


def test_extended_b_sees_only_direction_before_arrival_and_minimum_after(f):
    dev = f.sys.install_device(f.sealed)
    to_citizen(f)
    assert f.sys.offers_for("C-2")[0].tier is TrustTier.EXTENDED_B
    token = f.sys.accept("C-2", f.sealed, "phone-c2")
    assert set(f.sys.view(token, "phone-c2").fields) == {Field.DIRECTION, Field.NEED_TYPE}
    with pytest.raises(Denied):
        f.sys.confirm_arrival(token, "phone-c2", NEXT, wrong_code(dev))
    with pytest.raises(Denied):
        f.sys.confirm_arrival(token, "phone-c2", FAR, dev.arrival_code())
    f.sys.confirm_arrival(token, "phone-c2", NEXT, dev.arrival_code())
    assert set(f.sys.view(token, "phone-c2").fields) == {Field.DIRECTION, Field.NEED_TYPE, Field.UNIT, Field.ESCAPE_ROUTE}


def test_extended_b_without_home_device_cannot_confirm_arrival(f):
    to_citizen(f)
    token = f.sys.accept("C-2", f.sealed, "phone-c2")
    with pytest.raises(Denied):
        f.sys.confirm_arrival(token, "phone-c2", NEXT, "123456")


def test_arrival_attempts_are_limited(f):
    dev = f.sys.install_device(f.relational)
    f.sys.ingest(f.warning(CELL))
    f.sys.evaluate()
    f.clock.advance(timedelta(minutes=3))
    f.sys.tick()
    token = f.sys.accept("P-2", f.relational, "phone-2")
    for _ in range(MAX_ARRIVAL_ATTEMPTS):
        with pytest.raises(Denied):
            f.sys.confirm_arrival(token, "phone-2", CELL, wrong_code(dev))
    with pytest.raises(Denied):
        f.sys.confirm_arrival(token, "phone-2", CELL, dev.arrival_code())


def test_token_is_bound_to_device_and_expires(f):
    f.sys.ingest(f.warning(CELL))
    f.sys.evaluate()
    token = f.sys.accept("P-1", f.relational, "phone-1")
    with pytest.raises(Denied):
        f.sys.view(token, "other-phone")
    with pytest.raises(Denied):
        f.sys.view("forged-token", "phone-1")
    f.clock.advance(timedelta(minutes=31))
    with pytest.raises(Denied):
        f.sys.view(token, "phone-1")


def test_concurrent_accepts_yield_exactly_one_assignment(f):
    to_citizen(f)
    barrier = threading.Barrier(16)
    ok = []

    def worker(helper):
        barrier.wait()
        try:
            f.sys.matching.accept(helper, f.sealed)
            ok.append(helper)
        except Denied:
            pass

    threads = [threading.Thread(target=worker, args=(("C-1", "C-2")[i % 2],)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert len(ok) == 1


def test_helper_can_hold_only_one_household_at_a_time(f):
    f.sys.ingest(f.warning(CELL, NEXT))
    f.sys.evaluate()
    f.sys.accept("P-1", f.relational, "phone-1")
    assert f.sys.offers_for("P-1") == []
    with pytest.raises(Denied):
        f.sys.matching.accept("P-1", f.sealed)


def test_abandon_hands_off_to_next_helper(f):
    f.sys.ingest(f.warning(CELL))
    f.sys.evaluate()
    f.sys.accept("P-1", f.relational, "phone-1")
    f.sys.abandon("P-1", f.relational)
    assert f.sys.offers_for("P-2")


def test_device_signal_opens_immediately_without_any_forecast(f):
    f.sys.ingest(f.sys.install_device(f.sealed).signal(SignalType.WATER_LEVEL))
    stages = f.sys.evaluate()
    assert stages[f.sealed] is Stage.OPEN
    assert stages[f.relational] is Stage.PEACETIME


def test_end_of_alert_reseals_and_notifies(f):
    w = f.warning(CELL)
    f.sys.ingest(w)
    f.sys.evaluate()
    token = f.sys.accept("P-1", f.relational, "phone-1")
    f.sys.view(token, "phone-1")
    f.sys.clear_alert(w.alert_id)
    with pytest.raises(Denied):
        f.sys.view(token, "phone-1")
    assert f.sys.active_disclosures() == 0
    notes = f.sys.notifications(f.relational)
    assert any("지정 조력자 1명 열람" in n and "공식 침수경보" in n for n in notes)
    assert any("재봉인" in n for n in notes)


def test_repeated_abandons_suspend_helper_and_custodians_stop_releasing(f):
    w = f.warning(CELL, NEXT)
    f.sys.ingest(w)
    f.sys.evaluate()
    f.sys.accept("P-1", f.relational, "phone-1")
    f.sys.abandon("P-1", f.relational)
    f.sys.decline("P-2", f.sealed)
    f.sys.accept("P-1", f.sealed, "phone-1")
    f.sys.abandon("P-1", f.sealed)
    assert any(x.actor == "P-1" for x in f.sys.detect_anomalies())
    assert f.sys.offers_for("P-1") == []
    req = OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), (w,))
    for c in f.sys.custodians:
        with pytest.raises(Denied):
            c.release(req)


def test_audit_log_is_anchored_at_custodians(f):
    f.sys.ingest(f.warning(CELL))
    f.sys.evaluate()
    f.sys.anchor_audit_log()
    assert f.sys.audit_log_intact()
