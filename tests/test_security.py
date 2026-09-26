"""기획서 12. 검증 계획의 보안 시나리오: 모두 실패해야 통과."""
from dataclasses import replace
from datetime import timedelta

import pytest

from conftest import CELL, FAR
from emergency_envelope.common import Denied, Stage
from emergency_envelope.crypto import Layer
from emergency_envelope.custodian import KeyCombiner, OpenRequest, Requester
from emergency_envelope.evidence import AlertIssuer, AlertLevel, EscalationReason, EscalationSigner, SignalType


def helper_req(hid, helper, *evidence):
    return OpenRequest(hid, Layer.ENVELOPE_2, Requester.helper(helper), tuple(evidence))


def all_deny(f, req):
    for c in f.sys.custodians:
        with pytest.raises(Denied):
            c.release(req)


def test_official_cannot_open_even_during_real_warning(f):
    w = f.warning(CELL)
    f.sys.ingest(w)
    with pytest.raises(Denied):
        f.sys.official_attempt_open("official-kim", f.relational, (w,))


def test_peacetime_open_is_denied_by_every_custodian_and_recorded(f):
    with pytest.raises(Denied):
        f.sys.official_attempt_open("official-kim", f.relational)
    for c in f.sys.custodians:
        assert [d.granted for d in c.decisions()] == [False]
    assert "열람 시도 거부됨" in f.sys.notifications(f.relational)[0]


def test_helper_cannot_open_without_evidence(f):
    all_deny(f, helper_req(f.relational, "P-1"))


def test_forged_alerts_are_rejected(f):
    adv = f.advisory(CELL)
    with pytest.raises(Denied):
        f.sys.ingest(replace(adv, level=AlertLevel.WARNING))
    with pytest.raises(Denied):
        f.sys.ingest(replace(adv, grid_cells=frozenset({FAR.id})))
    attacker = AlertIssuer("collector-1", f.clock).issue(AlertLevel.WARNING, {CELL.id}, timedelta(hours=1))
    with pytest.raises(Denied):
        f.sys.ingest(attacker)
    all_deny(f, helper_req(f.relational, "P-1", attacker))  # 보관 기관도 독립적으로 거부


def test_replayed_alert_is_rejected(f):
    w = f.warning(CELL)
    f.sys.ingest(w)
    with pytest.raises(Denied):
        f.sys.ingest(w)


def test_expired_alert_cannot_open(f):
    w = f.warning(CELL)
    f.clock.advance(timedelta(hours=3))
    all_deny(f, helper_req(f.relational, "P-1", w))


def test_alert_for_another_grid_cannot_open(f):
    all_deny(f, helper_req(f.relational, "P-1", f.warning(FAR)))


def test_advisory_opens_only_envelope1_for_policy_engine(f):
    adv = f.advisory(CELL)
    c = f.sys.custodians[0]
    c.release(OpenRequest(f.relational, Layer.ENVELOPE_1, Requester.policy_engine(), (adv,)))
    with pytest.raises(Denied):
        c.release(helper_req(f.relational, "P-1", adv))
    with pytest.raises(Denied):
        c.release(OpenRequest(f.relational, Layer.ENVELOPE_1, Requester.helper("P-1"), (adv,)))


def test_compromised_analysis_cannot_open_on_a_clear_day(f):
    # 정책 엔진의 앞당기기 키를 공격자가 쥐었다고 가정해도, 공식 예보 없이는 열리지 않는다
    stolen = EscalationSigner("policy-1", f.clock)
    fake_ref = AlertIssuer("x", f.clock).issue(AlertLevel.ADVISORY, {CELL.id}, timedelta(hours=1))
    x = stolen.sign(fake_ref, CELL.id, EscalationReason.HIGH_RISK, 0.99)
    all_deny(f, helper_req(f.relational, "P-1", x))


def test_device_signal_opens_only_its_own_household(f):
    sig = f.sys.install_device(f.sealed).signal(SignalType.EMERGENCY_BUTTON)
    c = f.sys.custodians[0]
    c.release(helper_req(f.sealed, "C-2", sig))
    with pytest.raises(Denied):
        c.release(helper_req(f.relational, "P-2", sig))


def test_replayed_device_signal_is_rejected(f):
    dev = f.sys.install_device(f.sealed)
    first = dev.signal(SignalType.WATER_LEVEL)
    f.sys.ingest(first)
    with pytest.raises(Denied):
        f.sys.ingest(first)
    f.sys.ingest(dev.signal(SignalType.WATER_LEVEL))


def test_single_compromised_custodian_cannot_restore_key(f):
    combiner = KeyCombiner(f.sys.custodians[:1])
    with pytest.raises(Denied):
        combiner.open(helper_req(f.relational, "P-1", f.warning(CELL)), f.sys.envelope(f.relational, Layer.ENVELOPE_2))


def test_clear_sky_stays_sealed(f):
    assert set(f.sys.evaluate().values()) == {Stage.PEACETIME}
    assert f.sys.offers_for("P-1") == []
