from datetime import datetime, timezone

from emergency_envelope.audit import AuditType, HashChainLog
from emergency_envelope.common import MutableClock


class Sink:
    name = "test-sink"

    def __init__(self):
        self.m, self.latest = {}, -1

    def record_anchor(self, seq, h):
        self.m[seq] = h
        self.latest = max(self.latest, seq)

    def anchor_at(self, seq):
        return self.m.get(seq)

    def latest_anchor_seq(self):
        return self.latest


def filled():
    log, sink = HashChainLog(MutableClock(datetime(2026, 7, 15, tzinfo=timezone.utc))), Sink()
    log.append(AuditType.OPEN_DENIED, "HH-1", "official-kim", "OFFICIAL 증거 없음")
    log.append(AuditType.OPEN_GRANTED, "HH-1", "P-1", "근거: 공식 침수경보")
    log.append(AuditType.VIEWED, "HH-1", "P-1", "지정 조력자 1명 열람")
    log.anchor_to([sink])
    return log, sink


def test_intact_chain_verifies():
    log, sink = filled()
    assert log.verify_chain() and log.verify_against([sink])


def test_editing_an_entry_is_detected():
    log, _ = filled()
    log._tamper(0, actor="someone-else")
    assert not log.verify_chain()


def test_rewriting_the_whole_chain_is_detected_by_anchors():
    log, sink = filled()
    # 관리자가 기록을 지우고 해시까지 다시 계산해 새 체인을 만든 경우
    log._truncate(0)
    log.append(AuditType.OPEN_GRANTED, "HH-1", "P-1", "근거: 공식 침수경보")
    assert log.verify_chain()
    assert not log.verify_against([sink])


def test_truncation_after_anchor_is_detected():
    log, sink = filled()
    log._truncate(1)
    assert not log.verify_against([sink])
