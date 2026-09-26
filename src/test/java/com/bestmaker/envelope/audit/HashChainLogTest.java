package com.bestmaker.envelope.audit;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashChainLogTest {
    static final class Sink implements AnchorSink {
        final Map<Long, String> m = new HashMap<>();
        long latest = -1;

        @Override
        public void recordAnchor(long seq, String hash) {
            m.put(seq, hash);
            latest = Math.max(latest, seq);
        }

        @Override
        public String anchorAt(long seq) {
            return m.get(seq);
        }

        @Override
        public long latestAnchorSeq() {
            return latest;
        }
    }

    private final HashChainLog log = new HashChainLog(Clock.systemUTC());
    private final Sink sink = new Sink();

    private void fill() {
        log.append(AuditType.OPEN_DENIED, "HH-1", "official-kim", "OFFICIAL 증거 없음");
        log.append(AuditType.OPEN_GRANTED, "HH-1", "P-1", "근거: 공식 침수경보");
        log.append(AuditType.VIEWED, "HH-1", "P-1", "지정 조력자 1명 열람");
        log.anchorTo(List.of(sink));
    }

    @Test
    void intactChainVerifies() {
        fill();
        assertTrue(log.verifyChain());
        assertTrue(log.verifyAgainst(List.of(sink)));
    }

    @Test
    void editingAnEntryIsDetected() {
        fill();
        AuditEntry e = log.entries().get(0);
        log.tamper(0, new AuditEntry(e.seq(), e.at(), e.type(), e.householdId(), "someone-else", e.detail(),
                e.prevHash(), e.hash()));
        assertFalse(log.verifyChain());
    }

    @Test
    void rewritingTheWholeChainIsDetectedByAnchors() {
        fill();
        // 관리자가 기록을 지우고 해시까지 다시 계산해 새 체인을 만든 경우
        log.truncate(0);
        log.append(AuditType.OPEN_GRANTED, "HH-1", "P-1", "근거: 공식 침수경보");
        assertTrue(log.verifyChain());
        assertFalse(log.verifyAgainst(List.of(sink)));
    }

    @Test
    void truncationAfterAnchorIsDetected() {
        fill();
        log.truncate(1);
        assertFalse(log.verifyAgainst(List.of(sink)));
    }
}
