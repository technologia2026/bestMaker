package com.bestmaker.envelope;

import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.crypto.Layer;
import com.bestmaker.envelope.custodian.KeyCustodian;
import com.bestmaker.envelope.custodian.OpenRequest;
import com.bestmaker.envelope.custodian.Requester;
import com.bestmaker.envelope.evidence.AlertIssuer;
import com.bestmaker.envelope.evidence.AlertLevel;
import com.bestmaker.envelope.evidence.EscalationReason;
import com.bestmaker.envelope.evidence.EscalationSigner;
import com.bestmaker.envelope.evidence.Evidence;
import com.bestmaker.envelope.evidence.HomeDevice;
import com.bestmaker.envelope.evidence.OfficialAlert;
import com.bestmaker.envelope.evidence.SignalType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 기획서 12. 검증 계획의 보안 시나리오: 모두 실패해야 통과. */
class SecurityScenarioTest {
    private final Fixture f = new Fixture();

    @Test
    void officialCannotOpenEvenDuringRealWarning() {
        OfficialAlert w = f.warning(Fixture.CELL);
        f.sys.ingest(w);
        assertThrows(DeniedException.class,
                () -> f.sys.officialAttemptOpen("official-kim", f.relational, List.of(w)));
        assertThrows(DeniedException.class, () -> f.sys.officialAttemptOpen("official-kim", f.relational, List.of()));
    }

    @Test
    void peacetimeOpenIsDeniedByEveryCustodianAndRecorded() {
        assertThrows(DeniedException.class, () -> f.sys.officialAttemptOpen("official-kim", f.relational, List.of()));
        for (KeyCustodian c : f.sys.custodians()) {
            assertEquals(1, c.decisions().size());
            assertFalse(c.decisions().get(0).granted());
        }
        assertTrue(f.sys.notifications(f.relational).get(0).contains("열람 시도 거부됨"));
    }

    @Test
    void helperCannotOpenWithoutEvidence() {
        OpenRequest req = new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), List.of());
        for (KeyCustodian c : f.sys.custodians()) {
            assertThrows(DeniedException.class, () -> c.release(req));
        }
    }

    @Test
    void forgedAlertsAreRejected() {
        OfficialAlert adv = f.advisory(Fixture.CELL);
        assertThrows(DeniedException.class, () -> f.sys.ingest(adv.withLevel(AlertLevel.WARNING)));
        assertThrows(DeniedException.class, () -> f.sys.ingest(adv.withCells(Set.of(Fixture.FAR.id()))));
        OfficialAlert attacker = new AlertIssuer("collector-1", f.clock)
                .issue(AlertLevel.WARNING, Set.of(Fixture.CELL.id()), Duration.ofHours(1));
        assertThrows(DeniedException.class, () -> f.sys.ingest(attacker));
        // 보관 기관도 독립적으로 거부
        OpenRequest req = new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"),
                List.of(attacker));
        f.sys.custodians().forEach(c -> assertThrows(DeniedException.class, () -> c.release(req)));
    }

    @Test
    void replayedAlertIsRejected() {
        OfficialAlert w = f.warning(Fixture.CELL);
        f.sys.ingest(w);
        assertThrows(DeniedException.class, () -> f.sys.ingest(w));
    }

    @Test
    void expiredAlertCannotOpen() {
        OfficialAlert w = f.warning(Fixture.CELL);
        f.clock.advance(Duration.ofHours(3));
        OpenRequest req = new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), List.of(w));
        f.sys.custodians().forEach(c -> assertThrows(DeniedException.class, () -> c.release(req)));
    }

    @Test
    void alertForAnotherGridCannotOpenThisHousehold() {
        OfficialAlert w = f.warning(Fixture.FAR);
        OpenRequest req = new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), List.of(w));
        f.sys.custodians().forEach(c -> assertThrows(DeniedException.class, () -> c.release(req)));
    }

    @Test
    void advisoryOpensOnlyEnvelope1ForPolicyEngine() {
        OfficialAlert adv = f.advisory(Fixture.CELL);
        KeyCustodian c = f.sys.custodians().get(0);
        c.release(new OpenRequest(f.relational, Layer.ENVELOPE_1, Requester.policyEngine(), List.of(adv)));
        assertThrows(DeniedException.class, () -> c.release(
                new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), List.of(adv))));
        assertThrows(DeniedException.class, () -> c.release(
                new OpenRequest(f.relational, Layer.ENVELOPE_1, Requester.helper("P-1"), List.of(adv))));
    }

    @Test
    void compromisedAnalysisCannotOpenOnAClearDay() {
        // 공격자가 정책 엔진의 앞당기기 키를 쥐었다고 가정해도, 공식 예보 없이는 열리지 않는다
        EscalationSigner stolen = new EscalationSigner("policy-1", f.clock);
        OfficialAlert fakeAdvisoryRef = new AlertIssuer("x", f.clock)
                .issue(AlertLevel.ADVISORY, Set.of(Fixture.CELL.id()), Duration.ofHours(1));
        Evidence x = stolen.sign(fakeAdvisoryRef, Fixture.CELL.id(), EscalationReason.HIGH_RISK, 0.99);
        OpenRequest req = new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), List.of(x));
        f.sys.custodians().forEach(c -> assertThrows(DeniedException.class, () -> c.release(req)));
    }

    @Test
    void deviceSignalOpensOnlyItsOwnHousehold() {
        HomeDevice dev = f.sys.installDevice(f.sealed);
        Evidence sig = dev.signal(SignalType.EMERGENCY_BUTTON);
        KeyCustodian c = f.sys.custodians().get(0);
        c.release(new OpenRequest(f.sealed, Layer.ENVELOPE_2, Requester.helper("C-2"), List.of(sig)));
        assertThrows(DeniedException.class, () -> c.release(
                new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-2"), List.of(sig))));
    }

    @Test
    void replayedDeviceSignalIsRejected() {
        HomeDevice dev = f.sys.installDevice(f.sealed);
        Evidence first = dev.signal(SignalType.WATER_LEVEL);
        f.sys.ingest(first);
        assertThrows(DeniedException.class, () -> f.sys.ingest(first));
        f.sys.ingest(dev.signal(SignalType.WATER_LEVEL));
    }

    @Test
    void singleCompromisedCustodianCannotRestoreKey() {
        OfficialAlert w = f.warning(Fixture.CELL);
        // 한 기관만 조각을 내줘도 조합기는 2개 미만이면 거부한다
        var combiner = new com.bestmaker.envelope.custodian.KeyCombiner(List.of(f.sys.custodians().get(0)));
        OpenRequest req = new OpenRequest(f.relational, Layer.ENVELOPE_2, Requester.helper("P-1"), List.of(w));
        assertThrows(DeniedException.class, () -> combiner.open(req, f.sys.envelope(f.relational, Layer.ENVELOPE_2)));
    }

    @Test
    void clearSkyStaysSealed() {
        assertTrue(f.sys.evaluate().values().stream().allMatch(s -> s == Stage.PEACETIME));
        assertTrue(f.sys.offersFor("P-1").isEmpty());
    }
}
