package com.bestmaker.envelope;

import com.bestmaker.envelope.anomaly.Finding;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.common.TrustTier;
import com.bestmaker.envelope.disclosure.DisclosureService;
import com.bestmaker.envelope.disclosure.Field;
import com.bestmaker.envelope.disclosure.HelperView;
import com.bestmaker.envelope.evidence.HomeDevice;
import com.bestmaker.envelope.evidence.OfficialAlert;
import com.bestmaker.envelope.evidence.SignalType;
import com.bestmaker.envelope.policy.RainObservation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FlowTest {
    private final Fixture f = new Fixture();

    @Test
    void advisoryPreparesWithoutDisclosing() {
        f.sys.ingest(f.advisory(Fixture.CELL, Fixture.NEXT));
        var stages = f.sys.evaluate();
        assertEquals(Stage.PREPARE, stages.get(f.relational));
        assertEquals(Stage.PREPARE, stages.get(f.sealed));
        assertTrue(f.sys.offersFor("P-1").isEmpty());
        assertEquals("담당 가구 대기 요청", f.sys.standbyNotices().get("P-1"));
        assertTrue(f.sys.standbyNotices().get("C-1").contains("주소 없음"));
    }

    @Test
    void staticBuildingRiskAloneDoesNotEscalate() {
        f.sys.ingest(f.advisory(Fixture.CELL));
        f.sys.observeRain(new RainObservation(Fixture.CELL.id(), 0, 0, 0));
        assertEquals(Stage.PREPARE, f.sys.evaluate().get(f.relational));
    }

    @Test
    void advisoryPlusHeavyRainEscalatesHighRiskBuildingOnly() {
        f.sys.ingest(f.advisory(Fixture.CELL, Fixture.NEXT));
        f.sys.observeRain(new RainObservation(Fixture.CELL.id(), 15, 50, 25));
        f.sys.observeRain(new RainObservation(Fixture.NEXT.id(), 15, 50, 25));
        var stages = f.sys.evaluate();
        assertEquals(Stage.OPEN, stages.get(f.relational));
        assertEquals(Stage.PREPARE, stages.get(f.sealed), "저위험 건물은 준비 단계 유지");
    }

    @Test
    void conservativeModeOpensAdvisoryGridWhenFeedIsLost() {
        f.sys.ingest(f.advisory(Fixture.NEXT));
        f.sys.policy().setFeedHealthy(false);
        assertEquals(Stage.OPEN, f.sys.evaluate().get(f.sealed));
    }

    @Test
    void designatedFirstThenEscalatesOnTimeout() {
        f.sys.ingest(f.warning(Fixture.CELL));
        f.sys.evaluate();
        assertEquals(TrustTier.DESIGNATED, f.sys.offersFor("P-1").get(0).tier());
        assertTrue(f.sys.offersFor("P-2").isEmpty());
        f.clock.advance(Duration.ofMinutes(3));
        f.sys.tick();
        assertEquals(TrustTier.EXTENDED_A, f.sys.offersFor("P-2").get(0).tier());
    }

    @Test
    void sealedHouseholdGoesStraightToExtendedHelpers() {
        f.sys.ingest(f.warning(Fixture.NEXT));
        f.sys.evaluate();
        assertEquals(TrustTier.EXTENDED_A, f.sys.offersFor("P-2").get(0).tier());
        assertEquals(TrustTier.EXTENDED_A, f.sys.offersFor("P-1").get(0).tier());
        assertTrue(f.sys.offersFor("C-2").isEmpty(), "시민은 동행파트너 다음 순서");
    }

    @Test
    void designatedSeesConsentedFieldsImmediately() {
        f.sys.ingest(f.warning(Fixture.CELL));
        f.sys.evaluate();
        String token = f.sys.accept("P-1", f.relational, "phone-1");
        HelperView v = f.sys.view(token, "phone-1");
        assertEquals("B01호", v.fields().get(Field.UNIT));
        assertEquals("010-0000-0000", v.fields().get(Field.EMERGENCY_CONTACT));
    }

    @Test
    void extendedBSeesOnlyDirectionBeforeArrivalAndMinimumAfter() {
        HomeDevice dev = f.sys.installDevice(f.sealed);
        f.sys.ingest(f.warning(Fixture.NEXT));
        f.sys.evaluate();
        // 동행파트너가 모두 거절 → 시민에게
        f.sys.decline("P-1", f.sealed);
        f.sys.decline("P-2", f.sealed);
        assertEquals(TrustTier.EXTENDED_B, f.sys.offersFor("C-2").get(0).tier());
        String token = f.sys.accept("C-2", f.sealed, "phone-c2");

        HelperView before = f.sys.view(token, "phone-c2");
        assertEquals(EnumSet.of(Field.DIRECTION, Field.NEED_TYPE), before.fields().keySet());

        assertThrows(DeniedException.class,
                () -> f.sys.confirmArrival(token, "phone-c2", Fixture.NEXT, "000000".equals(dev.arrivalCode())
                        ? "111111" : "000000"));
        assertThrows(DeniedException.class,
                () -> f.sys.confirmArrival(token, "phone-c2", Fixture.FAR, dev.arrivalCode()));
        f.sys.confirmArrival(token, "phone-c2", Fixture.NEXT, dev.arrivalCode());
        HelperView after = f.sys.view(token, "phone-c2");
        assertEquals(EnumSet.of(Field.DIRECTION, Field.NEED_TYPE, Field.UNIT, Field.ESCAPE_ROUTE),
                after.fields().keySet());
    }

    @Test
    void extendedBWithoutHomeDeviceCannotConfirmArrival() {
        f.sys.ingest(f.warning(Fixture.NEXT));
        f.sys.evaluate();
        f.sys.decline("P-1", f.sealed);
        f.sys.decline("P-2", f.sealed);
        String token = f.sys.accept("C-2", f.sealed, "phone-c2");
        assertThrows(DeniedException.class, () -> f.sys.confirmArrival(token, "phone-c2", Fixture.NEXT, "123456"));
    }

    @Test
    void arrivalAttemptsAreLimited() {
        HomeDevice dev = f.sys.installDevice(f.relational);
        f.sys.ingest(f.warning(Fixture.CELL));
        f.sys.evaluate();
        f.clock.advance(Duration.ofMinutes(3));
        f.sys.tick();
        String token = f.sys.accept("P-2", f.relational, "phone-2");
        String wrong = "000000".equals(dev.arrivalCode()) ? "111111" : "000000";
        for (int i = 0; i < DisclosureService.MAX_ARRIVAL_ATTEMPTS; i++) {
            assertThrows(DeniedException.class, () -> f.sys.confirmArrival(token, "phone-2", Fixture.CELL, wrong));
        }
        assertThrows(DeniedException.class,
                () -> f.sys.confirmArrival(token, "phone-2", Fixture.CELL, dev.arrivalCode()));
    }

    @Test
    void tokenIsBoundToDeviceAndExpires() {
        f.sys.ingest(f.warning(Fixture.CELL));
        f.sys.evaluate();
        String token = f.sys.accept("P-1", f.relational, "phone-1");
        assertThrows(DeniedException.class, () -> f.sys.view(token, "other-phone"));
        assertThrows(DeniedException.class, () -> f.sys.view("forged-token", "phone-1"));
        f.clock.advance(Duration.ofMinutes(31));
        assertThrows(DeniedException.class, () -> f.sys.view(token, "phone-1"));
    }

    @Test
    void concurrentAcceptsYieldExactlyOneAssignment() throws Exception {
        f.sys.ingest(f.warning(Fixture.NEXT));
        f.sys.evaluate();
        f.sys.decline("P-1", f.sealed);
        f.sys.decline("P-2", f.sealed);
        List<String> candidates = List.of("C-1", "C-2");
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            String helper = candidates.get(i % 2);
            futures.add(pool.submit(() -> {
                go.await();
                try {
                    f.sys.matching().accept(helper, f.sealed);
                    ok.incrementAndGet();
                } catch (DeniedException expected) {
                    // 다른 조력자가 먼저 수락
                }
                return null;
            }));
        }
        go.countDown();
        for (Future<?> fu : futures) {
            fu.get(5, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertEquals(1, ok.get());
    }

    @Test
    void helperCanHoldOnlyOneHouseholdAtATime() {
        f.sys.ingest(f.warning(Fixture.CELL, Fixture.NEXT));
        f.sys.evaluate();
        f.sys.accept("P-1", f.relational, "phone-1");
        assertTrue(f.sys.offersFor("P-1").isEmpty());
        assertThrows(DeniedException.class, () -> f.sys.matching().accept("P-1", f.sealed));
    }

    @Test
    void abandonHandsOffToNextHelper() {
        f.sys.ingest(f.warning(Fixture.CELL));
        f.sys.evaluate();
        f.sys.accept("P-1", f.relational, "phone-1");
        f.sys.abandon("P-1", f.relational);
        assertFalse(f.sys.offersFor("P-2").isEmpty());
    }

    @Test
    void deviceSignalOpensImmediatelyWithoutAnyForecast() {
        HomeDevice dev = f.sys.installDevice(f.sealed);
        f.sys.ingest(dev.signal(SignalType.WATER_LEVEL));
        var stages = f.sys.evaluate();
        assertEquals(Stage.OPEN, stages.get(f.sealed));
        assertEquals(Stage.PEACETIME, stages.get(f.relational));
    }

    @Test
    void endOfAlertResealsAndNotifies() {
        OfficialAlert w = f.warning(Fixture.CELL);
        f.sys.ingest(w);
        f.sys.evaluate();
        String token = f.sys.accept("P-1", f.relational, "phone-1");
        f.sys.view(token, "phone-1");
        f.sys.clearAlert(w.alertId());
        assertThrows(DeniedException.class, () -> f.sys.view(token, "phone-1"));
        assertEquals(0, f.sys.activeDisclosures());
        List<String> notes = f.sys.notifications(f.relational);
        assertTrue(notes.stream().anyMatch(n -> n.contains("지정 조력자 1명 열람") && n.contains("공식 침수경보")));
        assertTrue(notes.stream().anyMatch(n -> n.contains("재봉인")));
    }

    @Test
    void repeatedAbandonsSuspendHelperAndCustodiansStopReleasing() {
        OfficialAlert w = f.warning(Fixture.CELL, Fixture.NEXT);
        f.sys.ingest(w);
        f.sys.evaluate();
        f.sys.accept("P-1", f.relational, "phone-1");
        f.sys.abandon("P-1", f.relational);
        f.sys.decline("P-2", f.sealed);
        f.sys.accept("P-1", f.sealed, "phone-1");
        f.sys.abandon("P-1", f.sealed);
        List<Finding> findings = f.sys.detectAnomalies();
        assertTrue(findings.stream().anyMatch(x -> x.actor().equals("P-1")));
        assertTrue(f.sys.offersFor("P-1").isEmpty());
        var req = new com.bestmaker.envelope.custodian.OpenRequest(f.relational,
                com.bestmaker.envelope.crypto.Layer.ENVELOPE_2,
                com.bestmaker.envelope.custodian.Requester.helper("P-1"), List.of(w));
        f.sys.custodians().forEach(c -> assertThrows(DeniedException.class, () -> c.release(req)));
    }

    @Test
    void auditLogIsAnchoredAtCustodians() {
        f.sys.ingest(f.warning(Fixture.CELL));
        f.sys.evaluate();
        f.sys.anchorAuditLog();
        assertTrue(f.sys.auditLogIntact());
    }
}
