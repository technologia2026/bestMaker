package com.bestmaker.envelope.app;

import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.GridCell;
import com.bestmaker.envelope.common.HelperKind;
import com.bestmaker.envelope.common.MutableClock;
import com.bestmaker.envelope.disclosure.Field;
import com.bestmaker.envelope.disclosure.HelperView;
import com.bestmaker.envelope.evidence.AlertIssuer;
import com.bestmaker.envelope.evidence.AlertLevel;
import com.bestmaker.envelope.evidence.HomeDevice;
import com.bestmaker.envelope.evidence.OfficialAlert;
import com.bestmaker.envelope.evidence.SignalType;
import com.bestmaker.envelope.matching.Helper;
import com.bestmaker.envelope.policy.BuildingProfile;
import com.bestmaker.envelope.policy.RainObservation;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.ZoneId;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 결선 시연 6장면을 콘솔로 재현한다. 모든 인물·주소·연락처는 가상이다.
 * 실행: mvn -q compile exec:java
 */
public final class Demo {
    private static final GridCell CELL_A = new GridCell(10, 20);
    private static final GridCell CELL_B = new GridCell(10, 21);

    private Demo() {
    }

    public static void main(String[] args) {
        MutableClock clock = new MutableClock(
                ZonedDateTime.of(2026, 7, 15, 21, 40, 0, 0, ZoneId.of("Asia/Seoul")).toInstant());
        EmergencyEnvelopeSystem sys = new EmergencyEnvelopeSystem(clock);

        sys.registerHelper(new Helper("P-1", HelperKind.PARTNER, CELL_A, Set.of()));
        sys.registerHelper(new Helper("P-2", HelperKind.PARTNER, CELL_B, Set.of(Capability.WHEELCHAIR)));
        sys.registerHelper(new Helper("C-1", HelperKind.CITIZEN, CELL_A, Set.of(Capability.MOBILITY_AID)));

        sys.registerBuilding(new BuildingProfile("B-001", CELL_A.id(), true, true, true, 1200));
        sys.registerBuilding(new BuildingProfile("B-002", CELL_B.id(), false, false, false, 300));

        String h1 = sys.register(new Registration(CELL_A, "B-001", Capability.WHEELCHAIR,
                Map.of(Field.UNIT, "B01호", Field.STATUS, "휠체어 사용, 야간 단독 거주",
                        Field.ESCAPE_ROUTE, "창문 쪽 방 (골목 방향)", Field.EMERGENCY_CONTACT, "010-0000-0000 (가상)"),
                EnumSet.of(Field.UNIT, Field.STATUS, Field.ESCAPE_ROUTE, Field.EMERGENCY_CONTACT), "P-1"));
        String h2 = sys.register(new Registration(CELL_B, "B-002", Capability.MOBILITY_AID,
                Map.of(Field.UNIT, "2층 201호", Field.ESCAPE_ROUTE, "현관 계단"),
                EnumSet.of(Field.UNIT, Field.ESCAPE_ROUTE), null));
        sys.installDevice(h1);
        HomeDevice device1 = sys.devices(h1);
        HomeDevice device2 = sys.installDevice(h2);

        scene("1. 평시 — 담당자가 명단 열람 시도");
        try {
            sys.officialAttemptOpen("official-kim", h1, List.of());
        } catch (DeniedException e) {
            say("거부: " + e.getMessage());
        }
        say("DB에서 보이는 것: " + sys.household(h1));

        scene("2. 비 예보 — 준비는 미리, 공개는 나중에");
        AlertIssuer issuer = sys.alertIssuer();
        OfficialAlert advisory = issuer.issue(AlertLevel.ADVISORY, Set.of(CELL_A.id(), CELL_B.id()),
                Duration.ofHours(3));
        sys.ingest(advisory);
        sys.observeRain(new RainObservation(CELL_A.id(), 1, 5, 2));
        say("단계: " + sys.evaluate());
        sys.standbyNotices().forEach((id, msg) -> say("  " + id + " 화면: " + msg));

        scene("3. 폭우 — 가장 가까운 이웃 한 명이 연다");
        clock.advance(Duration.ofMinutes(20));
        sys.observeRain(new RainObservation(CELL_A.id(), 15, 50, 25));
        say("단계: " + sys.evaluate());
        say("P-1 요청: " + sys.offersFor("P-1"));
        clock.advance(Duration.ofMinutes(3));
        sys.tick();
        say("지정 조력자 3분 무응답 → 자동 확장");
        say("P-2 요청: " + sys.offersFor("P-2"));
        String token = sys.accept("P-2", h1, "phone-P2");
        HelperView before = sys.view(token, "phone-P2");
        say("도착 전 화면: " + before.fields());
        sys.moveHelper("P-2", CELL_A);
        sys.confirmArrival(token, "phone-P2", CELL_A, device1.arrivalCode());
        HelperView after = sys.view(token, "phone-P2");
        say("도착 확인 후: " + after.fields() + "  [워터마크 " + after.watermark() + "]");

        scene("4. 가짜 경보 — 서명 검증에서 거부");
        try {
            sys.ingest(advisory.withLevel(AlertLevel.WARNING));
        } catch (DeniedException e) {
            say("예보를 경보로 바꿔치기: " + e.getMessage());
        }
        try {
            sys.ingest(new AlertIssuer("collector-1", clock).issue(AlertLevel.WARNING, Set.of(CELL_A.id()),
                    Duration.ofHours(1)));
        } catch (DeniedException e) {
            say("공격자 키로 서명한 경보: " + e.getMessage());
        }
        try {
            sys.ingest(advisory);
        } catch (DeniedException e) {
            say("같은 경보 재전송: " + e.getMessage());
        }

        scene("5. 물컵 — 수위 센서가 예보 없이도 즉시 연다");
        sys.ingest(device2.signal(SignalType.WATER_LEVEL));
        say("단계: " + sys.evaluate());
        say("봉인형 가구 + 동행파트너는 모두 부적합·배정 중 → 시민 조력자 C-1 요청: " + sys.offersFor("C-1"));

        scene("6. 종료 — 자동 재봉인과 열람 통지");
        clock.advance(Duration.ofMinutes(61));
        sys.clearAlert(advisory.alertId());
        say("단계: " + sys.evaluate());
        try {
            sys.view(token, "phone-P2");
        } catch (DeniedException e) {
            say("P-2 화면 새로고침: " + e.getMessage());
        }
        say("당사자 통지:");
        sys.notifications(h1).forEach(n -> say("  " + n));
        sys.anchorAuditLog();
        say("감사 로그 " + sys.auditLog().entries().size() + "건, 보관 기관 앵커 대조: "
                + (sys.auditLogIntact() ? "무결" : "조작 탐지"));
    }

    private static void scene(String title) {
        System.out.println();
        System.out.println("━━ " + title);
    }

    private static void say(String s) {
        System.out.println("  " + s);
    }
}
