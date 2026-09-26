package com.bestmaker.envelope;

import com.bestmaker.envelope.app.EmergencyEnvelopeSystem;
import com.bestmaker.envelope.app.Registration;
import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.GridCell;
import com.bestmaker.envelope.common.HelperKind;
import com.bestmaker.envelope.common.MutableClock;
import com.bestmaker.envelope.disclosure.Field;
import com.bestmaker.envelope.evidence.AlertLevel;
import com.bestmaker.envelope.evidence.OfficialAlert;
import com.bestmaker.envelope.matching.Helper;
import com.bestmaker.envelope.policy.BuildingProfile;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/** 가상 인물·가구로 구성한 테스트 환경. */
public final class Fixture {
    public static final GridCell CELL = new GridCell(10, 20);
    public static final GridCell NEXT = new GridCell(10, 21);
    public static final GridCell FAR = new GridCell(40, 40);

    public final MutableClock clock = new MutableClock(Instant.parse("2026-07-15T12:40:00Z"));
    public final EmergencyEnvelopeSystem sys = new EmergencyEnvelopeSystem(clock);
    public final String relational;
    public final String sealed;

    public Fixture() {
        sys.registerHelper(new Helper("P-1", HelperKind.PARTNER, CELL, Set.of(Capability.WHEELCHAIR)));
        sys.registerHelper(new Helper("P-2", HelperKind.PARTNER, NEXT, Set.of(Capability.WHEELCHAIR)));
        sys.registerHelper(new Helper("C-1", HelperKind.CITIZEN, CELL, Set.of()));
        sys.registerHelper(new Helper("C-2", HelperKind.CITIZEN, NEXT, Set.of()));
        sys.registerBuilding(new BuildingProfile("B-1", CELL.id(), true, true, true, 1200));
        sys.registerBuilding(new BuildingProfile("B-2", NEXT.id(), false, false, false, 200));
        relational = sys.register(new Registration(CELL, "B-1", Capability.WHEELCHAIR,
                Map.of(Field.UNIT, "B01호", Field.STATUS, "휠체어", Field.ESCAPE_ROUTE, "창문 쪽 방",
                        Field.EMERGENCY_CONTACT, "010-0000-0000"),
                EnumSet.allOf(Field.class), "P-1"));
        sealed = sys.register(new Registration(NEXT, "B-2", Capability.GENERAL,
                Map.of(Field.UNIT, "201호", Field.STATUS, "거동 불편", Field.ESCAPE_ROUTE, "현관",
                        Field.EMERGENCY_CONTACT, "010-1111-1111"),
                EnumSet.of(Field.UNIT, Field.STATUS, Field.ESCAPE_ROUTE, Field.EMERGENCY_CONTACT), null));
    }

    public OfficialAlert warning(GridCell... cells) {
        return alert(AlertLevel.WARNING, cells);
    }

    public OfficialAlert advisory(GridCell... cells) {
        return alert(AlertLevel.ADVISORY, cells);
    }

    private OfficialAlert alert(AlertLevel level, GridCell... cells) {
        Set<String> ids = new java.util.HashSet<>();
        for (GridCell c : cells) {
            ids.add(c.id());
        }
        return sys.alertIssuer().issue(level, ids, Duration.ofHours(2));
    }
}
