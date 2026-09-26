package com.bestmaker.envelope.audit;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** 당사자 통지: "22:14, 확장 조력자 A 1명 열람 (호수·탈출 경로), 근거: 공식 침수경보". */
public final class Notifications {
    private static final DateTimeFormatter HM = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.of("Asia/Seoul"));

    private Notifications() {
    }

    public static List<String> forHousehold(HashChainLog log, String householdId) {
        return log.entries().stream()
                .filter(e -> householdId.equals(e.householdId()))
                .filter(e -> e.type() == AuditType.VIEWED || e.type() == AuditType.OPEN_DENIED
                        || e.type() == AuditType.RESEALED)
                .map(e -> HM.format(e.at()) + ", " + switch (e.type()) {
                    case VIEWED -> e.detail();
                    case OPEN_DENIED -> "열람 시도 거부됨";
                    default -> "재봉인 완료";
                })
                .toList();
    }
}
