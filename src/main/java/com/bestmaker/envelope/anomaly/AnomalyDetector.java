package com.bestmaker.envelope.anomaly;

import com.bestmaker.envelope.audit.AuditEntry;
import com.bestmaker.envelope.audit.AuditType;
import com.bestmaker.envelope.custodian.Role;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * 규칙 기반 열람 이상 탐지. 공식 증거로 여는 개봉은 막지 않고,
 * 사람이 요청하는 경로와 계정 행위만 제한한다.
 */
public final class AnomalyDetector {
    public static final Duration WINDOW = Duration.ofHours(1);
    public static final int MAX_ABANDONS = 2;
    public static final int MAX_DENIED_OPENS = 3;
    public static final int MAX_NIGHT_OFFICIAL_ATTEMPTS = 2;
    private static final ZoneId KST = ZoneId.of("Asia/Seoul");

    public List<Finding> analyze(List<AuditEntry> entries, Instant now) {
        Instant since = now.minus(WINDOW);
        List<AuditEntry> recent = entries.stream().filter(e -> !e.at().isBefore(since)).toList();
        List<Finding> out = new ArrayList<>();
        countBy(recent, e -> e.type() == AuditType.ABANDONED).forEach((actor, n) -> {
            if (n >= MAX_ABANDONS) {
                out.add(new Finding(actor, "수락·포기 반복", n));
            }
        });
        countBy(recent, e -> e.type() == AuditType.OPEN_DENIED).forEach((actor, n) -> {
            if (n >= MAX_DENIED_OPENS) {
                out.add(new Finding(actor, "개봉 거부 반복 (격자 밖·근거 없는 시도)", n));
            }
        });
        countBy(recent, e -> e.detail() != null && e.detail().startsWith(Role.OFFICIAL.name())
                && e.at().atZone(KST).getHour() < 6).forEach((actor, n) -> {
                    if (n >= MAX_NIGHT_OFFICIAL_ATTEMPTS) {
                        out.add(new Finding(actor, "비정상 시간대 관리자 조회 집중", n));
                    }
                });
        return out;
    }

    private static Map<String, Integer> countBy(List<AuditEntry> entries, Predicate<AuditEntry> p) {
        Map<String, Integer> m = new HashMap<>();
        entries.stream().filter(p).forEach(e -> m.merge(e.actor(), 1, Integer::sum));
        return m;
    }
}
