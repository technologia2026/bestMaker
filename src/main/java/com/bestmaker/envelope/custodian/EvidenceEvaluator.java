package com.bestmaker.envelope.custodian;

import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.evidence.AlertLevel;
import com.bestmaker.envelope.evidence.DeviceSignal;
import com.bestmaker.envelope.evidence.Escalation;
import com.bestmaker.envelope.evidence.Evidence;
import com.bestmaker.envelope.evidence.EvidenceVerifier;
import com.bestmaker.envelope.evidence.OfficialAlert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 증거 묶음이 특정 가구(격자)에 허용하는 최고 단계를 계산한다.
 *
 * <ul>
 *   <li>그 가구의 유효한 기기 신호 → 공개</li>
 *   <li>격자를 덮는 경보 → 공개</li>
 *   <li>격자를 덮는 예보 + 같은 예보·격자에 대한 앞당기기 → 공개</li>
 *   <li>격자를 덮는 예보 → 준비</li>
 *   <li>앞당기기 단독 → 아무것도 아님</li>
 * </ul>
 */
public final class EvidenceEvaluator {
    public record Result(Stage stage, Instant validUntil, String basis, List<String> rejected) {
    }

    private final EvidenceVerifier verifier;

    public EvidenceEvaluator(EvidenceVerifier verifier) {
        this.verifier = verifier;
    }

    public Result evaluate(List<Evidence> evidence, String householdId, String gridCell) {
        List<String> rejected = new ArrayList<>();
        List<OfficialAlert> advisories = new ArrayList<>();
        List<Escalation> escalations = new ArrayList<>();
        Stage best = Stage.PEACETIME;
        Instant until = null;
        String basis = "증거 없음";

        for (Evidence e : evidence) {
            Instant validUntil;
            try {
                validUntil = verifier.verify(e);
            } catch (DeniedException ex) {
                rejected.add(ex.getMessage());
                continue;
            }
            switch (e) {
                case DeviceSignal d -> {
                    if (d.householdId().equals(householdId)) {
                        best = Stage.OPEN;
                        until = later(until, validUntil);
                        basis = d.basis();
                    } else {
                        rejected.add("다른 가구의 기기 신호");
                    }
                }
                case OfficialAlert a -> {
                    if (!a.gridCells().contains(gridCell)) {
                        rejected.add("경보 격자 불일치");
                    } else if (a.level() == AlertLevel.WARNING) {
                        best = Stage.OPEN;
                        until = later(until, validUntil);
                        basis = a.basis();
                    } else {
                        advisories.add(a);
                    }
                }
                case Escalation x -> escalations.add(x);
            }
        }
        if (best != Stage.OPEN) {
            for (OfficialAlert adv : advisories) {
                for (Escalation x : escalations) {
                    if (x.alertId().equals(adv.alertId()) && x.gridCell().equals(gridCell)) {
                        best = Stage.OPEN;
                        until = earlier(adv.expiresAt(), x.expiresAt());
                        basis = adv.basis() + " + " + x.basis();
                    }
                }
            }
        }
        if (best == Stage.PEACETIME && !advisories.isEmpty()) {
            best = Stage.PREPARE;
            until = advisories.get(0).expiresAt();
            basis = advisories.get(0).basis();
        }
        if (best == Stage.PEACETIME && !escalations.isEmpty()) {
            rejected.add("앞당기기는 공식 예보 없이 근거가 될 수 없음");
        }
        return new Result(best, until, basis, List.copyOf(rejected));
    }

    private static Instant later(Instant a, Instant b) {
        return a == null || b.isAfter(a) ? b : a;
    }

    private static Instant earlier(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }
}
