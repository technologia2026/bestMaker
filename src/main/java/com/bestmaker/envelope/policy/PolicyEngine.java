package com.bestmaker.envelope.policy;

import com.bestmaker.envelope.audit.AuditType;
import com.bestmaker.envelope.audit.HashChainLog;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.evidence.AlertLevel;
import com.bestmaker.envelope.evidence.DeviceSignal;
import com.bestmaker.envelope.evidence.EscalationReason;
import com.bestmaker.envelope.evidence.EscalationSigner;
import com.bestmaker.envelope.evidence.Evidence;
import com.bestmaker.envelope.evidence.EvidenceVerifier;
import com.bestmaker.envelope.evidence.OfficialAlert;
import com.bestmaker.envelope.evidence.ReplayGuard;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 단계 판정. 증거를 받아(서명·재전송 검증) 가구별 단계를 정하고, 보관 기관에 낼 증거 묶음을 만든다.
 * 정책 엔진이 판정을 잘못해도 보관 기관이 같은 증거를 다시 검증하므로 단독으로는 열 수 없다.
 */
public final class PolicyEngine {
    private final EvidenceVerifier verifier;
    private final ReplayGuard replay;
    private final EscalationSigner escalations;
    private final HashChainLog log;
    private final Clock clock;
    private final Map<String, OfficialAlert> activeAlerts = new ConcurrentHashMap<>();
    private final Map<String, DeviceSignal> deviceSignals = new ConcurrentHashMap<>();
    private volatile boolean feedHealthy = true;

    public PolicyEngine(EvidenceVerifier verifier, ReplayGuard replay, EscalationSigner escalations,
                        HashChainLog log, Clock clock) {
        this.verifier = verifier;
        this.replay = replay;
        this.escalations = escalations;
        this.log = log;
        this.clock = clock;
    }

    public void ingest(Evidence e) {
        try {
            verifier.verify(e);
            switch (e) {
                case OfficialAlert a -> {
                    replay.checkAlert(a);
                    activeAlerts.put(a.alertId(), a);
                }
                case DeviceSignal d -> {
                    replay.checkDevice(d);
                    deviceSignals.put(d.householdId(), d);
                }
                default -> throw new DeniedException("외부 증거만 수신");
            }
            log.append(AuditType.EVIDENCE_ACCEPTED, householdOf(e), "policy-engine", e.basis());
        } catch (DeniedException ex) {
            log.append(AuditType.EVIDENCE_REJECTED, householdOf(e), "policy-engine", ex.getMessage());
            throw ex;
        }
    }

    /** 경보 해제. 해제된 경보는 더 이상 근거로 제출되지 않는다. */
    public void clear(String alertId) {
        activeAlerts.remove(alertId);
    }

    public void setFeedHealthy(boolean healthy) {
        this.feedHealthy = healthy;
    }

    public boolean isFeedHealthy() {
        return feedHealthy;
    }

    /** 격자 단위 판정 (봉투 1을 열기 전). */
    public Stage cellStage(String cell) {
        Instant now = clock.instant();
        Stage s = Stage.PEACETIME;
        for (OfficialAlert a : activeAlerts.values()) {
            if (a.expiresAt().isAfter(now) && a.gridCells().contains(cell)) {
                s = a.level().grants().atLeast(s) ? a.level().grants() : s;
            }
        }
        return s;
    }

    /** 격자 판정용 증거 (봉투 1 개봉 요청에 첨부). */
    public List<Evidence> cellEvidence(String cell) {
        return new ArrayList<>(liveAlertsFor(cell));
    }

    /**
     * 가구 단위 판정.
     *
     * @param risk 건물 위험도 (봉투 1에서 건물 ID를 얻은 뒤 계산). 없으면 null.
     */
    public StageDecision decide(String householdId, String cell, RiskAssessment risk) {
        Instant now = clock.instant();
        DeviceSignal d = deviceSignals.get(householdId);
        if (d != null && d.issuedAt().plus(EvidenceVerifier.DEVICE_SIGNAL_VALIDITY).isAfter(now)) {
            return new StageDecision(Stage.OPEN, List.of(d), d.basis() + " (단계 무관 즉시)");
        }
        List<OfficialAlert> alerts = liveAlertsFor(cell);
        Optional<OfficialAlert> warning = alerts.stream().filter(a -> a.level() == AlertLevel.WARNING).findFirst();
        if (warning.isPresent()) {
            return new StageDecision(Stage.OPEN, List.of(warning.get()), warning.get().basis());
        }
        Optional<OfficialAlert> advisory = alerts.stream().filter(a -> a.level() == AlertLevel.ADVISORY).findFirst();
        if (advisory.isEmpty()) {
            return new StageDecision(Stage.PEACETIME, List.of(), "근거 없음");
        }
        OfficialAlert adv = advisory.get();
        if (risk != null && risk.high()) {
            var x = escalations.sign(adv, cell, EscalationReason.HIGH_RISK, risk.score());
            return new StageDecision(Stage.OPEN, List.of(adv, x),
                    String.format(java.util.Locale.ROOT, "%s (위험도 %.2f, %s)", x.basis(), risk.score(),
                            topContributions(risk)));
        }
        if (!feedHealthy) {
            var x = escalations.sign(adv, cell, EscalationReason.FEED_OUTAGE, risk == null ? 0 : risk.score());
            return new StageDecision(Stage.OPEN, List.of(adv, x), x.basis());
        }
        return new StageDecision(Stage.PREPARE, List.of(adv), adv.basis());
    }

    private List<OfficialAlert> liveAlertsFor(String cell) {
        Instant now = clock.instant();
        return activeAlerts.values().stream()
                .filter(a -> a.expiresAt().isAfter(now) && a.gridCells().contains(cell))
                .toList();
    }

    private static String topContributions(RiskAssessment r) {
        return r.contributions().entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(3)
                .map(Map.Entry::getKey)
                .reduce((a, b) -> a + "·" + b)
                .orElse("-");
    }

    private static String householdOf(Evidence e) {
        return e instanceof DeviceSignal d ? d.householdId() : null;
    }
}
