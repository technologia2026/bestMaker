package com.bestmaker.envelope.evidence;

public enum EscalationReason {
    HIGH_RISK("건물 고위험 판정"),
    FEED_OUTAGE("데이터 수신 두절(보수 모드)");

    private final String label;

    EscalationReason(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
