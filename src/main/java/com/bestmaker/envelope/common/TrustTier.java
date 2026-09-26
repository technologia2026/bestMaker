package com.bestmaker.envelope.common;

/** 가구에 대한 조력자의 신뢰 등급. 순서가 배정 우선순위다. */
public enum TrustTier {
    DESIGNATED("지정 조력자"),
    EXTENDED_A("확장 조력자 A"),
    EXTENDED_B("확장 조력자 B");

    private final String label;

    TrustTier(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** 요청자 주장이 아니라 자격과 지정 관계로 계산한다. */
    public static TrustTier of(HelperKind kind, String helperId, String designatedHelperId) {
        if (kind == HelperKind.PARTNER) {
            return helperId.equals(designatedHelperId) ? DESIGNATED : EXTENDED_A;
        }
        return EXTENDED_B;
    }
}
