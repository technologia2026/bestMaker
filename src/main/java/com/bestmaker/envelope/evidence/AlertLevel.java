package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.Stage;

public enum AlertLevel {
    /** 사전예고·예보 → 준비 단계. */
    ADVISORY(Stage.PREPARE, "공식 침수예보"),
    /** 경보 → 공개 단계. */
    WARNING(Stage.OPEN, "공식 침수경보");

    private final Stage grants;
    private final String label;

    AlertLevel(Stage grants, String label) {
        this.grants = grants;
        this.label = label;
    }

    public Stage grants() {
        return grants;
    }

    public String label() {
        return label;
    }
}
