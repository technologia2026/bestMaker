package com.bestmaker.envelope.common;

/** 필요 유형 / 조력자 역량. */
public enum Capability {
    GENERAL("일반 동행"),
    MOBILITY_AID("이동 보조"),
    WHEELCHAIR("휠체어"),
    VISUAL("시각 보조"),
    HEARING("청각 보조");

    private final String label;

    Capability(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
