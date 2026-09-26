package com.bestmaker.envelope.common;

/** 위험 단계. 종료 단계는 재봉인 후 평시로 돌아간다. */
public enum Stage {
    PEACETIME("평시"),
    PREPARE("준비"),
    OPEN("공개");

    private final String label;

    Stage(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    public boolean atLeast(Stage other) {
        return compareTo(other) >= 0;
    }
}
