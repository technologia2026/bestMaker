package com.bestmaker.envelope.evidence;

public enum SignalType {
    WATER_LEVEL("가정 수위 센서"),
    EMERGENCY_BUTTON("긴급버튼");

    private final String label;

    SignalType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
