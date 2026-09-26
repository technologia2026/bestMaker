package com.bestmaker.envelope.disclosure;

import java.util.EnumSet;
import java.util.Set;

/** 봉투 2 항목과 도착 전 안내 항목. */
public enum Field {
    DIRECTION("방향", false),
    NEED_TYPE("필요 유형", false),
    UNIT("호수", true),
    STATUS("상태", true),
    ESCAPE_ROUTE("탈출 경로", true),
    EMERGENCY_CONTACT("비상연락처", true);

    private final String label;
    private final boolean consentable;

    Field(String label, boolean consentable) {
        this.label = label;
        this.consentable = consentable;
    }

    public String label() {
        return label;
    }

    /** 당사자가 공개 여부를 고르는 항목인가. */
    public boolean consentable() {
        return consentable;
    }

    public static Set<Field> consentableFields() {
        EnumSet<Field> s = EnumSet.noneOf(Field.class);
        for (Field f : values()) {
            if (f.consentable) {
                s.add(f);
            }
        }
        return s;
    }
}
