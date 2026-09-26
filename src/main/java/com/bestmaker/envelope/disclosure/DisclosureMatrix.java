package com.bestmaker.envelope.disclosure;

import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.common.TrustTier;

import java.util.EnumSet;
import java.util.Set;

/**
 * 공개 매트릭스 (신뢰 등급 × 위험 단계 × 도착 여부).
 * 결과는 항상 당사자가 동의한 항목과의 교집합이다.
 */
public final class DisclosureMatrix {
    private static final Set<Field> PRE_ARRIVAL = EnumSet.of(Field.DIRECTION, Field.NEED_TYPE);
    private static final Set<Field> EXTENDED_B_MINIMUM = EnumSet.of(Field.UNIT, Field.ESCAPE_ROUTE);

    private DisclosureMatrix() {
    }

    public static Set<Field> visible(TrustTier tier, Stage stage, boolean arrived, Set<Field> consented) {
        if (stage != Stage.OPEN) {
            return EnumSet.noneOf(Field.class);
        }
        EnumSet<Field> out = EnumSet.copyOf(PRE_ARRIVAL);
        boolean detailsAllowed = tier == TrustTier.DESIGNATED || arrived;
        if (detailsAllowed) {
            for (Field f : consented) {
                if (!f.consentable()) {
                    continue;
                }
                if (tier == TrustTier.EXTENDED_B && !EXTENDED_B_MINIMUM.contains(f)) {
                    continue;
                }
                out.add(f);
            }
        }
        return out;
    }
}
