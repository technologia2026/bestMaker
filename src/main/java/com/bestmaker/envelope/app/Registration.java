package com.bestmaker.envelope.app;

import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.GridCell;
import com.bestmaker.envelope.disclosure.Field;

import java.util.Map;
import java.util.Set;

/**
 * 주민센터 대면 등록 입력. designatedHelperId가 null이면 봉인형(지정 조력자 없음).
 * 공개할 항목(consented)은 본인이 고른다.
 */
public record Registration(GridCell cell, String buildingId, Capability need, Map<Field, String> details,
                           Set<Field> consented, String designatedHelperId) {
    public Registration {
        details = Map.copyOf(details);
        consented = Set.copyOf(consented);
    }
}
