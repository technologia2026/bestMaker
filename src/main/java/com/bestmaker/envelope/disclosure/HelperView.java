package com.bestmaker.envelope.disclosure;

import java.time.Instant;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * 조력자 화면에 보내는 응답. 웹 계층은 Cache-Control: no-store 로 내보내고
 * 브라우저 저장소에 남기지 않으며 워터마크를 화면에 겹쳐 그린다.
 */
public record HelperView(Map<Field, String> fields, boolean arrived, String watermark, Instant expiresAt) {
    public HelperView {
        fields = fields.isEmpty() ? Map.of() : Collections.unmodifiableMap(new EnumMap<>(fields));
    }
}
