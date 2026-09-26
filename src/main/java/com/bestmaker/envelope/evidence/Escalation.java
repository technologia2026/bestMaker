package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.Codec;

import java.time.Instant;
import java.util.Locale;

/**
 * 정책 엔진이 서명한 "앞당기기" 선언. 단독으로는 아무것도 열 수 없고,
 * 같은 격자를 덮는 유효한 공식 예보(alertId)와 함께일 때만 공개 단계 근거가 된다.
 * 따라서 분석 엔진이 오염돼도 맑은 날에는 아무것도 열리지 않는다.
 */
public record Escalation(String alertId, String gridCell, EscalationReason reason, double riskScore,
                         Instant issuedAt, Instant expiresAt, String keyId, byte[] signature) implements Evidence {
    public Escalation {
        signature = signature == null ? null : signature.clone();
    }

    @Override
    public byte[] signature() {
        return signature == null ? null : signature.clone();
    }

    @Override
    public byte[] signedBytes() {
        return signedBytes(alertId, gridCell, reason, riskScore, issuedAt, expiresAt, keyId);
    }

    static byte[] signedBytes(String alertId, String cell, EscalationReason reason, double score, Instant issuedAt,
                              Instant expiresAt, String keyId) {
        return Codec.fields("escalation-v1", alertId, cell, reason.name(), String.format(Locale.ROOT, "%.4f", score),
                issuedAt.toString(), expiresAt.toString(), keyId);
    }

    @Override
    public String basis() {
        return reason.label();
    }
}
