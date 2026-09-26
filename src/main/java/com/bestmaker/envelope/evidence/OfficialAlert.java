package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.Codec;

import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;

/**
 * 재난안전 부서 수집기가 공식 특보를 받아 서명한 경보.
 * 실제 특보는 서명돼 오지 않으므로 수집기 서명이 신뢰의 기준점이다.
 */
public record OfficialAlert(String alertId, AlertLevel level, Set<String> gridCells, Instant issuedAt,
                            Instant expiresAt, String nonce, String keyId, byte[] signature) implements Evidence {
    public OfficialAlert {
        gridCells = Set.copyOf(gridCells);
        signature = signature == null ? null : signature.clone();
    }

    @Override
    public byte[] signature() {
        return signature == null ? null : signature.clone();
    }

    @Override
    public byte[] signedBytes() {
        return signedBytes(alertId, level, gridCells, issuedAt, expiresAt, nonce, keyId);
    }

    static byte[] signedBytes(String alertId, AlertLevel level, Set<String> cells, Instant issuedAt,
                              Instant expiresAt, String nonce, String keyId) {
        return Codec.fields("alert-v1", alertId, level.name(), String.join(",", new TreeSet<>(cells)),
                issuedAt.toString(), expiresAt.toString(), nonce, keyId);
    }

    @Override
    public String basis() {
        return level.label();
    }

    /** 서명을 유지한 채 필드를 바꾼 사본 (위조 시뮬레이션용). */
    public OfficialAlert withCells(Set<String> cells) {
        return new OfficialAlert(alertId, level, cells, issuedAt, expiresAt, nonce, keyId, signature);
    }

    public OfficialAlert withLevel(AlertLevel l) {
        return new OfficialAlert(alertId, l, gridCells, issuedAt, expiresAt, nonce, keyId, signature);
    }
}
