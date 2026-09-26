package com.bestmaker.envelope.evidence;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** 증거 서명 검증용 공개키 목록. 각 보관 기관이 자기 사본을 가진다. */
public final class TrustStore {
    private final Map<String, PublicKey> alertKeys = new ConcurrentHashMap<>();
    private final Map<String, PublicKey> escalationKeys = new ConcurrentHashMap<>();

    public TrustStore trustAlertKey(String keyId, PublicKey key) {
        alertKeys.put(keyId, key);
        return this;
    }

    public TrustStore trustEscalationKey(String keyId, PublicKey key) {
        escalationKeys.put(keyId, key);
        return this;
    }

    PublicKey alertKey(String keyId) {
        return keyId == null ? null : alertKeys.get(keyId);
    }

    PublicKey escalationKey(String keyId) {
        return keyId == null ? null : escalationKeys.get(keyId);
    }
}
