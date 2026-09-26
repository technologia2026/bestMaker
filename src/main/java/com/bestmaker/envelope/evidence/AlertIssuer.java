package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.Ids;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/** 재난안전 부서 경보 수집기. MVP에서는 모의 발령기로 쓴다. */
public final class AlertIssuer {
    private final String keyId;
    private final KeyPair keys;
    private final Clock clock;

    public AlertIssuer(String keyId, Clock clock) {
        this.keyId = keyId;
        this.keys = Signatures.newKeyPair();
        this.clock = clock;
    }

    public String keyId() {
        return keyId;
    }

    public PublicKey publicKey() {
        return keys.getPublic();
    }

    public OfficialAlert issue(AlertLevel level, Set<String> cells, Duration validity) {
        Instant now = clock.instant();
        String alertId = "ALERT-" + Ids.randomHex(6);
        String nonce = Ids.randomHex(16);
        Instant expires = now.plus(validity);
        byte[] sig = Signatures.sign(keys.getPrivate(),
                OfficialAlert.signedBytes(alertId, level, cells, now, expires, nonce, keyId));
        return new OfficialAlert(alertId, level, cells, now, expires, nonce, keyId, sig);
    }
}
