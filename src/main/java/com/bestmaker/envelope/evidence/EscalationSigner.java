package com.bestmaker.envelope.evidence;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/** 정책 엔진의 앞당기기 서명 키. */
public final class EscalationSigner {
    private final String keyId;
    private final KeyPair keys;
    private final Clock clock;

    public EscalationSigner(String keyId, Clock clock) {
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

    public Escalation sign(OfficialAlert advisory, String cell, EscalationReason reason, double score) {
        Instant now = clock.instant();
        Instant cap = now.plus(Duration.ofHours(3));
        Instant expires = advisory.expiresAt().isBefore(cap) ? advisory.expiresAt() : cap;
        byte[] sig = Signatures.sign(keys.getPrivate(),
                Escalation.signedBytes(advisory.alertId(), cell, reason, score, now, expires, keyId));
        return new Escalation(advisory.alertId(), cell, reason, score, now, expires, keyId, sig);
    }
}
