package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.DeniedException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * 증거 한 건의 서명·유효 시간을 검증한다. 격자 일치나 증거 조합은
 * 호출자(보관 기관, 정책 엔진)가 판단한다.
 */
public final class EvidenceVerifier {
    public static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(2);
    public static final Duration MAX_ALERT_VALIDITY = Duration.ofHours(24);
    public static final Duration DEVICE_SIGNAL_VALIDITY = Duration.ofMinutes(60);
    public static final Duration MAX_ESCALATION_VALIDITY = Duration.ofHours(3);

    private final TrustStore trust;
    private final DeviceRegistry devices;
    private final Clock clock;

    public EvidenceVerifier(TrustStore trust, DeviceRegistry devices, Clock clock) {
        this.trust = trust;
        this.devices = devices;
        this.clock = clock;
    }

    /** 검증을 통과하면 증거가 유효한 마지막 시각을 돌려준다. */
    public Instant verify(Evidence e) {
        return switch (e) {
            case OfficialAlert a -> verifyAlert(a);
            case DeviceSignal d -> verifyDevice(d);
            case Escalation x -> verifyEscalation(x);
        };
    }

    private Instant verifyAlert(OfficialAlert a) {
        if (!Signatures.verify(trust.alertKey(a.keyId()), a.signedBytes(), a.signature())) {
            throw new DeniedException("경보 서명 검증 실패");
        }
        checkWindow(a.issuedAt(), a.expiresAt(), MAX_ALERT_VALIDITY, "경보");
        return a.expiresAt();
    }

    private Instant verifyDevice(DeviceSignal d) {
        DeviceRegistry.DeviceRecord rec = devices.find(d.deviceId())
                .orElseThrow(() -> new DeniedException("등록되지 않은 기기"));
        if (!rec.householdId().equals(d.householdId())) {
            throw new DeniedException("기기와 가구 불일치");
        }
        if (!Signatures.verify(rec.publicKey(), d.signedBytes(), d.signature())) {
            throw new DeniedException("기기 서명 검증 실패");
        }
        Instant expires = d.issuedAt().plus(DEVICE_SIGNAL_VALIDITY);
        checkWindow(d.issuedAt(), expires, DEVICE_SIGNAL_VALIDITY, "기기 신호");
        return expires;
    }

    private Instant verifyEscalation(Escalation x) {
        if (!Signatures.verify(trust.escalationKey(x.keyId()), x.signedBytes(), x.signature())) {
            throw new DeniedException("앞당기기 서명 검증 실패");
        }
        checkWindow(x.issuedAt(), x.expiresAt(), MAX_ESCALATION_VALIDITY, "앞당기기");
        return x.expiresAt();
    }

    private void checkWindow(Instant issuedAt, Instant expiresAt, Duration maxValidity, String what) {
        Instant now = clock.instant();
        if (issuedAt.isAfter(now.plus(MAX_CLOCK_SKEW))) {
            throw new DeniedException(what + " 발령 시각이 미래임");
        }
        if (!now.isBefore(expiresAt)) {
            throw new DeniedException(what + " 유효 시간 만료");
        }
        if (!expiresAt.isAfter(issuedAt) || Duration.between(issuedAt, expiresAt).compareTo(maxValidity) > 0) {
            throw new DeniedException(what + " 유효 기간 비정상");
        }
    }
}
