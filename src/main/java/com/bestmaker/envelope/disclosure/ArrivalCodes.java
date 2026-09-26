package com.bestmaker.envelope.disclosure;

import com.bestmaker.envelope.common.Codec;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 가정 기기가 재난 중에만 표시하는 일회용 도착 코드 (TOTP 방식, 60초 창).
 * 집 앞 QR처럼 "약자가 산다"는 흔적을 남기지 않는다.
 */
public final class ArrivalCodes {
    public static final long WINDOW_SECONDS = 60;

    private ArrivalCodes() {
    }

    public static String code(byte[] secret, String householdId, Instant at) {
        return codeForWindow(secret, householdId, at.getEpochSecond() / WINDOW_SECONDS);
    }

    /** 현재 창과 직전 창을 허용한다. 상수 시간 비교. */
    public static boolean verify(byte[] secret, String householdId, Instant now, String submitted) {
        if (submitted == null || submitted.length() != 6) {
            return false;
        }
        long w = now.getEpochSecond() / WINDOW_SECONDS;
        boolean ok = false;
        for (long i = w - 1; i <= w; i++) {
            ok |= MessageDigest.isEqual(codeForWindow(secret, householdId, i).getBytes(StandardCharsets.US_ASCII), submitted.getBytes(StandardCharsets.US_ASCII));
        }
        return ok;
    }

    private static String codeForWindow(byte[] secret, String householdId, long window) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] h = mac.doFinal(Codec.fields("arrival-v1", householdId, Long.toString(window)));
            int off = h[h.length - 1] & 0x0f;
            int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8)
                    | (h[off + 3] & 0xff);
            return String.format(Locale.ROOT, "%06d", bin % 1_000_000);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
