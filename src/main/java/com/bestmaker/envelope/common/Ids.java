package com.bestmaker.envelope.common;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/** 예측 불가능한 ID·토큰·nonce 생성. */
public final class Ids {
    private static final SecureRandom RNG = new SecureRandom();

    private Ids() {
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static String randomHex(int bytes) {
        return HexFormat.of().formatHex(randomBytes(bytes));
    }

    public static String randomToken() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
    }

    public static SecureRandom rng() {
        return RNG;
    }
}
