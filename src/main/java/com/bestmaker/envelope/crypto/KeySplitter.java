package com.bestmaker.envelope.crypto;

import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Ids;
import com.codahale.shamir.Scheme;

import java.util.Map;

/**
 * Shamir 2-of-3 비밀분산. GF(256) 위에서 바이트 단위로 분산하므로
 * 32바이트 키를 그대로 나눌 수 있다.
 */
public final class KeySplitter {
    public static final int SHARES = 3;
    public static final int THRESHOLD = 2;
    private static final Scheme SCHEME = new Scheme(Ids.rng(), SHARES, THRESHOLD);

    private KeySplitter() {
    }

    /** 조각 번호(1..3) → 조각. */
    public static Map<Integer, byte[]> split(byte[] key) {
        return SCHEME.split(key);
    }

    public static byte[] join(Map<Integer, byte[]> shares) {
        if (shares.size() < THRESHOLD) {
            throw new DeniedException("열쇠 조각 부족: " + shares.size() + "/" + THRESHOLD);
        }
        return SCHEME.join(shares);
    }
}
