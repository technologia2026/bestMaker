package com.bestmaker.envelope.crypto;

import com.bestmaker.envelope.common.Codec;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Ids;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM 봉인. AAD에 가구 ID·층·버전을 넣어 봉투를 다른 가구나 층으로
 * 바꿔 끼우면 복호화 단계에서 실패하게 한다.
 */
public final class EnvelopeCipher {
    public static final int KEY_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final String AAD_DOMAIN = "bestmaker-envelope-v1";

    private EnvelopeCipher() {
    }

    public static byte[] newDataKey() {
        return Ids.randomBytes(KEY_BYTES);
    }

    public static SealedEnvelope seal(String householdId, Layer layer, int version, byte[] plaintext, byte[] key) {
        requireKey(key);
        byte[] iv = Ids.randomBytes(IV_BYTES);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            c.updateAAD(aad(householdId, layer, version));
            return new SealedEnvelope(householdId, layer, version, iv, c.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("봉인 실패", e);
        }
    }

    public static byte[] open(SealedEnvelope env, byte[] key) {
        requireKey(key);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, env.iv()));
            c.updateAAD(aad(env.householdId(), env.layer(), env.version()));
            return c.doFinal(env.ciphertext());
        } catch (AEADBadTagException e) {
            throw new DeniedException("봉투 무결성 검증 실패");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("개봉 실패", e);
        }
    }

    static byte[] aad(String householdId, Layer layer, int version) {
        return Codec.fields(AAD_DOMAIN, householdId, layer.name(), Integer.toString(version));
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalArgumentException("AES-256 키가 아님");
        }
    }
}
