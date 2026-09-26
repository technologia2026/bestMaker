package com.bestmaker.envelope.crypto;

/** 암호화된 봉투. DB에 저장되는 형태. */
public record SealedEnvelope(String householdId, Layer layer, int version, byte[] iv, byte[] ciphertext) {
    public SealedEnvelope {
        iv = iv.clone();
        ciphertext = ciphertext.clone();
    }

    @Override
    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    /** 다른 가구·층·버전으로 라벨만 바꾼 봉투 (바꿔치기 공격 시뮬레이션용). */
    public SealedEnvelope relabel(String otherHouseholdId, Layer otherLayer, int otherVersion) {
        return new SealedEnvelope(otherHouseholdId, otherLayer, otherVersion, iv, ciphertext);
    }
}
