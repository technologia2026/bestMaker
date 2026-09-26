package com.bestmaker.envelope.crypto;

/** 봉투 층. 평문 층은 암호화하지 않으므로 여기 없다. */
public enum Layer {
    /** 건물 ID, 필요 유형. 준비 단계에서 정책 엔진만 연다. */
    ENVELOPE_1,
    /** 호수, 상태, 탈출 경로, 비상연락처. 공개 단계에서 배정된 조력자 1인에게만. */
    ENVELOPE_2
}
