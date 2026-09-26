package com.bestmaker.envelope.common;

/** 조력자 자격. 가구별 신뢰 등급(TrustTier)은 이 자격과 지정 관계로 정해진다. */
public enum HelperKind {
    /** 동행파트너·대피도우미 (기존 제도상 자격). */
    PARTNER,
    /** 본인인증·기본 교육·활동 서약을 마친 시민. */
    CITIZEN
}
