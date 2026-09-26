package com.bestmaker.envelope.custodian;

public enum Role {
    /** 정책 엔진: 준비 단계에서 봉투 1만 연다. */
    POLICY_ENGINE,
    /** 배정된 조력자: 공개 단계에서 봉투 2. */
    HELPER,
    /** 담당 공무원·관리자: 어떤 봉투도 열 수 없다. */
    OFFICIAL
}
