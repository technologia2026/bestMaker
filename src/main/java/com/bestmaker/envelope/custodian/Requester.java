package com.bestmaker.envelope.custodian;

/** 개봉을 요청하는 주체. 조력자의 신뢰 등급은 요청자가 주장하지 않고 받는 쪽이 계산한다. */
public record Requester(String id, Role role) {
    public static Requester policyEngine() {
        return new Requester("policy-engine", Role.POLICY_ENGINE);
    }

    public static Requester official(String id) {
        return new Requester(id, Role.OFFICIAL);
    }

    public static Requester helper(String id) {
        return new Requester(id, Role.HELPER);
    }
}
