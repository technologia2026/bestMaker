package com.bestmaker.envelope.custodian;

import java.time.Instant;

/** 보관 기관이 검증 후 내준 열쇠 조각. */
public record ShareGrant(String custodian, int index, byte[] share, Instant validUntil, String basis) {
    public ShareGrant {
        share = share.clone();
    }

    @Override
    public byte[] share() {
        return share.clone();
    }
}
