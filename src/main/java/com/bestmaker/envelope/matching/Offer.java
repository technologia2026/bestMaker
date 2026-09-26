package com.bestmaker.envelope.matching;

import com.bestmaker.envelope.common.TrustTier;

/** 조력자 화면의 출동 요청. 주소 없이 방향과 필요 유형만. */
public record Offer(String householdId, TrustTier tier, String direction, String needLabel) {
}
