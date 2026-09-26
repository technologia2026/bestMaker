package com.bestmaker.envelope.matching;

import com.bestmaker.envelope.common.TrustTier;

import java.time.Instant;

public record Assignment(String householdId, String helperId, TrustTier tier, Instant at) {
}
