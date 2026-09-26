package com.bestmaker.envelope.audit;

import java.time.Instant;

/** 해시 체인 한 칸. hash = SHA-256(prevHash ‖ 내용). */
public record AuditEntry(long seq, Instant at, AuditType type, String householdId, String actor, String detail,
                         String prevHash, String hash) {
}
