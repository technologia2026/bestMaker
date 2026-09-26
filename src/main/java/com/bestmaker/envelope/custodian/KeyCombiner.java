package com.bestmaker.envelope.custodian;

import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.crypto.EnvelopeCipher;
import com.bestmaker.envelope.crypto.KeySplitter;
import com.bestmaker.envelope.crypto.SealedEnvelope;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 내부망 키 조합기. 조각 2개 이상을 받아 메모리에서만 키를 복원하고 즉시 지운다. */
public final class KeyCombiner {
    public record Opened(byte[] plaintext, Instant validUntil, String basis, List<String> custodians) {
    }

    private final List<KeyCustodian> custodians;

    public KeyCombiner(List<KeyCustodian> custodians) {
        this.custodians = List.copyOf(custodians);
    }

    public Opened open(OpenRequest req, SealedEnvelope env) {
        if (!env.householdId().equals(req.householdId()) || env.layer() != req.layer()) {
            throw new DeniedException("요청과 봉투 불일치");
        }
        Map<Integer, byte[]> parts = new HashMap<>();
        List<String> granted = new ArrayList<>();
        List<String> denied = new ArrayList<>();
        Instant until = null;
        String basis = null;
        for (KeyCustodian c : custodians) {
            try {
                ShareGrant g = c.release(req);
                parts.put(g.index(), g.share());
                granted.add(c.name());
                until = until == null || g.validUntil().isBefore(until) ? g.validUntil() : until;
                basis = g.basis();
            } catch (DeniedException e) {
                denied.add(c.name() + ": " + e.getMessage());
            }
        }
        if (parts.size() < KeySplitter.THRESHOLD) {
            parts.values().forEach(p -> Arrays.fill(p, (byte) 0));
            throw new DeniedException("개봉 거부 (" + String.join(" / ", denied) + ")");
        }
        byte[] key = KeySplitter.join(parts);
        try {
            return new Opened(EnvelopeCipher.open(env, key), until, basis, List.copyOf(granted));
        } finally {
            Arrays.fill(key, (byte) 0);
            parts.values().forEach(p -> Arrays.fill(p, (byte) 0));
        }
    }
}
