package com.bestmaker.envelope.audit;

import com.bestmaker.envelope.common.Codec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;

/**
 * 모든 판정·개봉·열람을 해시 체인으로 묶는다. 체인 끝 해시를 열쇠 보관 기관들에
 * 주기적으로 기록해 두면 메인 DB 관리자가 과거 기록을 고치거나 지워도 드러난다.
 */
public final class HashChainLog {
    public static final String GENESIS = "0".repeat(64);

    private final Clock clock;
    private final List<AuditEntry> entries = new ArrayList<>();

    public HashChainLog(Clock clock) {
        this.clock = clock;
    }

    public synchronized AuditEntry append(AuditType type, String householdId, String actor, String detail) {
        String prev = entries.isEmpty() ? GENESIS : entries.get(entries.size() - 1).hash();
        long seq = entries.size();
        var at = clock.instant();
        String hash = hash(seq, at.toString(), type, householdId, actor, detail, prev);
        AuditEntry e = new AuditEntry(seq, at, type, householdId, actor, detail, prev, hash);
        entries.add(e);
        return e;
    }

    public synchronized List<AuditEntry> entries() {
        return List.copyOf(entries);
    }

    public synchronized AuditEntry head() {
        return entries.isEmpty() ? null : entries.get(entries.size() - 1);
    }

    /** 체인 끝 해시를 보관 기관들에 기록한다. */
    public void anchorTo(Collection<? extends AnchorSink> sinks) {
        AuditEntry h = head();
        if (h != null) {
            sinks.forEach(s -> s.recordAnchor(h.seq(), h.hash()));
        }
    }

    /** 내부 일관성: 각 칸의 해시와 연결이 맞는가. */
    public synchronized boolean verifyChain() {
        return verify(entries);
    }

    /** 외부 앵커와 대조: 보관 기관에 기록된 해시가 현재 체인과 일치하는가. */
    public synchronized boolean verifyAgainst(Collection<? extends AnchorSink> sinks) {
        if (!verify(entries)) {
            return false;
        }
        for (AnchorSink s : sinks) {
            if (s.latestAnchorSeq() >= entries.size()) {
                return false; // 앵커 이후 기록이 잘려 나감
            }
            for (int i = 0; i < entries.size(); i++) {
                String anchored = s.anchorAt(i);
                if (anchored != null && !anchored.equals(entries.get(i).hash())) {
                    return false;
                }
            }
        }
        return true;
    }

    /** 테스트용: DB 관리자가 기록을 조작하는 상황. */
    synchronized void tamper(int index, AuditEntry replacement) {
        entries.set(index, replacement);
    }

    /** 테스트용: 기록을 통째로 지우고 다시 쓰는 상황. */
    synchronized void truncate(int size) {
        entries.subList(size, entries.size()).clear();
    }

    private static boolean verify(List<AuditEntry> list) {
        String prev = GENESIS;
        for (int i = 0; i < list.size(); i++) {
            AuditEntry e = list.get(i);
            if (e.seq() != i || !e.prevHash().equals(prev)) {
                return false;
            }
            String expect = hash(e.seq(), e.at().toString(), e.type(), e.householdId(), e.actor(), e.detail(), prev);
            if (!expect.equals(e.hash())) {
                return false;
            }
            prev = e.hash();
        }
        return true;
    }

    private static String hash(long seq, String at, AuditType type, String hid, String actor, String detail,
                               String prev) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Codec.fields(prev, Long.toString(seq), at, type.name(), hid, actor, detail));
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
