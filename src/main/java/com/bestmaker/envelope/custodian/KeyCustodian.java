package com.bestmaker.envelope.custodian;

import com.bestmaker.envelope.audit.AnchorSink;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.crypto.Layer;
import com.bestmaker.envelope.evidence.EvidenceVerifier;
import com.bestmaker.envelope.matching.HelperRegistry;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 열쇠 보관 기관 (재난안전 부서 / 자치구 / 감사 기관). 같은 코드를 설정만 바꿔 세 번 띄운다.
 * 정책 엔진을 믿지 않고 증거·유효 시간·격자·조력자 자격을 직접 확인한 뒤에만 조각을 내준다.
 */
public final class KeyCustodian implements AnchorSink {
    private record ShareKey(String householdId, Layer layer) {
    }

    private record StoredShare(int index, byte[] share, String gridCell) {
    }

    private record ActiveGrant(String householdId, Instant until) {
    }

    public record Decision(Instant at, String householdId, Layer layer, String requester, boolean granted,
                           String reason) {
    }

    private final String name;
    private final EvidenceEvaluator evaluator;
    private final HelperRegistry helpers;
    private final Clock clock;
    private final Map<ShareKey, StoredShare> shares = new ConcurrentHashMap<>();
    private final Map<String, ActiveGrant> helperGrants = new ConcurrentHashMap<>();
    private final Map<Long, String> anchors = new ConcurrentHashMap<>();
    private final List<Decision> decisions = new ArrayList<>();
    private volatile long latestAnchor = -1;

    public KeyCustodian(String name, EvidenceVerifier verifier, HelperRegistry helpers, Clock clock) {
        this.name = name;
        this.evaluator = new EvidenceEvaluator(verifier);
        this.helpers = helpers;
        this.clock = clock;
    }

    public String name() {
        return name;
    }

    /** 봉인 시 조각 보관. 가구의 격자는 평문 층 정보라 보관 기관도 안다. */
    public void store(String householdId, Layer layer, String gridCell, int index, byte[] share) {
        shares.put(new ShareKey(householdId, layer), new StoredShare(index, share.clone(), gridCell));
    }

    public ShareGrant release(OpenRequest req) {
        try {
            ShareGrant g = check(req);
            record(req, true, g.basis());
            return g;
        } catch (DeniedException e) {
            record(req, false, e.getMessage());
            throw e;
        }
    }

    private ShareGrant check(OpenRequest req) {
        StoredShare stored = shares.get(new ShareKey(req.householdId(), req.layer()));
        if (stored == null) {
            throw new DeniedException("보관 중인 조각 없음");
        }
        Requester who = req.requester();
        if (who == null || who.role() == Role.OFFICIAL) {
            throw new DeniedException("관리자·공무원은 봉투를 열 수 없음");
        }
        if (req.evidence().isEmpty()) {
            throw new DeniedException("증거 없음");
        }
        EvidenceEvaluator.Result r = evaluator.evaluate(req.evidence(), req.householdId(), stored.gridCell());
        switch (req.layer()) {
            case ENVELOPE_1 -> {
                if (who.role() != Role.POLICY_ENGINE) {
                    throw new DeniedException("봉투 1은 정책 엔진만 사용");
                }
                if (!r.stage().atLeast(Stage.PREPARE)) {
                    throw new DeniedException("준비 단계 근거 부족: " + reasons(r));
                }
            }
            case ENVELOPE_2 -> {
                if (who.role() != Role.HELPER) {
                    throw new DeniedException("봉투 2는 배정된 조력자에게만");
                }
                if (!helpers.isQualified(who.id())) {
                    throw new DeniedException("조력자 자격 없음 또는 정지");
                }
                if (r.stage() != Stage.OPEN) {
                    throw new DeniedException("공개 단계 근거 부족: " + reasons(r));
                }
                claimHelperSlot(who.id(), req.householdId(), r.validUntil());
            }
        }
        return new ShareGrant(name, stored.index(), stored.share(), r.validUntil(), r.basis());
    }

    /** 보관 기관 스스로도 "조력자 1인 = 가구 1곳"을 강제한다. */
    private void claimHelperSlot(String helperId, String householdId, Instant until) {
        Instant now = clock.instant();
        helperGrants.compute(helperId, (k, cur) -> {
            if (cur != null && cur.until().isAfter(now) && !cur.householdId().equals(householdId)) {
                throw new DeniedException("조력자가 이미 다른 가구를 맡고 있음");
            }
            return new ActiveGrant(householdId, until);
        });
    }

    /** 재봉인 시 조력자 슬롯 해제. */
    public void releaseHelper(String helperId) {
        helperGrants.remove(helperId);
    }

    private static String reasons(EvidenceEvaluator.Result r) {
        return r.rejected().isEmpty() ? r.basis() : String.join(", ", r.rejected());
    }

    private synchronized void record(OpenRequest req, boolean granted, String reason) {
        String who = req.requester() == null ? "?" : req.requester().id();
        decisions.add(new Decision(clock.instant(), req.householdId(), req.layer(), who, granted, reason));
    }

    public synchronized List<Decision> decisions() {
        return List.copyOf(decisions);
    }

    @Override
    public void recordAnchor(long seq, String hash) {
        anchors.putIfAbsent(seq, hash);
        latestAnchor = Math.max(latestAnchor, seq);
    }

    @Override
    public String anchorAt(long seq) {
        return anchors.get(seq);
    }

    @Override
    public long latestAnchorSeq() {
        return latestAnchor;
    }
}
