package com.bestmaker.envelope.matching;

import com.bestmaker.envelope.audit.AuditType;
import com.bestmaker.envelope.audit.HashChainLog;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.HelperKind;
import com.bestmaker.envelope.common.TrustTier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 조력자 매칭. 순서는 항상 지정 조력자 → 확장 A → 확장 B.
 * 먼저 수락한 한 명에게 잠금 배정하고, 조력자는 동시에 1건만 맡을 수 있다.
 */
public final class MatchingEngine {
    public static final int CANDIDATES_PER_ROUND = 3;

    private final HelperRegistry helpers;
    private final HashChainLog log;
    private final Clock clock;
    private final Duration responseTimeout;
    private final int maxDistanceCells;

    private final Map<String, Dispatch> dispatches = new ConcurrentHashMap<>();
    private final Map<String, String> busyHelpers = new ConcurrentHashMap<>();

    private static final class Dispatch {
        final HouseholdNeed need;
        TrustTier tier;
        final Set<String> notified = new HashSet<>();
        final Set<String> declined = new HashSet<>();
        Instant offeredAt;
        Assignment assignment;

        Dispatch(HouseholdNeed need) {
            this.need = need;
        }
    }

    public MatchingEngine(HelperRegistry helpers, HashChainLog log, Clock clock, Duration responseTimeout,
                          int maxDistanceCells) {
        this.helpers = helpers;
        this.log = log;
        this.clock = clock;
        this.responseTimeout = responseTimeout;
        this.maxDistanceCells = maxDistanceCells;
    }

    /** 위험도가 높은 가구부터 출동 요청을 보낸다. */
    public void dispatch(List<HouseholdNeed> needs) {
        needs.stream()
                .sorted(Comparator.comparingDouble(HouseholdNeed::risk).reversed())
                .forEach(n -> {
                    Dispatch d = dispatches.computeIfAbsent(n.householdId(), k -> new Dispatch(n));
                    synchronized (d) {
                        if (d.assignment == null && d.tier == null) {
                            startRound(d, TrustTier.DESIGNATED);
                        }
                    }
                });
    }

    /** 조력자 화면에 보일 요청 목록. 이미 배정된 가구는 지워진다. */
    public List<Offer> offersFor(String helperId) {
        Optional<Helper> h = helpers.find(helperId);
        if (h.isEmpty() || busyHelpers.containsKey(helperId)) {
            return List.of();
        }
        return dispatches.values().stream()
                .filter(d -> {
                    synchronized (d) {
                        return d.assignment == null && d.notified.contains(helperId)
                                && !d.declined.contains(helperId);
                    }
                })
                .map(d -> new Offer(d.need.householdId(), h.get().tierFor(d.need.designatedHelperId()), d.need.cell().directionFrom(h.get().cell()),
                        d.need.need().label()))
                .toList();
    }

    public Assignment accept(String helperId, String householdId) {
        Dispatch d = dispatches.get(householdId);
        if (d == null) {
            throw new DeniedException("출동 요청 없음");
        }
        synchronized (d) {
            if (d.assignment != null) {
                throw new DeniedException("이미 다른 조력자가 수락함");
            }
            if (!d.notified.contains(helperId) || d.declined.contains(helperId)) {
                throw new DeniedException("이 조력자에게 온 요청이 아님");
            }
            Helper h = helpers.find(helperId).orElseThrow(() -> new DeniedException("조력자 없음"));
            if (helpers.isSuspended(helperId)) {
                throw new DeniedException("정지된 계정");
            }
            if (busyHelpers.putIfAbsent(helperId, householdId) != null) {
                throw new DeniedException("동시에 1건만 수락 가능");
            }
            TrustTier tier = h.tierFor(d.need.designatedHelperId());
            d.assignment = new Assignment(householdId, helperId, tier, clock.instant());
            log.append(AuditType.ACCEPTED, householdId, helperId, tier.label());
            return d.assignment;
        }
    }

    /** 수락 후 포기: 자동으로 다음 조력자에게 넘긴다. */
    public void abandon(String helperId, String householdId) {
        Dispatch d = dispatches.get(householdId);
        if (d == null) {
            return;
        }
        synchronized (d) {
            if (d.assignment == null || !d.assignment.helperId().equals(helperId)) {
                throw new DeniedException("배정되지 않은 조력자");
            }
            busyHelpers.remove(helperId, householdId);
            d.assignment = null;
            d.declined.add(helperId);
            log.append(AuditType.ABANDONED, householdId, helperId, "포기");
            continueRound(d);
        }
    }

    public void decline(String helperId, String householdId) {
        Dispatch d = dispatches.get(householdId);
        if (d == null) {
            return;
        }
        synchronized (d) {
            d.declined.add(helperId);
            if (d.assignment == null && d.declined.containsAll(d.notified)) {
                continueRound(d);
            }
        }
    }

    /** 응답 시간 초과 처리. 주기적으로 호출한다. */
    public void tick() {
        Instant now = clock.instant();
        for (Dispatch d : dispatches.values()) {
            synchronized (d) {
                if (d.assignment == null && d.offeredAt != null
                        && !now.isBefore(d.offeredAt.plus(responseTimeout))) {
                    continueRound(d);
                }
            }
        }
    }

    public Optional<Assignment> assignment(String householdId) {
        Dispatch d = dispatches.get(householdId);
        if (d == null) {
            return Optional.empty();
        }
        synchronized (d) {
            return Optional.ofNullable(d.assignment);
        }
    }

    public List<String> unassigned() {
        return dispatches.values().stream().filter(d -> {
            synchronized (d) {
                return d.assignment == null;
            }
        }).map(d -> d.need.householdId()).toList();
    }

    /** 가구 단위 재봉인: 요청과 배정을 지우고 조력자를 풀어 준다. */
    public void release(String householdId) {
        Dispatch d = dispatches.remove(householdId);
        if (d != null) {
            synchronized (d) {
                if (d.assignment != null) {
                    busyHelpers.remove(d.assignment.helperId(), householdId);
                }
            }
        }
    }

    /** 재봉인: 모든 배정과 요청을 지운다. */
    public void clearAll() {
        dispatches.clear();
        busyHelpers.clear();
    }

    private void continueRound(Dispatch d) {
        // 같은 등급에 아직 안 부른 후보가 있으면 추가로, 없으면 다음 등급으로
        if (d.tier == TrustTier.EXTENDED_B || !notifyCandidates(d, d.tier)) {
            TrustTier next = d.tier == null ? TrustTier.DESIGNATED
                    : d.tier == TrustTier.DESIGNATED ? TrustTier.EXTENDED_A : TrustTier.EXTENDED_B;
            startRound(d, next);
        }
    }

    private void startRound(Dispatch d, TrustTier tier) {
        TrustTier t = tier;
        while (true) {
            d.tier = t;
            if (notifyCandidates(d, t) || t == TrustTier.EXTENDED_B) {
                return;
            }
            t = t == TrustTier.DESIGNATED ? TrustTier.EXTENDED_A : TrustTier.EXTENDED_B;
        }
    }

    /** 등급 t의 후보에게 요청을 보낸다. 새로 부른 사람이 있으면 true. */
    private boolean notifyCandidates(Dispatch d, TrustTier t) {
        List<Helper> candidates;
        if (t == TrustTier.DESIGNATED) {
            String id = d.need.designatedHelperId();
            candidates = helpers.find(id)
                    .filter(h -> h.kind() == HelperKind.PARTNER)
                    .filter(this::available)
                    .filter(h -> !d.notified.contains(h.id()))
                    .map(List::of).orElse(List.of());
        } else {
            candidates = helpers.active().stream()
                    .filter(h -> h.tierFor(d.need.designatedHelperId()) == t)
                    .filter(this::available)
                    .filter(h -> !d.notified.contains(h.id()))
                    .filter(h -> h.canServe(d.need.need()))
                    .filter(h -> h.cell().distance(d.need.cell()) <= maxDistanceCells)
                    .sorted(Comparator.comparingInt(h -> h.cell().distance(d.need.cell())))
                    .limit(CANDIDATES_PER_ROUND)
                    .toList();
        }
        if (candidates.isEmpty()) {
            return false;
        }
        d.offeredAt = clock.instant();
        for (Helper h : candidates) {
            d.notified.add(h.id());
            log.append(AuditType.OFFERED, d.need.householdId(), h.id(), t.label());
        }
        return true;
    }

    private boolean available(Helper h) {
        return !helpers.isSuspended(h.id()) && !busyHelpers.containsKey(h.id());
    }
}
