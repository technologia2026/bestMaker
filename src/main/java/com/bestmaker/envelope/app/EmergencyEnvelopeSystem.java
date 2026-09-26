package com.bestmaker.envelope.app;

import com.bestmaker.envelope.anomaly.AnomalyDetector;
import com.bestmaker.envelope.anomaly.Finding;
import com.bestmaker.envelope.audit.AuditType;
import com.bestmaker.envelope.audit.HashChainLog;
import com.bestmaker.envelope.audit.Notifications;
import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.Codec;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.GridCell;
import com.bestmaker.envelope.common.Ids;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.custodian.KeyCombiner;
import com.bestmaker.envelope.custodian.KeyCustodian;
import com.bestmaker.envelope.custodian.OpenRequest;
import com.bestmaker.envelope.custodian.Requester;
import com.bestmaker.envelope.crypto.EnvelopeCipher;
import com.bestmaker.envelope.crypto.KeySplitter;
import com.bestmaker.envelope.crypto.Layer;
import com.bestmaker.envelope.crypto.SealedEnvelope;
import com.bestmaker.envelope.disclosure.DisclosureService;
import com.bestmaker.envelope.disclosure.Field;
import com.bestmaker.envelope.disclosure.HelperView;
import com.bestmaker.envelope.evidence.AlertIssuer;
import com.bestmaker.envelope.evidence.DeviceRegistry;
import com.bestmaker.envelope.evidence.EscalationSigner;
import com.bestmaker.envelope.evidence.Evidence;
import com.bestmaker.envelope.evidence.EvidenceVerifier;
import com.bestmaker.envelope.evidence.HomeDevice;
import com.bestmaker.envelope.evidence.ReplayGuard;
import com.bestmaker.envelope.evidence.TrustStore;
import com.bestmaker.envelope.matching.Assignment;
import com.bestmaker.envelope.matching.Helper;
import com.bestmaker.envelope.matching.HelperRegistry;
import com.bestmaker.envelope.matching.HouseholdNeed;
import com.bestmaker.envelope.matching.MatchingEngine;
import com.bestmaker.envelope.matching.Offer;
import com.bestmaker.envelope.policy.BuildingProfile;
import com.bestmaker.envelope.policy.PolicyEngine;
import com.bestmaker.envelope.policy.RainObservation;
import com.bestmaker.envelope.policy.RiskAnalyzer;
import com.bestmaker.envelope.policy.RiskAssessment;
import com.bestmaker.envelope.policy.StageDecision;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 등록 → 봉인 → 준비 → 공개 → 재봉인 → 통지 전체 흐름을 한 프로세스에 조립한 것.
 * 실제 배포에서는 보관 기관 3곳, 정책 엔진, 매칭, 키 조합기, 전달 서비스가 각각 별도 컨테이너다.
 */
public final class EmergencyEnvelopeSystem {
    public static final String[] CUSTODIAN_NAMES = {"재난안전부서", "자치구", "감사기관"};

    private final Clock clock;
    private final HashChainLog log;
    private final DeviceRegistry devices = new DeviceRegistry();
    private final HelperRegistry helpers = new HelperRegistry();
    private final AlertIssuer alertIssuer;
    private final List<KeyCustodian> custodians = new ArrayList<>();
    private final KeyCombiner combiner;
    private final PolicyEngine policy;
    private final MatchingEngine matching;
    private final DisclosureService disclosure;
    private final RiskAnalyzer analyzer = new RiskAnalyzer();
    private final AnomalyDetector anomalies = new AnomalyDetector();

    private final Map<String, HouseholdRecord> households = new ConcurrentHashMap<>();
    private final Map<String, SealedEnvelope> envelopes = new ConcurrentHashMap<>();
    private final Map<String, BuildingProfile> buildings = new ConcurrentHashMap<>();
    private final Map<String, RainObservation> rain = new ConcurrentHashMap<>();
    private final Map<String, StageDecision> decisions = new ConcurrentHashMap<>();
    private final Map<String, Capability> needs = new ConcurrentHashMap<>();
    private final Map<String, Double> risks = new ConcurrentHashMap<>();
    /** 준비 단계 이상인 동안만 유지하는 봉투 1 내용 (정책 엔진 메모리). */
    private final Map<String, Map<String, String>> env1Cache = new ConcurrentHashMap<>();

    public EmergencyEnvelopeSystem(Clock clock) {
        this.clock = clock;
        this.log = new HashChainLog(clock);
        this.alertIssuer = new AlertIssuer("collector-1", clock);
        EscalationSigner escalationSigner = new EscalationSigner("policy-1", clock);
        for (String name : CUSTODIAN_NAMES) {
            // 보관 기관마다 자기 신뢰 목록을 가진다
            TrustStore trust = new TrustStore()
                    .trustAlertKey(alertIssuer.keyId(), alertIssuer.publicKey())
                    .trustEscalationKey(escalationSigner.keyId(), escalationSigner.publicKey());
            custodians.add(new KeyCustodian(name, new EvidenceVerifier(trust, devices, clock), helpers, clock));
        }
        this.combiner = new KeyCombiner(custodians);
        TrustStore policyTrust = new TrustStore().trustAlertKey(alertIssuer.keyId(), alertIssuer.publicKey());
        this.policy = new PolicyEngine(new EvidenceVerifier(policyTrust, devices, clock), new ReplayGuard(),
                escalationSigner, log, clock);
        this.matching = new MatchingEngine(helpers, log, clock, Duration.ofMinutes(3), 2);
        this.disclosure = new DisclosureService(helpers, devices, log, clock, Duration.ofMinutes(30));
    }

    // ── 등록·봉인 ──────────────────────────────────────────────

    public String register(Registration r) {
        String hid = "HH-" + Ids.randomHex(8);
        households.put(hid, new HouseholdRecord(hid, r.cell(), r.designatedHelperId()));

        Map<String, String> env1 = Map.of("buildingId", r.buildingId(), "need", r.need().name());
        Map<String, String> env2 = new LinkedHashMap<>();
        r.details().forEach((f, v) -> env2.put(f.name(), v));
        env2.put("consented", r.consented().stream().map(Field::name).sorted().collect(Collectors.joining(",")));

        seal(hid, r.cell(), Layer.ENVELOPE_1, Codec.encodeMap(env1));
        seal(hid, r.cell(), Layer.ENVELOPE_2, Codec.encodeMap(env2));
        log.append(AuditType.REGISTERED, hid, "registrar",
                r.designatedHelperId() == null ? "봉인형" : "관계형");
        return hid;
    }

    private void seal(String hid, GridCell cell, Layer layer, byte[] plaintext) {
        byte[] key = EnvelopeCipher.newDataKey();
        try {
            envelopes.put(envKey(hid, layer), EnvelopeCipher.seal(hid, layer, 1, plaintext, key));
            Map<Integer, byte[]> shares = KeySplitter.split(key);
            for (int i = 0; i < custodians.size(); i++) {
                byte[] share = shares.get(i + 1);
                custodians.get(i).store(hid, layer, cell.id(), i + 1, share);
                Arrays.fill(share, (byte) 0);
            }
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private final Map<String, HomeDevice> homeDevices = new ConcurrentHashMap<>();

    /** 가정 기기 설치 (시연에서는 시뮬레이터 객체를 돌려준다). */
    public HomeDevice installDevice(String householdId) {
        HomeDevice d = new HomeDevice(householdId, clock);
        devices.register(d.registration());
        homeDevices.put(householdId, d);
        return d;
    }

    public HomeDevice devices(String householdId) {
        return homeDevices.get(householdId);
    }

    /** 조력자 위치 갱신 (웹앱의 위치 보고). */
    public void moveHelper(String helperId, GridCell cell) {
        helpers.find(helperId).ifPresent(h -> helpers.updateLocation(h.movedTo(cell)));
    }

    public void registerHelper(Helper h) {
        helpers.register(h);
    }

    public void registerBuilding(BuildingProfile b) {
        buildings.put(b.buildingId(), b);
    }

    public void observeRain(RainObservation r) {
        rain.put(r.gridCell(), r);
    }

    // ── 개봉 시도 ─────────────────────────────────────────────

    /** 담당 공무원·관리자의 명단 열람 시도. 증거와 관계없이 항상 거부되고 기록된다. */
    public void officialAttemptOpen(String officialId, String householdId, List<Evidence> evidence) {
        OpenRequest req = new OpenRequest(householdId, Layer.ENVELOPE_2, Requester.official(officialId), evidence);
        openAndLog(req);
    }

    private KeyCombiner.Opened openAndLog(OpenRequest req) {
        String detail = req.requester().role().name() + " " + req.layer();
        try {
            KeyCombiner.Opened o = combiner.open(req, envelopes.get(envKey(req.householdId(), req.layer())));
            log.append(AuditType.OPEN_GRANTED, req.householdId(), req.requester().id(),
                    detail + " 근거: " + o.basis() + " / 조각: " + String.join(",", o.custodians()));
            return o;
        } catch (DeniedException e) {
            log.append(AuditType.OPEN_DENIED, req.householdId(), req.requester().id(),
                    detail + " " + e.getMessage());
            throw e;
        }
    }

    // ── 증거 수신·단계 판정 ────────────────────────────────────

    public void ingest(Evidence e) {
        policy.ingest(e);
    }

    public PolicyEngine policy() {
        return policy;
    }

    public AlertIssuer alertIssuer() {
        return alertIssuer;
    }

    /** 모든 가구의 단계를 다시 판정하고, 공개 단계 가구에 출동 요청을 보낸다. */
    public Map<String, Stage> evaluate() {
        Map<String, Stage> out = new LinkedHashMap<>();
        List<HouseholdNeed> toDispatch = new ArrayList<>();
        for (HouseholdRecord h : households.values()) {
            StageDecision d = decide(h);
            StageDecision prev = decisions.put(h.householdId(), d);
            Stage before = prev == null ? Stage.PEACETIME : prev.stage();
            if (before != d.stage()) {
                log.append(AuditType.STAGE_CHANGED, h.householdId(), "policy-engine",
                        before.label() + " → " + d.stage().label() + " (" + d.reason() + ")");
            }
            if (before == Stage.OPEN && d.stage() != Stage.OPEN) {
                reseal(h.householdId());
            }
            if (d.stage() == Stage.OPEN) {
                toDispatch.add(new HouseholdNeed(h.householdId(), h.cell(), needs.get(h.householdId()),
                        h.designatedHelperId(), risks.getOrDefault(h.householdId(), 0.0)));
            }
            out.put(h.householdId(), d.stage());
        }
        matching.dispatch(toDispatch);
        return out;
    }

    private StageDecision decide(HouseholdRecord h) {
        StageDecision base = policy.decide(h.householdId(), h.cell().id(), null);
        if (base.stage() == Stage.PEACETIME) {
            env1Cache.remove(h.householdId());
            return base;
        }
        // 봉투 1은 정책 엔진만, 준비 단계 이상일 때만 연다 (건물 ID·필요 유형)
        Map<String, String> env1 = env1Cache.get(h.householdId());
        if (env1 == null) {
            try {
                env1 = Codec.decodeMap(openAndLog(new OpenRequest(h.householdId(), Layer.ENVELOPE_1,
                        Requester.policyEngine(), base.evidence())).plaintext());
                env1Cache.put(h.householdId(), env1);
            } catch (DeniedException e) {
                return new StageDecision(Stage.PEACETIME, List.of(), "봉투 1 개봉 거부: " + e.getMessage());
            }
        }
        needs.put(h.householdId(), Capability.valueOf(env1.get("need")));
        BuildingProfile b = buildings.get(env1.get("buildingId"));
        if (b == null) {
            return base;
        }
        RiskAssessment risk = analyzer.assess(b, rain.get(h.cell().id()));
        risks.put(h.householdId(), risk.score());
        return base.stage() == Stage.OPEN ? base : policy.decide(h.householdId(), h.cell().id(), risk);
    }

    /** 준비 단계 대기 호출. 주소 없이 격자 단위로만 알린다. */
    public Map<String, String> standbyNotices() {
        Map<String, String> out = new LinkedHashMap<>();
        for (Helper helper : helpers.active()) {
            long designated = 0;
            long nearby = 0;
            for (HouseholdRecord h : households.values()) {
                StageDecision d = decisions.get(h.householdId());
                if (d == null || d.stage() == Stage.PEACETIME) {
                    continue;
                }
                if (helper.id().equals(h.designatedHelperId())) {
                    designated++;
                } else if (helper.cell().distance(h.cell()) <= 2) {
                    nearby++;
                }
            }
            if (designated > 0) {
                out.put(helper.id(), "담당 가구 대기 요청");
            } else if (nearby > 0) {
                out.put(helper.id(), "격자 " + helper.cell().id() + " 일대 " + nearby + "곳 대기 요청 (주소 없음)");
            }
        }
        return out;
    }

    // ── 매칭·전달 ─────────────────────────────────────────────

    public List<Offer> offersFor(String helperId) {
        return matching.offersFor(helperId);
    }

    /** 수락 → 잠금 배정 → 봉투 2 개봉(보관 기관 검증) → 단기 토큰 발급. */
    public String accept(String helperId, String householdId, String helperDeviceId) {
        Assignment a = matching.accept(helperId, householdId);
        StageDecision d = decisions.get(householdId);
        HouseholdRecord h = households.get(householdId);
        KeyCombiner.Opened o;
        try {
            o = openAndLog(new OpenRequest(householdId, Layer.ENVELOPE_2, Requester.helper(helperId),
                    d == null ? List.of() : d.evidence()));
        } catch (DeniedException e) {
            matching.abandon(helperId, householdId);
            throw e;
        }
        Map<String, String> env2 = Codec.decodeMap(o.plaintext());
        Arrays.fill(o.plaintext(), (byte) 0);
        Map<Field, String> record = new EnumMap<>(Field.class);
        Set<Field> consented = EnumSet.noneOf(Field.class);
        env2.forEach((k, v) -> {
            if (k.equals("consented")) {
                if (!v.isEmpty()) {
                    Arrays.stream(v.split(",")).map(Field::valueOf).forEach(consented::add);
                }
            } else {
                record.put(Field.valueOf(k), v);
            }
        });
        return disclosure.issue(householdId, helperId, a.tier(), helperDeviceId, h.cell(),
                needs.getOrDefault(householdId, Capability.GENERAL), record, consented, o.validUntil(), o.basis());
    }

    public void decline(String helperId, String householdId) {
        matching.decline(helperId, householdId);
    }

    public void abandon(String helperId, String householdId) {
        matching.abandon(helperId, householdId);
        disclosure.reseal(householdId);
        custodians.forEach(c -> c.releaseHelper(helperId));
    }

    public void tick() {
        matching.tick();
    }

    public HelperView view(String token, String helperDeviceId) {
        return disclosure.view(token, helperDeviceId);
    }

    public void confirmArrival(String token, String helperDeviceId, GridCell helperCell, String code) {
        disclosure.confirmArrival(token, helperDeviceId, helperCell, code);
    }

    public MatchingEngine matching() {
        return matching;
    }

    // ── 재봉인·감사·통지 ──────────────────────────────────────

    private void reseal(String householdId) {
        matching.assignment(householdId).ifPresent(a -> custodians.forEach(c -> c.releaseHelper(a.helperId())));
        matching.release(householdId);
        disclosure.reseal(householdId);
        log.append(AuditType.RESEALED, householdId, "system", "자동 재봉인");
    }

    /** 경보 해제. 재판정 시 공개 단계였던 가구는 자동 재봉인된다. */
    public void clearAlert(String alertId) {
        policy.clear(alertId);
        evaluate();
    }

    public void anchorAuditLog() {
        log.anchorTo(custodians);
    }

    public boolean auditLogIntact() {
        return log.verifyAgainst(custodians);
    }

    public HashChainLog auditLog() {
        return log;
    }

    public List<String> notifications(String householdId) {
        return Notifications.forHousehold(log, householdId);
    }

    /** 이상 탐지 후 조력자 계정 정지. 공무원 계정은 추가 승인 대상으로 보고만 한다. */
    public List<Finding> detectAnomalies() {
        List<Finding> findings = anomalies.analyze(log.entries(), clock.instant());
        for (Finding f : findings) {
            if (helpers.find(f.actor()).isPresent() && !helpers.isSuspended(f.actor())) {
                helpers.suspend(f.actor());
                log.append(AuditType.ACCOUNT_SUSPENDED, null, f.actor(), f.rule());
            }
        }
        return findings;
    }

    public List<KeyCustodian> custodians() {
        return List.copyOf(custodians);
    }

    public HouseholdRecord household(String householdId) {
        return households.get(householdId);
    }

    public SealedEnvelope envelope(String householdId, Layer layer) {
        return envelopes.get(envKey(householdId, layer));
    }

    public int activeDisclosures() {
        return disclosure.activeSessions();
    }

    private static String envKey(String hid, Layer layer) {
        return hid + "/" + layer;
    }
}
