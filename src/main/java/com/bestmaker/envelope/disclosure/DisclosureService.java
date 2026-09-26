package com.bestmaker.envelope.disclosure;

import com.bestmaker.envelope.audit.AuditType;
import com.bestmaker.envelope.audit.HashChainLog;
import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.DeniedException;
import com.bestmaker.envelope.common.GridCell;
import com.bestmaker.envelope.common.Ids;
import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.common.TrustTier;
import com.bestmaker.envelope.evidence.DeviceRegistry;
import com.bestmaker.envelope.matching.Helper;
import com.bestmaker.envelope.matching.HelperRegistry;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 전달 서비스. 복호화된 봉투 2는 이 서비스의 메모리에만 머물고, 단기 토큰(기기 바인딩)으로만
 * 조회된다. 도착 전에는 방향과 필요 유형만, 도착 확인 후 신뢰 등급이 허용하는 항목만 연다.
 */
public final class DisclosureService {
    public static final int MAX_ARRIVAL_ATTEMPTS = 5;
    private static final DateTimeFormatter HM = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.of("Asia/Seoul"));

    private static final class Session {
        final String householdId;
        final String helperId;
        final TrustTier tier;
        final String deviceId;
        final GridCell cell;
        final Capability need;
        final Map<Field, String> record;
        final Set<Field> consented;
        final Instant expiresAt;
        final String basis;
        boolean arrived;
        int failedArrivals;
        Set<Field> lastLogged = EnumSet.noneOf(Field.class);

        Session(String householdId, String helperId, TrustTier tier, String deviceId, GridCell cell, Capability need,
                Map<Field, String> record, Set<Field> consented, Instant expiresAt, String basis) {
            this.householdId = householdId;
            this.helperId = helperId;
            this.tier = tier;
            this.deviceId = deviceId;
            this.cell = cell;
            this.need = need;
            this.record = record;
            this.consented = consented;
            this.expiresAt = expiresAt;
            this.basis = basis;
        }
    }

    private final HelperRegistry helpers;
    private final DeviceRegistry devices;
    private final HashChainLog log;
    private final Clock clock;
    private final Duration tokenTtl;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public DisclosureService(HelperRegistry helpers, DeviceRegistry devices, HashChainLog log, Clock clock,
                             Duration tokenTtl) {
        this.helpers = helpers;
        this.devices = devices;
        this.log = log;
        this.clock = clock;
        this.tokenTtl = tokenTtl;
    }

    /** 배정 확정 + 봉투 2 개봉 후 조력자에게 단기 토큰 발급. 토큰 원문은 저장하지 않는다. */
    public String issue(String householdId, String helperId, TrustTier tier, String helperDeviceId, GridCell cell,
                        Capability need, Map<Field, String> record, Set<Field> consented, Instant evidenceValidUntil,
                        String basis) {
        Instant cap = clock.instant().plus(tokenTtl);
        Instant expires = evidenceValidUntil.isBefore(cap) ? evidenceValidUntil : cap;
        String token = Ids.randomToken();
        Set<Field> consentCopy = consented.isEmpty() ? EnumSet.noneOf(Field.class) : EnumSet.copyOf(consented);
        sessions.put(digest(token), new Session(householdId, helperId, tier, helperDeviceId, cell, need,
                new EnumMap<>(record), consentCopy, expires, basis));
        return token;
    }

    public HelperView view(String token, String helperDeviceId) {
        Session s = session(token, helperDeviceId);
        synchronized (s) {
            Set<Field> visible = DisclosureMatrix.visible(s.tier, Stage.OPEN, s.arrived, s.consented);
            Map<Field, String> out = new EnumMap<>(Field.class);
            Helper h = helpers.find(s.helperId).orElseThrow(() -> new DeniedException("조력자 없음"));
            for (Field f : visible) {
                switch (f) {
                    case DIRECTION -> out.put(f, s.cell.directionFrom(h.cell()));
                    case NEED_TYPE -> out.put(f, s.need.label());
                    default -> {
                        String v = s.record.get(f);
                        if (v != null) {
                            out.put(f, v);
                        }
                    }
                }
            }
            Set<Field> details = EnumSet.copyOf(visible);
            details.removeAll(EnumSet.of(Field.DIRECTION, Field.NEED_TYPE));
            if (!details.isEmpty() && !details.equals(s.lastLogged)) {
                s.lastLogged = details;
                String items = details.stream().map(Field::label).collect(Collectors.joining("·"));
                log.append(AuditType.VIEWED, s.householdId, s.helperId,
                        s.tier.label() + " 1명 열람 (" + items + "), 근거: " + s.basis);
            }
            String watermark = s.helperId + " · " + HM.format(clock.instant());
            return new HelperView(out, s.arrived, watermark, s.expiresAt);
        }
    }

    /** 도착 확인: 위치 격자 일치 + 가정 기기 일회용 코드. 반복 실패 시 세션 잠금. */
    public void confirmArrival(String token, String helperDeviceId, GridCell helperCell, String code) {
        Session s = session(token, helperDeviceId);
        synchronized (s) {
            if (s.failedArrivals >= MAX_ARRIVAL_ATTEMPTS) {
                throw new DeniedException("도착 확인 시도 초과로 잠김");
            }
            boolean locationOk = helperCell.equals(s.cell);
            var device = devices.forHousehold(s.householdId);
            boolean codeOk = device.isPresent()
                    && ArrivalCodes.verify(device.get().arrivalSecret(), s.householdId, clock.instant(), code);
            // 가정 기기가 없는 가구는 확장 A만 위치로 도착 인정, 확장 B는 불가
            boolean noDeviceFallback = device.isEmpty() && s.tier != TrustTier.EXTENDED_B;
            if (!locationOk || !(codeOk || noDeviceFallback)) {
                s.failedArrivals++;
                throw new DeniedException("도착 확인 실패");
            }
            s.arrived = true;
            log.append(AuditType.ARRIVED, s.householdId, s.helperId, s.tier.label() + " 도착 확인");
        }
    }

    /** 가구 단위 재봉인. */
    public void reseal(String householdId) {
        sessions.entrySet().removeIf(e -> e.getValue().householdId.equals(householdId));
    }

    /** 전체 재봉인: 토큰 폐기, 메모리의 봉투 2 내용 삭제. */
    public List<String> resealAll() {
        List<String> households = sessions.values().stream().map(s -> s.householdId).distinct().toList();
        sessions.clear();
        return households;
    }

    public int activeSessions() {
        return sessions.size();
    }

    private Session session(String token, String helperDeviceId) {
        if (token == null) {
            throw new DeniedException("토큰 없음");
        }
        Session s = sessions.get(digest(token));
        if (s == null) {
            throw new DeniedException("유효하지 않거나 폐기된 토큰");
        }
        if (!clock.instant().isBefore(s.expiresAt)) {
            sessions.remove(digest(token));
            throw new DeniedException("만료된 토큰");
        }
        if (!s.deviceId.equals(helperDeviceId)) {
            throw new DeniedException("다른 기기에서의 토큰 사용");
        }
        if (helpers.isSuspended(s.helperId)) {
            throw new DeniedException("정지된 계정");
        }
        return s;
    }

    private static String digest(String token) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
