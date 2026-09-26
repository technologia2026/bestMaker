package com.bestmaker.envelope.policy;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 규칙 기반 가중 점수. 서울시 침수 예보 기준(15분 20mm, 1시간 55mm)을 강우 항목의 포화점으로 쓴다.
 * 분석은 명단을 보지 않는다: 입력은 건물 공공데이터와 격자 단위 관측값뿐이다.
 * 정적 항목 합계(최대 0.65)는 임계값에 못 미치므로 실제 강우 없이 건물 조건만으로는 앞당기지 않는다.
 */
public final class RiskAnalyzer {
    public static final double HIGH_THRESHOLD = 0.7;

    static final double W_FLOOD_TRACE = 0.30;
    static final double W_BASEMENT = 0.20;
    static final double W_LOWLAND = 0.10;
    static final double W_PUMP_FAR = 0.05;
    static final double W_RAIN_10 = 0.15;
    static final double W_RAIN_60 = 0.15;
    static final double W_SEWER = 0.05;

    public RiskAssessment assess(BuildingProfile b, RainObservation rain) {
        Map<String, Double> c = new LinkedHashMap<>();
        c.put("침수흔적", b.floodTrace() ? W_FLOOD_TRACE : 0);
        c.put("지하층", b.basement() ? W_BASEMENT : 0);
        c.put("저지대", b.lowland() ? W_LOWLAND : 0);
        c.put("빗물펌프장 1km 초과", b.pumpStationDistanceM() > 1000 ? W_PUMP_FAR : 0);
        if (rain != null) {
            // 15분 20mm ≈ 10분 13.3mm 를 포화점으로
            c.put("10분 강우", W_RAIN_10 * clamp(rain.rain10MinMm() / 13.3));
            c.put("1시간 강우", W_RAIN_60 * clamp(rain.rain60MinMm() / 55.0));
            c.put("하수관로 수위 상승", W_SEWER * clamp(rain.sewerRiseCmPer10Min() / 30.0));
        }
        double score = c.values().stream().mapToDouble(Double::doubleValue).sum();
        return new RiskAssessment(b.buildingId(), score, c, score >= HIGH_THRESHOLD);
    }

    private static double clamp(double v) {
        return Math.max(0, Math.min(1, v));
    }
}
