package com.bestmaker.envelope.policy;

import java.util.Map;

/** 위험도 점수와 항목별 기여도. 기여도는 개봉 근거로 감사 로그에 남는다. */
public record RiskAssessment(String buildingId, double score, Map<String, Double> contributions, boolean high) {
    public RiskAssessment {
        contributions = Map.copyOf(contributions);
    }
}
