package com.bestmaker.envelope.policy;

import com.bestmaker.envelope.common.Stage;
import com.bestmaker.envelope.evidence.Evidence;

import java.util.List;

/** 단계 판정 결과와 보관 기관에 제출할 증거 묶음. */
public record StageDecision(Stage stage, List<Evidence> evidence, String reason) {
    public StageDecision {
        evidence = List.copyOf(evidence);
    }
}
