package com.bestmaker.envelope.policy;

/** 인근 강우량계·하수관로 수위 관측값. */
public record RainObservation(String gridCell, double rain10MinMm, double rain60MinMm, double sewerRiseCmPer10Min) {
}
