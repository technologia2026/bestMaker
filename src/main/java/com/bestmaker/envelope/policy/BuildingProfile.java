package com.bestmaker.envelope.policy;

/** 평시 건물 취약도 입력. 모두 공공데이터이며 개인정보가 없다. */
public record BuildingProfile(String buildingId, String gridCell, boolean floodTrace, boolean basement,
                              boolean lowland, double pumpStationDistanceM) {
}
