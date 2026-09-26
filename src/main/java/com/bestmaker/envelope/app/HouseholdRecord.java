package com.bestmaker.envelope.app;

import com.bestmaker.envelope.common.GridCell;

/** 평문 층: 가구 랜덤 ID, 500m 격자, 지정 조력자 ID. DB가 탈취돼도 드러나는 것은 이것뿐이다. */
public record HouseholdRecord(String householdId, GridCell cell, String designatedHelperId) {
}
