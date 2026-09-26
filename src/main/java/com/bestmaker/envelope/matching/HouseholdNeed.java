package com.bestmaker.envelope.matching;

import com.bestmaker.envelope.common.Capability;
import com.bestmaker.envelope.common.GridCell;

/**
 * 매칭 엔진 입력. 격자 위치와 필요 유형뿐이라 매칭 엔진은 개인정보를 보지 않는다.
 * designatedHelperId가 null이면 봉인형 가구다.
 */
public record HouseholdNeed(String householdId, GridCell cell, Capability need, String designatedHelperId,
                            double risk) {
}
