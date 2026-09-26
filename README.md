# 비상봉투 (가칭)

평소엔 봉인, 재난 땐 가장 가까운 이웃이 여는 재난약자 구조 플랫폼 — **보안 코어 (Java 21)**

재난약자의 위치·상태 정보를 평시에는 관리자를 포함해 누구도 열 수 없게 봉인하고, 재난 위험이 확인되면
지정 조력자 → 확장 조력자 A → 확장 조력자 B 순으로 한 사람을 배정해 신뢰 등급이 허용하는 항목만 단계적으로 공개한다.
복호화 열쇠는 기관 3곳에 2-of-3으로 나눠 두고, 상황이 끝나면 자동으로 다시 잠그며, 모든 열람은 당사자에게 통지한다.

> 모든 시연·테스트 데이터는 가상 인물·가상 주소다. 실제 개인정보는 사용하지 않는다.

## 실행

```bash
mvn test                                                  # 보안 시나리오 포함 전체 테스트 (39개)
MAVEN_OPTS="-Dstdout.encoding=UTF-8" mvn -q compile exec:java   # 결선 시연 6장면 콘솔 재현
```

요구 사항: JDK 21, Maven 3.9+. 외부 의존성은 Shamir 비밀분산(`com.codahale:shamir`)과 JUnit뿐이며,
AES-256-GCM·Ed25519·HMAC·SecureRandom은 JDK 표준 암호 API(JCA)를 쓴다.

## 웹 시연 (설치 없이 브라우저로)

`web/demo.html`은 Java 코어의 판정·매칭·공개 규칙을 JavaScript로 옮긴 앱 형태 시연 페이지다.
암호 연산은 브라우저 WebCrypto로 실제로 수행한다 (AES-256-GCM, Shamir 2-of-3, Ed25519, HMAC-SHA256, SHA-256 해시 체인).

- 상단 "다음 장면"으로 결선 시연 6장면(세부 10단계)을 차례로 진행
- 조력자 폰(P-1 지정 / P-2 파트너 / C-1 시민)과 당사자(H1) 화면을 탭으로 전환, 수락·거절·포기·도착 코드 입력을 직접 조작
- 가정 기기 패널에서 수위 센서·긴급버튼을 눌러 즉시 공개
- "직접 공격해 보기"로 관리자 열람, 경보 위조·재전송, 봉투 끼워 넣기, 로그 조작을 시도하고 거부·탐지 확인

파일은 Artifact 게시용 조각(fragment)이라 `<html>` 뼈대 없이 시작하지만, 브라우저로 바로 열어도 동작한다.

## 구조 (기획서 ❷ 절과 대응)

| 패키지 | 기획서 | 내용 |
|---|---|---|
| `crypto` | ② 봉인 | `EnvelopeCipher` AES-256-GCM, AAD = 가구 ID·층·버전 (바꿔치기 차단) / `KeySplitter` Shamir 2-of-3 |
| `evidence` | ③ 개봉 증거 검증 | 공식 경보·가정 기기 신호·앞당기기 선언의 Ed25519 서명, 유효 시간, nonce·단조 카운터 재전송 방지 |
| `custodian` | ③, 5. 보장 범위 | `KeyCustodian` 보관 기관: 정책 엔진을 믿지 않고 증거·격자·자격을 직접 검증 후 조각 제공. `KeyCombiner` 메모리 내 복원 후 즉시 삭제 |
| `policy` | ④ 위험도 분석, ⑤ 단계 판정 | 규칙 기반 가중 점수(항목별 기여도 기록), 평시/준비/공개 판정, 보수 모드 |
| `matching` | ⑥ 조력자 매칭 | 지정 → 확장 A → 확장 B, 응답 시간 초과·거절·포기 시 자동 재배정, 선착순 잠금 배정, 동시 1건 |
| `disclosure` | ⑦ 도착 확인과 최소 전달, 4. 공개 매트릭스 | 신뢰 등급 × 단계 × 도착 여부 매트릭스, 가정 기기 일회용 도착 코드, 기기 바인딩 단기 토큰, 워터마크 |
| `audit` | ⑧ 재봉인·감사·통지 | 해시 체인 감사 로그 + 보관 기관 앵커, 당사자 통지 문구 |
| `anomaly` | ⑨ 열람 이상 탐지 | 수락·포기 반복, 거부된 개봉 반복, 심야 관리자 조회 → 조력자 계정 정지 |
| `app` | 전체 흐름, 결선 시연 | `EmergencyEnvelopeSystem` 조립, `Demo` 6장면 |

### 핵심 설계 결정

- **보관 기관이 신뢰 등급을 직접 계산한다.** 요청자는 등급을 주장하지 않는다. 확장 A는 "다른 가구의 동행파트너"이므로
  조력자 자격(`HelperKind`: 동행파트너/시민)과 가구별 지정 관계로 등급(`TrustTier`)이 정해진다.
- **분석은 열 수만 있고, 단독으로는 못 연다.** "예보 + 건물 고위험"으로 앞당길 때 정책 엔진은 서명된 `Escalation`을 만든다.
  보관 기관은 같은 예보(alertId)·같은 격자의 유효한 공식 예보가 함께 올 때만 이를 공개 근거로 인정한다.
  정책 엔진 서명 키가 탈취돼도 맑은 날에는 아무것도 열리지 않는다 (`compromisedAnalysisCannotOpenOnAClearDay`).
- **건물 조건만으로는 앞당기지 않는다.** 정적 항목 합계 최대 0.65 < 임계값 0.7, 실제 강우가 있어야 넘는다.
- **재전송 방지는 두 층이다.** 한 경보가 여러 가구 개봉의 근거가 되는 건 정상이므로, 수신 시점(정책 엔진)에 nonce 1회,
  보관 기관은 유효 시간·격자로 재사용을 제한한다.
- **보관 기관도 "조력자 1인 = 가구 1곳"을 강제한다.** 매칭 엔진이 오염돼도 한 조력자가 여러 가구를 열 수 없다.
- Java 직렬화(`ObjectInputStream`)를 쓰지 않고 길이 접두 인코딩(`Codec`)으로 서명·AAD·해시 입력을 만든다.

## 보안 시나리오 테스트 (기획서 12. 검증 계획)

| 시나리오 | 테스트 |
|---|---|
| 단독 관리자 개봉 | `officialCannotOpenEvenDuringRealWarning`, `peacetimeOpenIsDeniedByEveryCustodianAndRecorded` |
| 한 기관 탈취로 복원 | `singleCompromisedCustodianCannotRestoreKey`, `anyTwoSharesRestoreKeyButOneDoesNot` |
| 위조·재전송 경보 | `forgedAlertsAreRejected`, `replayedAlertIsRejected`, `expiredAlertCannotOpen`, `alertForAnotherGridCannotOpenThisHousehold` |
| 분석 오염 | `compromisedAnalysisCannotOpenOnAClearDay`, `staticBuildingRiskAloneDoesNotEscalate` |
| 기기 신호 오용 | `deviceSignalOpensOnlyItsOwnHousehold`, `replayedDeviceSignalIsRejected` |
| 만료 토큰 재사용 | `tokenIsBoundToDeviceAndExpires`, `endOfAlertResealsAndNotifies` |
| 봉투 바꿔치기 | `swappingEnvelopeToAnotherHouseholdFails` |
| 동시 수락 | `concurrentAcceptsYieldExactlyOneAssignment`, `helperCanHoldOnlyOneHouseholdAtATime` |
| 확장 B 도착 전 상세 요청 | `extendedBSeesOnlyDirectionBeforeArrivalAndMinimumAfter`, `extendedBWithoutHomeDeviceCannotConfirmArrival`, `arrivalAttemptsAreLimited` |
| 로그 조작 | `HashChainLogTest` (수정·전체 재작성·잘라내기) |
| 수락 반복 정보 수집 | `repeatedAbandonsSuspendHelperAndCustodiansStopReleasing` |

## 아직 없는 것 (다음 단계)

- 웹 계층: Spring Boot + Spring Security (담당자 웹, 조력자 PWA, 당사자 알림), `Cache-Control: no-store`, CSP
- 저장소: PostgreSQL + PostGIS, 배정은 `SELECT … FOR UPDATE` 행 잠금으로 (현재는 메모리 내 잠금)
- 배포: Docker Compose로 보관 기관 3곳·정책 엔진·매칭·키 조합기 분리, 각 기관 별도 DB·서명 키
- 공공데이터 수집: 강우량·하천 수위·하수관로 수위 API, 침수흔적도·건축물대장, 2022년 8월 강우 재생기
- 매칭 확장: 확장 B의 2인 1조, 휠체어 가구처럼 2명 이상 필요한 가구, 위험도·거리 동시 최적화
- 경보 해제 신호를 보관 기관에도 직접 전달 (현재는 유효 시간 만료로 제한)

Java 전환에 따라 기획서에서 고칠 부분은 [`docs/java-stack.md`](docs/java-stack.md)에 정리했다.
