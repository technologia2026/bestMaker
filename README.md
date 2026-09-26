# 비상봉투 (가칭)

평소엔 봉인, 재난 땐 가장 가까운 이웃이 여는 재난약자 구조 플랫폼 — **보안 코어 (Python)**

재난약자의 위치·상태 정보를 평시에는 관리자를 포함해 누구도 열 수 없게 봉인하고, 재난 위험이 확인되면
지정 조력자 → 확장 조력자 A → 확장 조력자 B 순으로 한 사람을 배정해 신뢰 등급이 허용하는 항목만 단계적으로 공개한다.
복호화 열쇠는 기관 3곳에 2-of-3으로 나눠 두고, 상황이 끝나면 자동으로 다시 잠그며, 모든 열람은 당사자에게 통지한다.

> 모든 시연·테스트 데이터는 가상 인물·가상 주소다. 실제 개인정보는 사용하지 않는다.

## 실행

```bash
pip install -e ".[dev]"
pytest                               # 보안 시나리오 포함 전체 테스트 (39개)
python -m emergency_envelope.demo    # 결선 시연 6장면 콘솔 재현
bandit -r emergency_envelope         # 보안 자가진단
```

요구 사항: Python 3.11+. 암호는 검증된 라이브러리만 쓴다.
- `pycryptodome`: AES-256-GCM, Shamir 비밀분산 (16바이트 제한 → 32바이트 키를 두 덩어리로 나눠 각각 2-of-3 분산)
- `cryptography`: Ed25519 서명
- 표준 라이브러리 `secrets`, `hmac`, `hashlib`: 토큰·nonce, 도착 코드(HMAC-SHA256), 해시 체인

## 웹 시연 (설치 없이 브라우저로)

`web/demo.html`은 코어의 판정·매칭·공개 규칙을 JavaScript로 옮긴 앱 형태 시연 페이지다.
암호 연산은 브라우저 WebCrypto로 실제로 수행한다.

- 상단 "다음 장면"으로 결선 시연 6장면(세부 10단계)을 차례로 진행
- 조력자 폰(P-1 지정 / P-2 파트너 / C-1 시민)과 당사자(H1) 화면을 탭으로 전환해 수락·거절·포기·도착 코드 입력을 직접 조작
- 가정 기기 패널에서 수위 센서·긴급버튼을 눌러 즉시 공개
- "직접 공격해 보기"로 관리자 열람, 경보 위조·재전송, 봉투 끼워 넣기, 로그 조작을 시도하고 거부·탐지 확인

## 구조 (기획서 ❷ 절과 대응)

| 모듈 | 기획서 | 내용 |
|---|---|---|
| `crypto` | ② 봉인 | AES-256-GCM, AAD = 가구 ID·층·버전 (바꿔치기 차단) / Shamir 2-of-3 |
| `evidence` | ③ 개봉 증거 검증 | 공식 경보·가정 기기 신호·앞당기기 선언의 Ed25519 서명, 유효 시간, nonce·단조 카운터 재전송 방지, 도착 코드 |
| `custodian` | ③, 5. 보장 범위 | 보관 기관: 정책 엔진을 믿지 않고 증거·격자·자격을 직접 검증 후 조각 제공. 키 조합기: 메모리 내 복원 후 즉시 덮어쓰기 |
| `policy` | ④ 위험도 분석, ⑤ 단계 판정 | 규칙 기반 가중 점수(항목별 기여도 기록), 평시/준비/공개 판정, 보수 모드 |
| `matching` | ⑥ 조력자 매칭 | 지정 → 확장 A → 확장 B, 응답 시간 초과·거절·포기 시 자동 재배정, 선착순 잠금 배정, 동시 1건 |
| `disclosure` | ⑦ 도착 확인과 최소 전달, 4. 공개 매트릭스 | 신뢰 등급 × 단계 × 도착 여부 매트릭스, 기기 바인딩 단기 토큰, 워터마크, 도착 시도 제한 |
| `audit` | ⑧ 재봉인·감사·통지 | 해시 체인 감사 로그 + 보관 기관 앵커, 당사자 통지 문구 |
| `anomaly` | ⑨ 열람 이상 탐지 | 수락·포기 반복, 거부된 개봉 반복, 심야 관리자 조회 → 조력자 계정 정지 |
| `system`, `demo` | 전체 흐름, 결선 시연 | 전체 조립, 6장면 콘솔 시연 |

### 구현하면서 설계를 보강한 점 (기획서 반영 권장)

1. **보관 기관이 신뢰 등급을 직접 계산한다.** 요청자는 등급을 주장하지 않는다. 확장 A는 "다른 가구의 동행파트너"이므로
   조력자 자격(`HelperKind`: 동행파트너/시민)과 가구별 지정 관계로 등급(`TrustTier`)이 정해진다.
2. **분석은 열 수만 있고, 단독으로는 못 연다.** "예보 + 건물 고위험"으로 앞당길 때 정책 엔진은 서명된 앞당기기 선언을 만든다.
   보관 기관은 같은 예보·같은 격자의 유효한 공식 예보가 함께 올 때만 이를 공개 근거로 인정한다.
   정책 엔진 서명 키가 탈취돼도 맑은 날에는 아무것도 열리지 않는다 (`test_compromised_analysis_cannot_open_on_a_clear_day`).
3. **건물 조건만으로는 앞당기지 않는다.** 정적 항목 합계 최대 0.65 < 임계값 0.7, 실제 강우가 있어야 넘는다.
4. **재전송 방지는 두 층이다.** 한 경보가 여러 가구 개봉의 근거가 되는 건 정상이므로, 수신 시점(정책 엔진)에 nonce 1회,
   보관 기관은 유효 시간·격자로 재사용을 제한한다.
5. **보관 기관도 "조력자 1인 = 가구 1곳"을 강제한다.** 매칭 엔진이 오염돼도 한 조력자가 여러 가구를 열 수 없다.
6. **가정 기기가 없는 가구:** 확장 A는 위치만으로 도착 인정, 확장 B는 도착 확인 불가(방향·필요 유형까지만).
7. **Shamir 조각 개수는 직접 강제한다.** pycryptodome `Shamir.combine`은 조각이 모자라도 오류 없이 엉뚱한 값을 낸다.

### 보안 자가진단 메모

- Bandit B413(pyCrypto 사용 경고)은 같은 `Crypto` 이름공간을 쓰는 pycryptodome까지 잡는 오탐이라 사유를 적고 `# nosec B413` 처리했다.
- 봉투 평문은 JSON으로만 직렬화한다 (pickle 미사용). 서명·AAD·해시 입력은 길이 접두 인코딩(`common.fields`).
- Python `bytes`는 불변이라 완전한 메모리 소거는 불가능하다. 복원 키는 `bytearray`로 받아 사용 직후 덮어쓴다.

## 보안 시나리오 테스트 (기획서 12. 검증 계획)

| 시나리오 | 테스트 |
|---|---|
| 단독 관리자 개봉 | `test_official_cannot_open_even_during_real_warning`, `test_peacetime_open_is_denied_by_every_custodian_and_recorded` |
| 한 기관 탈취로 복원 | `test_single_compromised_custodian_cannot_restore_key`, `test_any_two_shares_restore_key_but_one_does_not` |
| 위조·재전송 경보 | `test_forged_alerts_are_rejected`, `test_replayed_alert_is_rejected`, `test_expired_alert_cannot_open`, `test_alert_for_another_grid_cannot_open` |
| 분석 오염 | `test_compromised_analysis_cannot_open_on_a_clear_day`, `test_static_building_risk_alone_does_not_escalate` |
| 기기 신호 오용 | `test_device_signal_opens_only_its_own_household`, `test_replayed_device_signal_is_rejected` |
| 만료 토큰 재사용 | `test_token_is_bound_to_device_and_expires`, `test_end_of_alert_reseals_and_notifies` |
| 봉투 바꿔치기 | `test_swapping_envelope_to_another_household_fails` |
| 동시 수락 | `test_concurrent_accepts_yield_exactly_one_assignment`, `test_helper_can_hold_only_one_household_at_a_time` |
| 확장 B 도착 전 상세 요청 | `test_extended_b_sees_only_direction_before_arrival_and_minimum_after`, `test_extended_b_without_home_device_cannot_confirm_arrival`, `test_arrival_attempts_are_limited` |
| 로그 조작 | `tests/test_audit.py` (수정·전체 재작성·잘라내기) |
| 수락 반복 정보 수집 | `test_repeated_abandons_suspend_helper_and_custodians_stop_releasing` |

## 아직 없는 것 (다음 단계)

- 웹 계층: Django + Django REST framework (담당자 웹, 조력자 PWA, 당사자 알림), `Cache-Control: no-store`, CSP
- 저장소: PostgreSQL + PostGIS, 배정은 `SELECT … FOR UPDATE` 행 잠금으로 (현재는 메모리 내 잠금)
- 비동기: Celery(JSON 직렬화) + Redis로 경보 수집·분석 주기 작업
- 배포: Docker Compose로 보관 기관 3곳·정책 엔진·매칭·키 조합기 분리, 각 기관 별도 DB·서명 키
- 공공데이터 수집: 강우량·하천 수위·하수관로 수위 API, 침수흔적도·건축물대장, 2022년 8월 강우 재생기
- 매칭 확장: 확장 B의 2인 1조, 휠체어 가구처럼 2명 이상 필요한 가구, 위험도·거리 동시 최적화
