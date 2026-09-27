"""결선 시연 6장면을 콘솔로 재현한다. 모든 인물·주소·연락처는 가상이다.

실행: python -m emergency_envelope.demo
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from .common import KST, Capability, Denied, GridCell, HelperKind, MutableClock, Position
from .disclosure import Field
from .evidence import AlertIssuer, AlertLevel, SignalType
from .matching import Helper
from .policy import BuildingProfile, RainObservation
from .system import EmergencyEnvelopeSystem, Registration

CELL_A = GridCell(10, 20)
CELL_B = GridCell(10, 21)
BASE = Position(37.48760, 126.91330)  # 가상 기준점
POS_H1 = BASE.offset(0, -480)
POS_H2 = BASE.offset(180, 150)


def scene(title: str) -> None:
    print(f"\n━━ {title}")


def say(s: str) -> None:
    print(f"  {s}")


def fields_str(view) -> str:
    return ", ".join(f"{f.label}={v}" for f, v in view.fields.items())


def main() -> None:
    clock = MutableClock(datetime(2026, 7, 15, 21, 40, tzinfo=KST))
    sys = EmergencyEnvelopeSystem(clock)

    sys.register_helper(Helper("P-1", HelperKind.PARTNER, CELL_A))
    sys.register_helper(Helper("P-2", HelperKind.PARTNER, CELL_B, frozenset({Capability.WHEELCHAIR})))
    sys.register_helper(Helper("C-1", HelperKind.CITIZEN, CELL_A, frozenset({Capability.MOBILITY_AID})))
    sys.register_building(BuildingProfile("B-001", CELL_A.id, True, True, True, 1200))
    sys.register_building(BuildingProfile("B-002", CELL_B.id, False, False, False, 300))

    h1 = sys.register(Registration(
        CELL_A, POS_H1, "B-001", Capability.WHEELCHAIR,
        {Field.UNIT: "B01호", Field.STATUS: "휠체어 사용, 야간 단독 거주",
         Field.ESCAPE_ROUTE: "창문 쪽 방 (골목 방향)", Field.EMERGENCY_CONTACT: "010-0000-0000 (가상)"},
        frozenset({Field.UNIT, Field.STATUS, Field.ESCAPE_ROUTE, Field.EMERGENCY_CONTACT}), "P-1"))
    h2 = sys.register(Registration(
        CELL_B, POS_H2, "B-002", Capability.MOBILITY_AID,
        {Field.UNIT: "2층 201호", Field.ESCAPE_ROUTE: "현관 계단"},
        frozenset({Field.UNIT, Field.ESCAPE_ROUTE}), None))
    device2 = sys.install_device(h2)  # 수위 센서는 선택 설치
    names = {h1: "H1", h2: "H2"}

    def stages(result) -> str:
        return ", ".join(f"{names[k]}={v.label}" for k, v in result.items())

    scene("1. 평시 — 담당자가 명단 열람 시도")
    try:
        sys.official_attempt_open("official-kim", h1)
    except Denied as e:
        say(f"거부: {e}")
    say(f"DB에서 보이는 것: {sys.household(h1)}")

    scene("2. 비 예보 — 준비는 미리, 공개는 나중에")
    advisory = sys.alert_issuer.issue(AlertLevel.ADVISORY, {CELL_A.id, CELL_B.id}, timedelta(hours=3))
    sys.ingest(advisory)
    sys.observe_rain(RainObservation(CELL_A.id, 1, 5, 2))
    say(f"단계: {stages(sys.evaluate())} (H1 위험도 {sys.risk(h1):.2f} < 0.70)")
    for helper_id, msg in sys.standby_notices().items():
        say(f"  {helper_id} 화면: {msg}")

    scene("3. 폭우 — 가장 가까운 이웃 한 명이 연다")
    clock.advance(timedelta(minutes=20))
    sys.observe_rain(RainObservation(CELL_A.id, 15, 50, 25))
    say(f"단계: {stages(sys.evaluate())} — {sys.decision(h1).reason}")
    say(f"P-1 요청: {sys.offers_for('P-1')[0].tier.value}, {sys.offers_for('P-1')[0].direction}")
    clock.advance(timedelta(minutes=3))
    sys.tick()
    say("지정 조력자 3분 무응답 → 자동 확장")
    offer = sys.offers_for("P-2")[0]
    say(f"P-2 요청: {offer.tier.value}, {offer.direction}, {offer.need_label}")
    token = sys.accept("P-2", h1, "phone-P2")
    say(f"도착 전 화면: {fields_str(sys.view(token, 'phone-P2'))}")
    try:
        sys.confirm_arrival(token, "phone-P2", POS_H1.offset(0, 300))
    except Denied as e:
        say(f"300m 전에서 도착 확인: {e}")
    sys.move_helper("P-2", CELL_A)
    sys.confirm_arrival(token, "phone-P2", POS_H1.offset(12, 8))
    say("집 반경 50m 안에 들어와 도착 자동 인식")
    after = sys.view(token, "phone-P2")
    say(f"도착 확인 후: {fields_str(after)}  [워터마크 {after.watermark}]")

    scene("4. 가짜 경보 — 서명 검증에서 거부")
    for label, forged in (
        ("예보를 경보로 바꿔치기", replace(advisory, level=AlertLevel.WARNING)),
        ("공격자 키로 서명한 경보", AlertIssuer("collector-1", clock).issue(AlertLevel.WARNING, {CELL_A.id}, timedelta(hours=1))),
        ("같은 경보 재전송", advisory),
    ):
        try:
            sys.ingest(forged)
        except Denied as e:
            say(f"{label}: {e}")

    scene("5. 물컵 — 수위 센서가 예보 없이도 즉시 연다")
    sys.ingest(device2.signal(SignalType.WATER_LEVEL))
    say(f"단계: {stages(sys.evaluate())}")
    offer = sys.offers_for("C-1")[0]
    say(f"봉인형 가구 + 동행파트너는 부적합·출동 중 → 시민 조력자 C-1 요청: {offer.tier.value}, {offer.direction}, {offer.need_label}")

    scene("6. 종료 — 자동 재봉인과 열람 통지")
    clock.advance(timedelta(minutes=61))
    sys.clear_alert(advisory.alert_id)
    say(f"단계: {stages(sys.evaluate())}")
    try:
        sys.view(token, "phone-P2")
    except Denied as e:
        say(f"P-2 화면 새로고침: {e}")
    say("당사자 통지:")
    for n in sys.notifications(h1):
        say(f"  {n}")
    sys.anchor_audit_log()
    say(f"감사 로그 {len(sys.log.entries())}건, 보관 기관 앵커 대조: {'무결' if sys.audit_log_intact() else '조작 탐지'}")


if __name__ == "__main__":
    main()
