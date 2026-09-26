"""공공데이터 위험도 분석과 단계 판정."""
from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditType, HashChainLog
from .common import Denied, Stage
from .evidence import (DEVICE_SIGNAL_VALIDITY, AlertLevel, DeviceSignal, EscalationReason, EscalationSigner,
                       Evidence, EvidenceVerifier, OfficialAlert, ReplayGuard)

HIGH_THRESHOLD = 0.7


@dataclass(frozen=True)
class BuildingProfile:
    """평시 건물 취약도 입력. 모두 공공데이터이며 개인정보가 없다."""

    building_id: str
    grid_cell: str
    flood_trace: bool
    basement: bool
    lowland: bool
    pump_station_distance_m: float


@dataclass(frozen=True)
class RainObservation:
    """인근 강우량계·하수관로 수위 관측값."""

    grid_cell: str
    rain_10min_mm: float
    rain_60min_mm: float
    sewer_rise_cm_per_10min: float


@dataclass(frozen=True)
class RiskAssessment:
    building_id: str
    score: float
    contributions: dict[str, float]
    high: bool


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


class RiskAnalyzer:
    """규칙 기반 가중 점수. 서울시 침수 예보 기준(15분 20mm, 1시간 55mm)을 강우 항목의 포화점으로 쓴다.
    정적 항목 합계(최대 0.65)는 임계값(0.7)에 못 미치므로 실제 강우 없이 건물 조건만으로는 앞당기지 않는다."""

    def assess(self, b: BuildingProfile, rain: RainObservation | None) -> RiskAssessment:
        c = {
            "침수흔적": 0.30 if b.flood_trace else 0.0,
            "지하층": 0.20 if b.basement else 0.0,
            "저지대": 0.10 if b.lowland else 0.0,
            "빗물펌프장 1km 초과": 0.05 if b.pump_station_distance_m > 1000 else 0.0,
        }
        if rain is not None:
            c["10분 강우"] = 0.15 * _clamp(rain.rain_10min_mm / 13.3)  # 15분 20mm ≈ 10분 13.3mm
            c["1시간 강우"] = 0.15 * _clamp(rain.rain_60min_mm / 55.0)
            c["하수관로 수위 상승"] = 0.05 * _clamp(rain.sewer_rise_cm_per_10min / 30.0)
        score = sum(c.values())
        return RiskAssessment(b.building_id, score, c, score >= HIGH_THRESHOLD)


@dataclass(frozen=True)
class StageDecision:
    """단계 판정 결과와 보관 기관에 제출할 증거 묶음."""

    stage: Stage
    evidence: tuple[Evidence, ...]
    reason: str


class PolicyEngine:
    """증거를 받아(서명·재전송 검증) 가구별 단계를 정하고 보관 기관에 낼 증거 묶음을 만든다.
    판정을 잘못해도 보관 기관이 같은 증거를 다시 검증하므로 단독으로는 열 수 없다."""

    def __init__(self, verifier: EvidenceVerifier, replay: ReplayGuard, escalations: EscalationSigner,
                 log: HashChainLog, clock):
        self.verifier, self.replay, self.escalations, self.log, self.clock = verifier, replay, escalations, log, clock
        self.active_alerts: dict[str, OfficialAlert] = {}
        self._device_signals: dict[str, DeviceSignal] = {}
        self.feed_healthy = True

    def ingest(self, e: Evidence) -> None:
        hid = e.household_id if isinstance(e, DeviceSignal) else None
        try:
            self.verifier.verify(e)
            if isinstance(e, OfficialAlert):
                self.replay.check_alert(e)
                self.active_alerts[e.alert_id] = e
            elif isinstance(e, DeviceSignal):
                self.replay.check_device(e)
                self._device_signals[e.household_id] = e
            else:
                raise Denied("외부 증거만 수신")
            self.log.append(AuditType.EVIDENCE_ACCEPTED, hid, "policy-engine", e.basis)
        except Denied as ex:
            self.log.append(AuditType.EVIDENCE_REJECTED, hid, "policy-engine", str(ex))
            raise

    def clear(self, alert_id: str) -> None:
        """경보 해제. 해제된 경보는 더 이상 근거로 제출되지 않는다."""
        self.active_alerts.pop(alert_id, None)

    def _live_alerts(self, cell: str) -> list[OfficialAlert]:
        now = self.clock.now()
        return [a for a in self.active_alerts.values() if a.expires_at > now and cell in a.grid_cells]

    def decide(self, household_id: str, cell: str, risk: RiskAssessment | None) -> StageDecision:
        """가구 단위 판정. risk는 봉투 1에서 건물 ID를 얻은 뒤 계산한 위험도(없으면 None)."""
        d = self._device_signals.get(household_id)
        if d and d.issued_at + DEVICE_SIGNAL_VALIDITY > self.clock.now():
            return StageDecision(Stage.OPEN, (d,), f"{d.basis} (단계 무관 즉시)")
        alerts = self._live_alerts(cell)
        warning = next((a for a in alerts if a.level is AlertLevel.WARNING), None)
        if warning:
            return StageDecision(Stage.OPEN, (warning,), warning.basis)
        adv = next((a for a in alerts if a.level is AlertLevel.ADVISORY), None)
        if adv is None:
            return StageDecision(Stage.PEACETIME, (), "근거 없음")
        if risk is not None and risk.high:
            x = self.escalations.sign(adv, cell, EscalationReason.HIGH_RISK, risk.score)
            top = "·".join(k for k, v in sorted(risk.contributions.items(), key=lambda kv: -kv[1]) if v > 0)
            top = "·".join(top.split("·")[:3])
            return StageDecision(Stage.OPEN, (adv, x), f"{x.basis} (위험도 {risk.score:.2f}, {top})")
        if not self.feed_healthy:
            x = self.escalations.sign(adv, cell, EscalationReason.FEED_OUTAGE, risk.score if risk else 0.0)
            return StageDecision(Stage.OPEN, (adv, x), x.basis)
        return StageDecision(Stage.PREPARE, (adv,), adv.basis)
