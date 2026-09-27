"""등록 → 봉인 → 준비 → 공개 → 재봉인 → 통지 전체 흐름을 한 프로세스에 조립한 것.
실제 배포에서는 보관 기관 3곳, 정책 엔진, 매칭, 키 조합기, 전달 서비스가 각각 별도 컨테이너다."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from . import anomaly
from .audit import AuditType, HashChainLog, notifications_for
from .common import Capability, Denied, GridCell, Position, Stage, decode_json, encode_json, random_hex
from .crypto import Layer, SealedEnvelope, new_data_key, seal, split_key, wipe
from .custodian import KeyCombiner, KeyCustodian, OpenRequest, Opened, Requester
from .disclosure import DisclosureService, Field, HelperView
from .evidence import (AlertIssuer, DeviceRegistry, EscalationSigner, Evidence, EvidenceVerifier, HomeDevice,
                       ReplayGuard, TrustStore)
from .matching import Helper, HelperRegistry, HouseholdNeed, MatchingEngine, Offer
from .policy import BuildingProfile, PolicyEngine, RainObservation, RiskAnalyzer, StageDecision

CUSTODIAN_NAMES = ("재난안전부서", "자치구", "감사기관")


@dataclass(frozen=True)
class Registration:
    """등록 입력. designated_helper_id가 None이면 봉인형. 공개 항목은 본인이 고른다."""

    cell: GridCell
    position: Position
    building_id: str
    need: Capability
    details: dict[Field, str]
    consented: frozenset[Field]
    designated_helper_id: str | None


@dataclass(frozen=True)
class HouseholdRecord:
    """평문 층: 가구 랜덤 ID, 500m 격자, 지정 조력자 ID. DB가 탈취돼도 드러나는 것은 이것뿐이다."""

    household_id: str
    cell: GridCell
    designated_helper_id: str | None


class EmergencyEnvelopeSystem:
    def __init__(self, clock):
        self.clock = clock
        self.log = HashChainLog(clock)
        self.devices = DeviceRegistry()
        self.helpers = HelperRegistry()
        self.alert_issuer = AlertIssuer("collector-1", clock)
        esc = EscalationSigner("policy-1", clock)
        self.custodians: list[KeyCustodian] = []
        for name in CUSTODIAN_NAMES:
            # 보관 기관마다 자기 신뢰 목록을 가진다
            trust = (TrustStore().trust_alert_key(self.alert_issuer.key_id, self.alert_issuer.public_key)
                     .trust_escalation_key(esc.key_id, esc.public_key))
            self.custodians.append(KeyCustodian(name, EvidenceVerifier(trust, self.devices, clock), self.helpers, clock))
        self.combiner = KeyCombiner(self.custodians)
        policy_trust = TrustStore().trust_alert_key(self.alert_issuer.key_id, self.alert_issuer.public_key)
        self.policy = PolicyEngine(EvidenceVerifier(policy_trust, self.devices, clock), ReplayGuard(), esc, self.log, clock)
        self.matching = MatchingEngine(self.helpers, self.log, clock, timedelta(minutes=3), 2)
        self.disclosure = DisclosureService(self.helpers, self.log, clock, timedelta(minutes=30))
        self.analyzer = RiskAnalyzer()

        self._households: dict[str, HouseholdRecord] = {}
        self._envelopes: dict[tuple[str, Layer], SealedEnvelope] = {}
        self._buildings: dict[str, BuildingProfile] = {}
        self._rain: dict[str, RainObservation] = {}
        self._decisions: dict[str, StageDecision] = {}
        self._env1_cache: dict[str, dict] = {}  # 준비 단계 이상인 동안만 유지 (정책 엔진 메모리)
        self._risks: dict[str, float] = {}
        self._home_devices: dict[str, HomeDevice] = {}

    # ── 등록·봉인 ──────────────────────────────────────────
    def register(self, r: Registration) -> str:
        hid = f"HH-{random_hex(8)}"
        self._households[hid] = HouseholdRecord(hid, r.cell, r.designated_helper_id)
        env1 = {"building_id": r.building_id, "need": r.need.name}
        env2 = {f.name: v for f, v in r.details.items()}
        env2["consented"] = sorted(f.name for f in r.consented)
        env2["position"] = [r.position.lat, r.position.lon]
        self._seal(hid, r.cell, Layer.ENVELOPE_1, encode_json(env1))
        self._seal(hid, r.cell, Layer.ENVELOPE_2, encode_json(env2))
        self.log.append(AuditType.REGISTERED, hid, "registrar", "봉인형" if r.designated_helper_id is None else "관계형")
        return hid

    def _seal(self, hid: str, cell: GridCell, layer: Layer, plaintext: bytes) -> None:
        key = new_data_key()
        try:
            self._envelopes[(hid, layer)] = seal(hid, layer, 1, plaintext, key)
            shares = split_key(key)
            for i, c in enumerate(self.custodians, start=1):
                c.store(hid, layer, cell.id, i, shares[i])
        finally:
            wipe(key)

    def install_device(self, household_id: str) -> HomeDevice:
        d = HomeDevice(household_id, self.clock)
        self.devices.register(d.registration())
        self._home_devices[household_id] = d
        return d

    def home_device(self, household_id: str) -> HomeDevice | None:
        return self._home_devices.get(household_id)

    def register_helper(self, h: Helper) -> None:
        self.helpers.register(h)

    def move_helper(self, helper_id: str, cell: GridCell) -> None:
        h = self.helpers.find(helper_id)
        if h:
            self.helpers.update(h.moved_to(cell))

    def register_building(self, b: BuildingProfile) -> None:
        self._buildings[b.building_id] = b

    def observe_rain(self, r: RainObservation) -> None:
        self._rain[r.grid_cell] = r

    # ── 개봉 ──────────────────────────────────────────────
    def official_attempt_open(self, official_id: str, household_id: str, evidence: tuple[Evidence, ...] = ()) -> None:
        """담당 공무원·관리자의 명단 열람 시도. 증거와 관계없이 항상 거부되고 기록된다."""
        self._open_and_log(OpenRequest(household_id, Layer.ENVELOPE_2, Requester.official(official_id), tuple(evidence)))

    def _open_and_log(self, req: OpenRequest) -> Opened:
        detail = f"{req.requester.role.name} {req.layer.value}"
        try:
            o = self.combiner.open(req, self._envelopes.get((req.household_id, req.layer)))
        except Denied as e:
            self.log.append(AuditType.OPEN_DENIED, req.household_id, req.requester.id, f"{detail} {e}")
            raise
        self.log.append(AuditType.OPEN_GRANTED, req.household_id, req.requester.id,
                        f"{detail} 근거: {o.basis} / 조각: {','.join(o.custodians)}")
        return o

    # ── 증거 수신·단계 판정 ────────────────────────────────
    def ingest(self, e: Evidence) -> None:
        self.policy.ingest(e)

    def evaluate(self) -> dict[str, Stage]:
        """모든 가구의 단계를 다시 판정하고, 공개 단계 가구에 출동 요청을 보낸다."""
        out: dict[str, Stage] = {}
        to_dispatch: list[HouseholdNeed] = []
        for h in list(self._households.values()):
            d = self._decide(h)
            prev = self._decisions.get(h.household_id)
            before = prev.stage if prev else Stage.PEACETIME
            self._decisions[h.household_id] = d
            if before is not d.stage:
                self.log.append(AuditType.STAGE_CHANGED, h.household_id, "policy-engine",
                                f"{before.label} → {d.stage.label} ({d.reason})")
            if before is Stage.OPEN and d.stage is not Stage.OPEN:
                self._reseal(h.household_id)
            if d.stage is Stage.OPEN:
                need = Capability[self._env1_cache.get(h.household_id, {}).get("need", "GENERAL")]
                to_dispatch.append(HouseholdNeed(h.household_id, h.cell, need, h.designated_helper_id,
                                                 self._risks.get(h.household_id, 0.0)))
            out[h.household_id] = d.stage
        self.matching.dispatch(to_dispatch)
        return out

    def _decide(self, h: HouseholdRecord) -> StageDecision:
        base = self.policy.decide(h.household_id, h.cell.id, None)
        if base.stage is Stage.PEACETIME:
            self._env1_cache.pop(h.household_id, None)
            return base
        env1 = self._env1_cache.get(h.household_id)
        if env1 is None:
            try:
                o = self._open_and_log(OpenRequest(h.household_id, Layer.ENVELOPE_1, Requester.policy_engine(),
                                                   base.evidence))
            except Denied as e:
                return StageDecision(Stage.PEACETIME, (), f"봉투 1 개봉 거부: {e}")
            env1 = decode_json(o.plaintext)
            self._env1_cache[h.household_id] = env1
        b = self._buildings.get(env1["building_id"])
        if b is None:
            return base
        risk = self.analyzer.assess(b, self._rain.get(h.cell.id))
        self._risks[h.household_id] = risk.score
        return base if base.stage is Stage.OPEN else self.policy.decide(h.household_id, h.cell.id, risk)

    def stage(self, household_id: str) -> Stage:
        d = self._decisions.get(household_id)
        return d.stage if d else Stage.PEACETIME

    def decision(self, household_id: str) -> StageDecision | None:
        return self._decisions.get(household_id)

    def risk(self, household_id: str) -> float | None:
        return self._risks.get(household_id)

    def standby_notices(self) -> dict[str, str]:
        """준비 단계 대기 호출. 주소 없이 격자 단위로만 알린다."""
        out = {}
        for helper in self.helpers.active():
            designated = nearby = 0
            for h in self._households.values():
                if self.stage(h.household_id) is Stage.PEACETIME:
                    continue
                if helper.id == h.designated_helper_id:
                    designated += 1
                elif helper.cell.distance(h.cell) <= 2:
                    nearby += 1
            if designated:
                out[helper.id] = "담당 가구 대기 요청"
            elif nearby:
                out[helper.id] = f"격자 {helper.cell.id} 일대 {nearby}곳 대기 요청 (주소 없음)"
        return out

    # ── 매칭·전달 ─────────────────────────────────────────
    def offers_for(self, helper_id: str) -> list[Offer]:
        return self.matching.offers_for(helper_id)

    def accept(self, helper_id: str, household_id: str, helper_device_id: str) -> str:
        """수락 → 잠금 배정 → 봉투 2 개봉(보관 기관 검증) → 단기 토큰 발급."""
        a = self.matching.accept(helper_id, household_id)
        d = self._decisions.get(household_id)
        try:
            o = self._open_and_log(OpenRequest(household_id, Layer.ENVELOPE_2, Requester.helper(helper_id),
                                               d.evidence if d else ()))
        except Denied:
            self.matching.abandon(helper_id, household_id)
            raise
        env2 = decode_json(o.plaintext)
        consented = {Field[n] for n in env2.pop("consented", [])}
        position = Position(*env2.pop("position"))
        record = {Field[k]: v for k, v in env2.items()}
        h = self._households[household_id]
        need = Capability[self._env1_cache.get(household_id, {}).get("need", "GENERAL")]
        return self.disclosure.issue(household_id, helper_id, a.tier, helper_device_id, h.cell, position, need, record,
                                     consented, o.valid_until, o.basis)

    def decline(self, helper_id: str, household_id: str) -> None:
        self.matching.decline(helper_id, household_id)

    def abandon(self, helper_id: str, household_id: str) -> None:
        self.matching.abandon(helper_id, household_id)
        self.disclosure.reseal(household_id)
        for c in self.custodians:
            c.release_helper(helper_id)

    def tick(self) -> None:
        self.matching.tick()

    def view(self, token: str, helper_device_id: str) -> HelperView:
        return self.disclosure.view(token, helper_device_id)

    def confirm_arrival(self, token: str, helper_device_id: str, helper_position: Position) -> None:
        self.disclosure.confirm_arrival(token, helper_device_id, helper_position)

    # ── 재봉인·감사·통지 ──────────────────────────────────
    def _reseal(self, household_id: str) -> None:
        a = self.matching.assignment(household_id)
        if a:
            for c in self.custodians:
                c.release_helper(a.helper_id)
        self.matching.release(household_id)
        self.disclosure.reseal(household_id)
        self.log.append(AuditType.RESEALED, household_id, "system", "자동 재봉인")

    def clear_alert(self, alert_id: str) -> None:
        """경보 해제. 재판정 시 공개 단계였던 가구는 자동 재봉인된다."""
        self.policy.clear(alert_id)
        self.evaluate()

    def anchor_audit_log(self) -> None:
        self.log.anchor_to(self.custodians)

    def audit_log_intact(self) -> bool:
        return self.log.verify_against(self.custodians)

    def notifications(self, household_id: str) -> list[str]:
        return notifications_for(self.log, household_id)

    def detect_anomalies(self) -> list[anomaly.Finding]:
        """이상 탐지 후 조력자 계정 정지. 공무원 계정은 추가 승인 대상으로 보고만 한다."""
        findings = anomaly.analyze(self.log.entries(), self.clock.now())
        for f in findings:
            if self.helpers.find(f.actor) and not self.helpers.is_suspended(f.actor):
                self.helpers.suspend(f.actor)
                self.log.append(AuditType.ACCOUNT_SUSPENDED, None, f.actor, f.rule)
        return findings

    def household(self, household_id: str) -> HouseholdRecord:
        return self._households[household_id]

    def envelope(self, household_id: str, layer: Layer) -> SealedEnvelope:
        return self._envelopes[(household_id, layer)]

    def active_disclosures(self) -> int:
        return self.disclosure.active_sessions()
