"""열쇠 보관 기관과 키 조합기."""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from .common import Denied, Stage
from .crypto import Layer, SealedEnvelope, THRESHOLD, join_key, open_envelope, wipe
from .evidence import AlertLevel, DeviceSignal, Escalation, Evidence, EvidenceVerifier, OfficialAlert
from .matching import HelperRegistry


class Role(Enum):
    POLICY_ENGINE = "정책 엔진"  # 준비 단계에서 봉투 1만
    HELPER = "조력자"  # 공개 단계에서 봉투 2
    OFFICIAL = "공무원·관리자"  # 어떤 봉투도 열 수 없음


@dataclass(frozen=True)
class Requester:
    """개봉 요청 주체. 조력자의 신뢰 등급은 요청자가 주장하지 않고 받는 쪽이 계산한다."""

    id: str
    role: Role

    @staticmethod
    def policy_engine() -> "Requester":
        return Requester("policy-engine", Role.POLICY_ENGINE)

    @staticmethod
    def official(id_: str) -> "Requester":
        return Requester(id_, Role.OFFICIAL)

    @staticmethod
    def helper(id_: str) -> "Requester":
        return Requester(id_, Role.HELPER)


@dataclass(frozen=True)
class OpenRequest:
    household_id: str
    layer: Layer
    requester: Requester
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ShareGrant:
    custodian: str
    index: int
    share: bytes
    valid_until: datetime
    basis: str


@dataclass(frozen=True)
class EvaluationResult:
    stage: Stage
    valid_until: datetime | None
    basis: str
    rejected: tuple[str, ...]


def evaluate_evidence(verifier: EvidenceVerifier, evidence: tuple[Evidence, ...], household_id: str,
                      grid_cell: str) -> EvaluationResult:
    """증거 묶음이 특정 가구(격자)에 허용하는 최고 단계.

    - 그 가구의 유효한 기기 신호 → 공개
    - 격자를 덮는 경보 → 공개
    - 격자를 덮는 예보 + 같은 예보·격자에 대한 앞당기기 → 공개
    - 격자를 덮는 예보 → 준비
    - 앞당기기 단독 → 아무것도 아님
    """
    rejected: list[str] = []
    advisories: list[OfficialAlert] = []
    escalations: list[Escalation] = []
    best, until, basis = Stage.PEACETIME, None, "증거 없음"
    for e in evidence:
        try:
            valid_until = verifier.verify(e)
        except Denied as ex:
            rejected.append(str(ex))
            continue
        if isinstance(e, DeviceSignal):
            if e.household_id == household_id:
                best, until, basis = Stage.OPEN, max(until or valid_until, valid_until), e.basis
            else:
                rejected.append("다른 가구의 기기 신호")
        elif isinstance(e, OfficialAlert):
            if grid_cell not in e.grid_cells:
                rejected.append("경보 격자 불일치")
            elif e.level is AlertLevel.WARNING:
                best, until, basis = Stage.OPEN, max(until or valid_until, valid_until), e.basis
            else:
                advisories.append(e)
        else:
            escalations.append(e)
    if best is not Stage.OPEN:
        for adv in advisories:
            for x in escalations:
                if x.alert_id == adv.alert_id and x.grid_cell == grid_cell:
                    best, until, basis = Stage.OPEN, min(adv.expires_at, x.expires_at), f"{adv.basis} + {x.basis}"
    if best is Stage.PEACETIME and advisories:
        best, until, basis = Stage.PREPARE, advisories[0].expires_at, advisories[0].basis
    if best is Stage.PEACETIME and escalations:
        rejected.append("앞당기기는 공식 예보 없이 근거가 될 수 없음")
    return EvaluationResult(best, until, basis, tuple(rejected))


@dataclass(frozen=True)
class Decision:
    at: datetime
    household_id: str
    layer: Layer
    requester: str
    granted: bool
    reason: str


class KeyCustodian:
    """열쇠 보관 기관 (재난안전 부서 / 자치구 / 감사 기관). 같은 코드를 설정만 바꿔 세 번 띄운다.
    정책 엔진을 믿지 않고 증거·유효 시간·격자·조력자 자격을 직접 확인한 뒤에만 조각을 내준다."""

    def __init__(self, name: str, verifier: EvidenceVerifier, helpers: HelperRegistry, clock):
        self.name, self.verifier, self.helpers, self.clock = name, verifier, helpers, clock
        self._shares: dict[tuple[str, Layer], tuple[int, bytes, str]] = {}
        self._helper_grants: dict[str, tuple[str, datetime]] = {}
        self._anchors: dict[int, str] = {}
        self._latest_anchor = -1
        self._decisions: list[Decision] = []
        self._lock = threading.Lock()

    def store(self, household_id: str, layer: Layer, grid_cell: str, index: int, share: bytes) -> None:
        """봉인 시 조각 보관. 가구의 격자는 평문 층 정보라 보관 기관도 안다."""
        self._shares[(household_id, layer)] = (index, bytes(share), grid_cell)

    def release(self, req: OpenRequest) -> ShareGrant:
        try:
            g = self._check(req)
            self._record(req, True, g.basis)
            return g
        except Denied as e:
            self._record(req, False, str(e))
            raise

    def _check(self, req: OpenRequest) -> ShareGrant:
        stored = self._shares.get((req.household_id, req.layer))
        if stored is None:
            raise Denied("보관 중인 조각 없음")
        index, share, cell = stored
        who = req.requester
        if who.role is Role.OFFICIAL:
            raise Denied("관리자·공무원은 봉투를 열 수 없음")
        if not req.evidence:
            raise Denied("증거 없음")
        r = evaluate_evidence(self.verifier, req.evidence, req.household_id, cell)
        why = ", ".join(r.rejected) or r.basis
        if req.layer is Layer.ENVELOPE_1:
            if who.role is not Role.POLICY_ENGINE:
                raise Denied("봉투 1은 정책 엔진만 사용")
            if not r.stage.at_least(Stage.PREPARE):
                raise Denied(f"준비 단계 근거 부족: {why}")
        else:
            if who.role is not Role.HELPER:
                raise Denied("봉투 2는 배정된 조력자에게만")
            if not self.helpers.is_qualified(who.id):
                raise Denied("조력자 자격 없음 또는 정지")
            if r.stage is not Stage.OPEN:
                raise Denied(f"공개 단계 근거 부족: {why}")
            self._claim_helper_slot(who.id, req.household_id, r.valid_until)
        return ShareGrant(self.name, index, share, r.valid_until, r.basis)

    def _claim_helper_slot(self, helper_id: str, household_id: str, until: datetime) -> None:
        """보관 기관 스스로도 "조력자 1인 = 가구 1곳"을 강제한다."""
        with self._lock:
            cur = self._helper_grants.get(helper_id)
            if cur and cur[1] > self.clock.now() and cur[0] != household_id:
                raise Denied("조력자가 이미 다른 가구를 맡고 있음")
            self._helper_grants[helper_id] = (household_id, until)

    def release_helper(self, helper_id: str) -> None:
        with self._lock:
            self._helper_grants.pop(helper_id, None)

    def _record(self, req: OpenRequest, granted: bool, reason: str) -> None:
        with self._lock:
            self._decisions.append(Decision(self.clock.now(), req.household_id, req.layer, req.requester.id,
                                            granted, reason))

    def decisions(self) -> list[Decision]:
        with self._lock:
            return list(self._decisions)

    def share_count(self) -> int:
        return len(self._shares)

    # AnchorSink
    def record_anchor(self, seq: int, hash_: str) -> None:
        with self._lock:
            self._anchors.setdefault(seq, hash_)
            self._latest_anchor = max(self._latest_anchor, seq)

    def anchor_at(self, seq: int) -> str | None:
        return self._anchors.get(seq)

    def latest_anchor_seq(self) -> int:
        return self._latest_anchor


@dataclass(frozen=True)
class Opened:
    plaintext: bytes
    valid_until: datetime
    basis: str
    custodians: tuple[str, ...]


class KeyCombiner:
    """내부망 키 조합기. 조각 2개 이상을 받아 메모리에서만 키를 복원하고 즉시 지운다."""

    def __init__(self, custodians: list[KeyCustodian]):
        self.custodians = list(custodians)

    def open(self, req: OpenRequest, env: SealedEnvelope | None) -> Opened:
        if env is None or env.household_id != req.household_id or env.layer is not req.layer:
            raise Denied("요청과 봉투 불일치")
        parts: dict[int, bytes] = {}
        granted, denied = [], []
        until, basis = None, ""
        for c in self.custodians:
            try:
                g = c.release(req)
            except Denied as e:
                denied.append(f"{c.name}: {e}")
                continue
            parts[g.index] = g.share
            granted.append(c.name)
            until = g.valid_until if until is None else min(until, g.valid_until)
            basis = g.basis
        if len(parts) < THRESHOLD:
            raise Denied(f"개봉 거부 ({' / '.join(denied)})")
        key = join_key(parts)
        try:
            return Opened(open_envelope(env, key), until, basis, tuple(granted))
        finally:
            wipe(key)
