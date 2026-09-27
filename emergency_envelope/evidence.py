"""개봉 근거가 되는 서명된 외부 증거와 그 검증."""
from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import Denied, Stage, fields, iso, random_hex

MAX_CLOCK_SKEW = timedelta(minutes=2)
MAX_ALERT_VALIDITY = timedelta(hours=24)
DEVICE_SIGNAL_VALIDITY = timedelta(minutes=60)
MAX_ESCALATION_VALIDITY = timedelta(hours=3)


def _verify(pub: Ed25519PublicKey | None, message: bytes, signature: bytes | None) -> bool:
    if pub is None or not signature:
        return False
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False


class AlertLevel(Enum):
    ADVISORY = (Stage.PREPARE, "공식 침수예보")  # 사전예고·예보 → 준비
    WARNING = (Stage.OPEN, "공식 침수경보")  # 경보 → 공개

    @property
    def grants(self) -> Stage:
        return self.value[0]

    @property
    def label(self) -> str:
        return self.value[1]


class SignalType(Enum):
    WATER_LEVEL = "가정 수위 센서"
    EMERGENCY_BUTTON = "긴급버튼"


class EscalationReason(Enum):
    HIGH_RISK = "건물 고위험 판정"
    FEED_OUTAGE = "데이터 수신 두절(보수 모드)"


@dataclass(frozen=True)
class OfficialAlert:
    """재난안전 부서 수집기가 공식 특보를 받아 서명한 경보.
    실제 특보는 서명돼 오지 않으므로 수집기 서명이 신뢰의 기준점이다."""

    alert_id: str
    level: AlertLevel
    grid_cells: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        return fields("alert-v1", self.alert_id, self.level.name, ",".join(sorted(self.grid_cells)),
                      iso(self.issued_at), iso(self.expires_at), self.nonce, self.key_id)

    @property
    def basis(self) -> str:
        return self.level.label


@dataclass(frozen=True)
class DeviceSignal:
    """가정 기기 신호. 기기 키로 서명, 단조 증가 카운터로 재전송 방지."""

    device_id: str
    household_id: str
    type: SignalType
    counter: int
    issued_at: datetime
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        return fields("device-v1", self.device_id, self.household_id, self.type.name, self.counter, iso(self.issued_at))

    @property
    def basis(self) -> str:
        return self.type.value


@dataclass(frozen=True)
class Escalation:
    """정책 엔진이 서명한 "앞당기기" 선언. 단독으로는 아무것도 열 수 없고,
    같은 격자를 덮는 유효한 공식 예보(alert_id)와 함께일 때만 공개 근거가 된다."""

    alert_id: str
    grid_cell: str
    reason: EscalationReason
    risk_score: float
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        return fields("escalation-v1", self.alert_id, self.grid_cell, self.reason.name, f"{self.risk_score:.4f}",
                      iso(self.issued_at), iso(self.expires_at), self.key_id)

    @property
    def basis(self) -> str:
        return self.reason.value


Evidence = OfficialAlert | DeviceSignal | Escalation


class TrustStore:
    """증거 서명 검증용 공개키 목록. 각 보관 기관이 자기 사본을 가진다."""

    def __init__(self) -> None:
        self.alert_keys: dict[str, Ed25519PublicKey] = {}
        self.escalation_keys: dict[str, Ed25519PublicKey] = {}

    def trust_alert_key(self, key_id: str, key: Ed25519PublicKey) -> "TrustStore":
        self.alert_keys[key_id] = key
        return self

    def trust_escalation_key(self, key_id: str, key: Ed25519PublicKey) -> "TrustStore":
        self.escalation_keys[key_id] = key
        return self


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    household_id: str
    public_key: Ed25519PublicKey


class DeviceRegistry:
    """설치 시 등록한 가정 기기(선택)의 공개키."""

    def __init__(self) -> None:
        self._devices: dict[str, DeviceRecord] = {}

    def register(self, rec: DeviceRecord) -> None:
        self._devices[rec.device_id] = rec

    def find(self, device_id: str) -> DeviceRecord | None:
        return self._devices.get(device_id)

    def for_household(self, household_id: str) -> DeviceRecord | None:
        return next((d for d in self._devices.values() if d.household_id == household_id), None)


class EvidenceVerifier:
    """증거 한 건의 서명·유효 시간을 검증한다. 격자 일치나 증거 조합은 호출자가 판단한다."""

    def __init__(self, trust: TrustStore, devices: DeviceRegistry, clock):
        self.trust, self.devices, self.clock = trust, devices, clock

    def verify(self, e: Evidence) -> datetime:
        """통과하면 증거가 유효한 마지막 시각을 돌려준다."""
        if isinstance(e, OfficialAlert):
            if not _verify(self.trust.alert_keys.get(e.key_id), e.signed_bytes(), e.signature):
                raise Denied("경보 서명 검증 실패")
            self._window(e.issued_at, e.expires_at, MAX_ALERT_VALIDITY, "경보")
            return e.expires_at
        if isinstance(e, DeviceSignal):
            rec = self.devices.find(e.device_id)
            if rec is None:
                raise Denied("등록되지 않은 기기")
            if rec.household_id != e.household_id:
                raise Denied("기기와 가구 불일치")
            if not _verify(rec.public_key, e.signed_bytes(), e.signature):
                raise Denied("기기 서명 검증 실패")
            expires = e.issued_at + DEVICE_SIGNAL_VALIDITY
            self._window(e.issued_at, expires, DEVICE_SIGNAL_VALIDITY, "기기 신호")
            return expires
        if isinstance(e, Escalation):
            if not _verify(self.trust.escalation_keys.get(e.key_id), e.signed_bytes(), e.signature):
                raise Denied("앞당기기 서명 검증 실패")
            self._window(e.issued_at, e.expires_at, MAX_ESCALATION_VALIDITY, "앞당기기")
            return e.expires_at
        raise Denied("알 수 없는 증거")

    def _window(self, issued: datetime, expires: datetime, max_validity: timedelta, what: str) -> None:
        now = self.clock.now()
        if issued > now + MAX_CLOCK_SKEW:
            raise Denied(f"{what} 발령 시각이 미래임")
        if now >= expires:
            raise Denied(f"{what} 유효 시간 만료")
        if expires <= issued or expires - issued > max_validity:
            raise Denied(f"{what} 유효 기간 비정상")


class ReplayGuard:
    """수신 시점의 재전송 방지. 경보 nonce는 한 번만, 기기 카운터는 단조 증가만.
    한 경보가 여러 가구 개봉 근거가 되는 것은 정상이라 보관 기관은 유효 시간으로 제한한다."""

    def __init__(self) -> None:
        self._nonces: set[str] = set()
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    def check_alert(self, a: OfficialAlert) -> None:
        with self._lock:
            k = f"{a.key_id}/{a.nonce}"
            if k in self._nonces:
                raise Denied("재전송된 경보 (nonce 재사용)")
            self._nonces.add(k)

    def check_device(self, d: DeviceSignal) -> None:
        with self._lock:
            last = self._counters.get(d.device_id)
            if last is not None and d.counter <= last:
                raise Denied("재전송된 기기 신호 (카운터 역행)")
            self._counters[d.device_id] = d.counter


class AlertIssuer:
    """재난안전 부서 경보 수집기. MVP에서는 모의 발령기로 쓴다."""

    def __init__(self, key_id: str, clock):
        self.key_id, self.clock = key_id, clock
        self._key = Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def issue(self, level: AlertLevel, cells: set[str] | frozenset[str], validity: timedelta) -> OfficialAlert:
        now = self.clock.now()
        a = OfficialAlert(f"ALERT-{random_hex(3)}", level, frozenset(cells), now, now + validity, random_hex(16), self.key_id)
        return replace(a, signature=self._key.sign(a.signed_bytes()))


class EscalationSigner:
    """정책 엔진의 앞당기기 서명 키."""

    def __init__(self, key_id: str, clock):
        self.key_id, self.clock = key_id, clock
        self._key = Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def sign(self, advisory: OfficialAlert, cell: str, reason: EscalationReason, score: float) -> Escalation:
        now = self.clock.now()
        expires = min(advisory.expires_at, now + MAX_ESCALATION_VALIDITY)
        x = Escalation(advisory.alert_id, cell, reason, score, now, expires, self.key_id)
        return replace(x, signature=self._key.sign(x.signed_bytes()))


class HomeDevice:
    """가정 침수경보기·긴급버튼 시뮬레이터 (선택 설치, 시연에서는 Raspberry Pi가 이 역할)."""

    def __init__(self, household_id: str, clock):
        self.device_id = f"DEV-{random_hex(4)}"
        self.household_id = household_id
        self.clock = clock
        self._key = Ed25519PrivateKey.generate()
        self._counter = 0
        self._lock = threading.Lock()

    def registration(self) -> DeviceRecord:
        return DeviceRecord(self.device_id, self.household_id, self._key.public_key())

    def signal(self, type_: SignalType) -> DeviceSignal:
        with self._lock:
            self._counter += 1
            d = DeviceSignal(self.device_id, self.household_id, type_, self._counter, self.clock.now())
            return replace(d, signature=self._key.sign(d.signed_bytes()))
