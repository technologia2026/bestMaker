"""봉인(AES-256-GCM)과 열쇠 분산(Shamir 2-of-3)."""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

# Bandit B413은 관리 중단된 pycrypto를 겨냥하지만, 같은 Crypto 이름공간을 쓰는 pycryptodome(현역)까지 잡는 오탐이다.
from Crypto.Cipher import AES  # nosec B413
from Crypto.Protocol.SecretSharing import Shamir  # nosec B413
from Crypto.Random import get_random_bytes  # nosec B413

from .common import Denied, fields

KEY_BYTES = 32
SHARES = 3
THRESHOLD = 2
_AAD_DOMAIN = "bestmaker-envelope-v1"


class Layer(Enum):
    ENVELOPE_1 = "봉투 1"  # 건물 ID, 필요 유형 — 준비 단계에서 정책 엔진만
    ENVELOPE_2 = "봉투 2"  # 호수, 상태, 탈출 경로, 비상연락처 — 공개 단계, 배정된 조력자 1인


@dataclass(frozen=True)
class SealedEnvelope:
    household_id: str
    layer: Layer
    version: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def relabel(self, household_id: str | None = None, layer: Layer | None = None,
                version: int | None = None) -> "SealedEnvelope":
        """라벨만 바꾼 사본 (바꿔치기 공격 시뮬레이션용)."""
        return replace(self, household_id=household_id or self.household_id, layer=layer or self.layer,
                       version=self.version if version is None else version)


def new_data_key() -> bytearray:
    return bytearray(get_random_bytes(KEY_BYTES))


def _aad(household_id: str, layer: Layer, version: int) -> bytes:
    return fields(_AAD_DOMAIN, household_id, layer.name, version)


def _require_key(key: bytes | bytearray) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError("AES-256 키가 아님")


def seal(household_id: str, layer: Layer, version: int, plaintext: bytes, key: bytes | bytearray) -> SealedEnvelope:
    """AAD에 가구 ID·층·버전을 넣어, 다른 가구 봉투로 바꿔 끼우면 복호화 단계에서 실패하게 한다."""
    _require_key(key)
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=get_random_bytes(12), mac_len=16)
    cipher.update(_aad(household_id, layer, version))
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return SealedEnvelope(household_id, layer, version, cipher.nonce, ct, tag)


def open_envelope(env: SealedEnvelope, key: bytes | bytearray) -> bytes:
    _require_key(key)
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=env.nonce, mac_len=16)
    cipher.update(_aad(env.household_id, env.layer, env.version))
    try:
        return cipher.decrypt_and_verify(env.ciphertext, env.tag)
    except ValueError:
        raise Denied("봉투 무결성 검증 실패") from None


def split_key(key: bytes | bytearray) -> dict[int, bytes]:
    """pycryptodome Shamir는 16바이트 비밀만 다루므로 32바이트 키를 두 덩어리로 나눠 각각 2-of-3 분산한다.

    반환: 조각 번호(1..3) → 32바이트 조각 (앞 16바이트 = 앞 덩어리 조각, 뒤 16바이트 = 뒤 덩어리 조각).
    """
    _require_key(key)
    lo = Shamir.split(THRESHOLD, SHARES, bytes(key[:16]))
    hi = Shamir.split(THRESHOLD, SHARES, bytes(key[16:]))
    hi_by_idx = dict(hi)
    return {idx: share + hi_by_idx[idx] for idx, share in lo}


def join_key(shares: dict[int, bytes]) -> bytearray:
    """Shamir.combine은 조각이 모자라도 오류 없이 엉뚱한 값을 내므로 개수를 직접 강제한다."""
    if len(shares) < THRESHOLD:
        raise Denied(f"열쇠 조각 부족: {len(shares)}/{THRESHOLD}")
    lo = Shamir.combine([(i, s[:16]) for i, s in shares.items()])
    hi = Shamir.combine([(i, s[16:]) for i, s in shares.items()])
    return bytearray(lo + hi)


def wipe(buf: bytearray) -> None:
    """복원한 키를 메모리에서 덮어쓴다 (bytes 사본은 GC에 맡길 수밖에 없다)."""
    for i in range(len(buf)):
        buf[i] = 0
