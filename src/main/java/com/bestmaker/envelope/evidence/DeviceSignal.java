package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.Codec;

import java.time.Instant;

/** 가정 기기(수위 센서·긴급버튼) 신호. 기기 키로 서명, 단조 증가 카운터로 재전송 방지. */
public record DeviceSignal(String deviceId, String householdId, SignalType type, long counter, Instant issuedAt,
                           byte[] signature) implements Evidence {
    public DeviceSignal {
        signature = signature == null ? null : signature.clone();
    }

    @Override
    public byte[] signature() {
        return signature == null ? null : signature.clone();
    }

    @Override
    public byte[] signedBytes() {
        return signedBytes(deviceId, householdId, type, counter, issuedAt);
    }

    static byte[] signedBytes(String deviceId, String householdId, SignalType type, long counter, Instant at) {
        return Codec.fields("device-v1", deviceId, householdId, type.name(), Long.toString(counter), at.toString());
    }

    @Override
    public String basis() {
        return type.label();
    }
}
