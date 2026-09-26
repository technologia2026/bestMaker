package com.bestmaker.envelope.evidence;

import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** 설치 시 등록한 가정 기기의 공개키와 도착 코드 비밀. */
public final class DeviceRegistry {
    public record DeviceRecord(String deviceId, String householdId, PublicKey publicKey, byte[] arrivalSecret) {
        public DeviceRecord {
            arrivalSecret = arrivalSecret.clone();
        }

        @Override
        public byte[] arrivalSecret() {
            return arrivalSecret.clone();
        }
    }

    private final Map<String, DeviceRecord> devices = new ConcurrentHashMap<>();

    public void register(DeviceRecord record) {
        devices.put(record.deviceId(), record);
    }

    public Optional<DeviceRecord> find(String deviceId) {
        return deviceId == null ? Optional.empty() : Optional.ofNullable(devices.get(deviceId));
    }

    public Optional<DeviceRecord> forHousehold(String householdId) {
        return devices.values().stream().filter(d -> d.householdId().equals(householdId)).findFirst();
    }
}
