package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.Ids;
import com.bestmaker.envelope.disclosure.ArrivalCodes;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;

/** 가정 침수경보기·긴급버튼 시뮬레이터 (시연에서는 Raspberry Pi가 이 역할). */
public final class HomeDevice {
    private final String deviceId;
    private final String householdId;
    private final KeyPair keys;
    private final byte[] arrivalSecret;
    private final Clock clock;
    private long counter;

    public HomeDevice(String householdId, Clock clock) {
        this.deviceId = "DEV-" + Ids.randomHex(4);
        this.householdId = householdId;
        this.keys = Signatures.newKeyPair();
        this.arrivalSecret = Ids.randomBytes(32);
        this.clock = clock;
    }

    /** 설치 시 등록 정보. */
    public DeviceRegistry.DeviceRecord registration() {
        return new DeviceRegistry.DeviceRecord(deviceId, householdId, keys.getPublic(), arrivalSecret);
    }

    public String deviceId() {
        return deviceId;
    }

    public synchronized DeviceSignal signal(SignalType type) {
        long c = ++counter;
        Instant now = clock.instant();
        byte[] sig = Signatures.sign(keys.getPrivate(),
                DeviceSignal.signedBytes(deviceId, householdId, type, c, now));
        return new DeviceSignal(deviceId, householdId, type, c, now, sig);
    }

    /** 재난 중 기기 화면에 표시되는 도착 코드. */
    public String arrivalCode() {
        return ArrivalCodes.code(arrivalSecret, householdId, clock.instant());
    }
}
