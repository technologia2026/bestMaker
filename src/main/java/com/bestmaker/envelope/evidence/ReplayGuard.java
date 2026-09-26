package com.bestmaker.envelope.evidence;

import com.bestmaker.envelope.common.DeniedException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 수신(ingest) 시점의 재전송 방지. 경보 nonce는 한 번만, 기기 카운터는 단조 증가만 허용.
 * 한 경보가 여러 가구 개봉의 근거가 되는 것은 정상이므로 보관 기관은 nonce가 아니라
 * 유효 시간으로 재사용을 제한한다.
 */
public final class ReplayGuard {
    private final Set<String> seenAlertNonces = new HashSet<>();
    private final Map<String, Long> deviceCounters = new HashMap<>();

    public synchronized void checkAlert(OfficialAlert a) {
        if (!seenAlertNonces.add(a.keyId() + "/" + a.nonce())) {
            throw new DeniedException("재전송된 경보 (nonce 재사용)");
        }
    }

    public synchronized void checkDevice(DeviceSignal d) {
        Long last = deviceCounters.get(d.deviceId());
        if (last != null && d.counter() <= last) {
            throw new DeniedException("재전송된 기기 신호 (카운터 역행)");
        }
        deviceCounters.put(d.deviceId(), d.counter());
    }
}
