package com.bestmaker.envelope.evidence;

/** 개봉 근거가 되는 서명된 외부 증거. */
public sealed interface Evidence permits OfficialAlert, DeviceSignal, Escalation {
    byte[] signedBytes();

    byte[] signature();

    /** 통지·감사 기록용 근거 문구. */
    String basis();
}
