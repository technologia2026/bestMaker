package com.bestmaker.envelope.common;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

/** 시연·테스트용 시계. 강우 기록 재생 시 시간을 앞으로 돌린다. */
public final class MutableClock extends Clock {
    private volatile Instant now;
    private final ZoneId zone;

    public MutableClock(Instant start) {
        this(start, ZoneId.of("Asia/Seoul"));
    }

    private MutableClock(Instant start, ZoneId zone) {
        this.now = start;
        this.zone = zone;
    }

    public void advance(Duration d) {
        now = now.plus(d);
    }

    public void set(Instant t) {
        now = t;
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId z) {
        return new MutableClock(now, z);
    }

    @Override
    public Instant instant() {
        return now;
    }
}
