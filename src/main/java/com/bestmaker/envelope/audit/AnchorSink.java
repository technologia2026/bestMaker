package com.bestmaker.envelope.audit;

/** 체인 끝 해시를 받아 적는 외부 기관 (열쇠 보관 기관). */
public interface AnchorSink {
    void recordAnchor(long seq, String hash);

    /** 기록된 앵커 해시. 없으면 null. */
    String anchorAt(long seq);

    /** 가장 최근에 기록된 앵커 번호. 없으면 -1. */
    long latestAnchorSeq();
}
