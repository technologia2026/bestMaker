package com.bestmaker.envelope.common;

/** 보안 검사에서 거부된 요청. 메시지는 사용자에게 보여도 되는 사유만 담는다. */
public class DeniedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public DeniedException(String reason) {
        super(reason);
    }
}
