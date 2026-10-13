package com.logssey.secretworker.detector;

/** Public failure code only: a tool error may contain the scanned credential. */
public final class DetectionFailure extends RuntimeException {

    public enum Code {
        INPUT_TOO_LARGE, OUTPUT_TOO_LARGE, TOOL_UNAVAILABLE, UNSUPPORTED_VERSION,
        TOOL_TIMEOUT, TOOL_EXIT, INVALID_REPORT, TOOL_IO_ERROR, INTERRUPTED
    }

    private final Code code;

    public DetectionFailure(Code code) {
        super(code.name());
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
