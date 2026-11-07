package com.logssey.secretworker.usage;
import java.time.Instant;
/** Never retains SDK exception messages, request headers, identifiers or response bodies. */
public final class AwsUsageFailure extends RuntimeException {
    private final String code; private final boolean retryable; private final Instant retryAt;
    public AwsUsageFailure(String code,boolean retryable,Instant retryAt){super(code,null,false,false);this.code=code;this.retryable=retryable;this.retryAt=retryAt;}
    public String code(){return code;} public boolean retryable(){return retryable;} public Instant retryAt(){return retryAt;}
}
