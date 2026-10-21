package com.logssey.secret.validation;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** Only internal fixed reason codes enter public errors. Never include request or provider text. */
public final class ValidationApiException extends ApiException {
    private final String reasonCode;

    public ValidationApiException(ErrorCode code, String reasonCode) {
        super(code);
        this.reasonCode = reasonCode;
    }

    public String reasonCode() {
        return reasonCode;
    }
}
