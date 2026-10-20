package com.logssey.secret.decision;

import java.util.List;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** Contains codes only; compared source data and hidden locations are never returned. */
public final class SecretReviewConflict extends ApiException {
    private final List<String> changedFields;
    public SecretReviewConflict(String... fields) {
        super(ErrorCode.CONFLICT,"판정 근거가 변경되었어요. 근거를 다시 확인해 주세요.");
        this.changedFields=List.of(fields);
    }
    public List<String> changedFields() { return changedFields; }
}
