package com.logssey.secret.query;
import com.logssey.common.error.*;
/** Controlled public read conflicts without source identifiers or hidden counts. */
public final class SecretReadConflict extends ApiException {
    public enum Reason { SNAPSHOT_EXPIRED,SNAPSHOT_ACCESS_CHANGED,SNAPSHOT_MISMATCH,DETAIL_CHANGED,SNAPSHOT_RETRY }
    private final Reason reason;
    public SecretReadConflict(Reason reason){super(ErrorCode.CONFLICT,"조회 기준이 변경되었어요. 새로고침해 주세요.");this.reason=reason;}
    public Reason reason(){return reason;}
}
