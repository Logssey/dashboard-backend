package com.logssey.credential;

/** 키 상태. ERD 초안 credentials.status와 같은 값이다 */
public enum CredentialStatus {
    ACTIVE,
    INACTIVE,
    EXPIRED,
    REVOKED,
    UNKNOWN
}
