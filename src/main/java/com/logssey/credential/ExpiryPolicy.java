package com.logssey.credential;

/** 만료 방식. 만료일이 비어 있을 때 "만료 없음"과 "모름"을 구분하기 위해 둔다 (ERD 초안) */
public enum ExpiryPolicy {
    FIXED,
    NEVER,
    UNKNOWN
}
