package com.logssey.overview;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** 통합 현황 상단의 환경 선택 (API 명세 0.3) */
public enum EnvironmentFilter {
    ALL, PROD, DEV;

    public static EnvironmentFilter from(String value) {
        try {
            return EnvironmentFilter.valueOf(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "environment는 ALL, PROD, DEV 중 하나여야 합니다.");
        }
    }

    public boolean isAll() {
        return this == ALL;
    }
}
