package com.logssey.auth.dto.response;

import com.logssey.user.DashboardUser;

/** 로그인, 내 정보 조회 응답 (API 명세: 로그인, 내 정보 조회) */
public record LoginResponse(Long userId, String displayName, String role) {

    public static LoginResponse from(DashboardUser user) {
        return new LoginResponse(user.getUserId(), user.getDisplayName(), user.getRole());
    }
}
