package com.logssey.security;

import java.io.IOException;

import com.logssey.common.error.ApiErrorResponse;
import com.logssey.common.error.ErrorCode;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/** 보안 필터에서 막힌 요청도 { code, message } 모양으로 응답한다 */
final class JsonSecurityErrorHandlers {

    private JsonSecurityErrorHandlers() {
    }

    /** 로그인 안 됨, 세션 만료 → 401 UNAUTHENTICATED */
    static AuthenticationEntryPoint unauthenticated() {
        return (request, response, exception) -> write(response, ErrorCode.UNAUTHENTICATED);
    }

    /** CSRF 토큰 누락·불일치 등 → 403 FORBIDDEN */
    static AccessDeniedHandler forbidden() {
        return (request, response, exception) -> write(response, ErrorCode.FORBIDDEN);
    }

    private static void write(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setStatus(errorCode.status().value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(ApiErrorResponse.of(errorCode).toJson());
    }
}
