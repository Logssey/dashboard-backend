package com.logssey.reach.ci;

import java.util.Map;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 503 UNAVAILABLE 응답 (API 명세 2-6). 공통 오류 모양 { code, message }에 details.dependency를 더한다 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(basePackages = "com.logssey.reach.ci")
class ReachUnavailableAdvice {

    @ExceptionHandler(ReachUnavailableException.class)
    ResponseEntity<Map<String, Object>> unavailable(ReachUnavailableException e) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "code", "UNAVAILABLE",
                "message", "스캔 실행기(GitHub 워크플로)를 지금 부를 수 없습니다. 잠시 뒤 다시 시도해 주세요.",
                "details", Map.of("dependency", e.dependency())));
    }
}
