package com.logssey.secret.validation;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(basePackages = "com.logssey.secret.validation")
public class ValidationApiAdvice {
    @ExceptionHandler(ValidationRateLimitException.class)
    public ResponseEntity<Map<String, Object>> rateLimit() {
        return ResponseEntity.status(429)
                .header("Retry-After", "60")
                .body(
                        Map.of(
                                "code",
                                "RATE_LIMITED",
                                "message",
                                "Credential validation request budget exceeded.",
                                "details",
                                Map.of(
                                        "reasonCode",
                                        "RATE_BUDGET_EXHAUSTED",
                                        "retryAfterSeconds",
                                        60)));
    }

    @ExceptionHandler(ValidationApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ValidationApiException e) {
        return ResponseEntity.status(e.errorCode().status())
                .body(
                        Map.of(
                                "code",
                                e.errorCode().name(),
                                "message",
                                e.errorCode().defaultMessage(),
                                "details",
                                Map.of("reasonCode", e.reasonCode())));
    }
}
