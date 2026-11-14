package com.logssey.secret.query;

import java.util.Map;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.CannotSerializeTransactionException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Concurrent snapshot creation safely retries without emitting SQL or replacing another user's snapshot. */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(basePackages="com.logssey.secret")
public class SecretReadConflictAdvice {
    @ExceptionHandler(SecretReadConflict.class)
    public ResponseEntity<Map<String,Object>> changed(SecretReadConflict e) {
        if(e.reason()==SecretReadConflict.Reason.SNAPSHOT_RETRY) return retryResponse();
        return ResponseEntity.status(409).body(Map.of("code","CONFLICT","message",e.getMessage(),"details",Map.of("reasonCode",e.reason().name())));
    }
    @ExceptionHandler(CannotSerializeTransactionException.class)
    public ResponseEntity<Map<String,Object>> retry(CannotSerializeTransactionException ignored) {
        return retryResponse();
    }
    private ResponseEntity<Map<String,Object>> retryResponse() {
        return ResponseEntity.status(409).body(Map.of("code","CONFLICT","message","조회가 겹쳤어요. 다시 조회해 주세요.",
            "retryable",true,"details",Map.of("reasonCode","SNAPSHOT_RETRY")));
    }
}
