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
@RestControllerAdvice(assignableTypes={SecretInventoryController.class,SecretLocationController.class})
public class SecretReadConflictAdvice {
    @ExceptionHandler(CannotSerializeTransactionException.class)
    public ResponseEntity<Map<String,Object>> retry(CannotSerializeTransactionException ignored) {
        return ResponseEntity.status(409).body(Map.of("code","CONFLICT","message","조회가 겹쳤어요. 다시 조회해 주세요.",
            "retryable",true,"details",Map.of("reasonCode","SNAPSHOT_RETRY")));
    }
}
