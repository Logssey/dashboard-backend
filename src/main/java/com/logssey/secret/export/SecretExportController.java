package com.logssey.secret.export;

import java.nio.charset.StandardCharsets;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.query.SecretInventoryFilters;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretExportController {
    private final SecretExportService service;

    public SecretExportController(SecretExportService service) { this.service = service; }

    /** 키 목록(GET /api/v1/secrets)과 같은 필터·snapshotId를 받는다. */
    @GetMapping("/exports")
    public ResponseEntity<byte[]> export(@RequestParam String format,
                                         @RequestParam String snapshotId,
                                         @RequestParam(defaultValue = "ALL") String issuer,
                                         @RequestParam(defaultValue = "ALL") String componentState,
                                         @RequestParam(defaultValue = "PRODUCTION") String origin,
                                         @RequestParam(defaultValue = "ALL") String source,
                                         @RequestParam(defaultValue = "ALL") String provider,
                                         @RequestParam(defaultValue = "ALL") String environment,
                                         @RequestParam(defaultValue = "VALUE_FINDINGS") String contentKind,
                                         @RequestParam(defaultValue = "ALL") String workBucket,
                                         @RequestParam(defaultValue = "ALL") String validity,
                                         @RequestParam(defaultValue = "ALL") String severity,
                                         @RequestParam(required = false) Long runId,
                                         @RequestParam(required = false) String q,
                                         Authentication authentication) {
        if (!"ALL".equals(issuer)) {
            if (!"ALL".equals(provider) && !provider.equals(issuer)) throw new ApiException(ErrorCode.INVALID_INPUT);
            provider = issuer;
        }
        var filters = new SecretInventoryFilters(origin, source, provider, environment, contentKind, workBucket,
                componentState, validity, severity, q);
        var file = service.export(authentication == null ? null : authentication.getName(), format, filters, runId, snapshotId);
        var disposition = ContentDisposition.attachment().filename(file.filename(), StandardCharsets.UTF_8).build();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.parseMediaType(file.contentType()))
                .body(file.body());
    }
}
