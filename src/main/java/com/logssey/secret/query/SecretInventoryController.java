package com.logssey.secret.query;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretInventoryController {
    private final SecretInventoryService service;
    private final SecretLocationService locations;

    public SecretInventoryController(SecretInventoryService service,SecretLocationService locations) {
        this.service = service;
        this.locations=locations;
    }

    @GetMapping
    public java.util.Map<String,Object> list(@RequestParam(defaultValue = "0") int page,
                                   @RequestParam(defaultValue = "20") int size,
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
                                   @RequestParam(required=false) String snapshotId,
                                   @RequestParam(required=false) Long runId,
                                   Authentication authentication) {
        if(!"ALL".equals(issuer)) {
            if(!"ALL".equals(provider)&&!provider.equals(issuer))
                throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.INVALID_INPUT);
            provider=issuer;
        }
        var filters=new SecretInventoryFilters(origin,source,provider,environment,contentKind,workBucket,componentState,validity,severity);
        return runId==null?locations.inventory(loginId(authentication),filters,page,size,snapshotId):
            locations.inventory(loginId(authentication),filters,page,size,snapshotId,runId);
    }

    @GetMapping("/connections")
    public SecretConnectionListResponse connections(Authentication authentication) {
        return service.connections(loginId(authentication));
    }

    @GetMapping("/{id}")
    public java.util.Map<String,Object> detail(@PathVariable long id,
            @RequestParam(defaultValue="PRODUCTION") String origin,Authentication authentication) {
        return locations.detail(loginId(authentication),id,origin);
    }

    private static String loginId(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
