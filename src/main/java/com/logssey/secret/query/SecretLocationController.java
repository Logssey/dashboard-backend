package com.logssey.secret.query;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretLocationController {
    private final SecretLocationService service;
    public SecretLocationController(SecretLocationService service) { this.service=service; }
    @GetMapping("/{id}/locations")
    public Map<String,Object> locations(@PathVariable long id,@RequestParam(defaultValue="PRODUCTION") String origin,
            @RequestParam(defaultValue="ALL") String source,@RequestParam(defaultValue="ALL") String environment,
            @RequestParam(defaultValue="ALL") String presence,@RequestParam(defaultValue="ALL") String exposure,
            @RequestParam(defaultValue="ALL") String actionStatus,@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size,@RequestParam(required=false) String expectedDetailVersion,
            Authentication authentication) {
        var filters=new SecretInventoryFilters(origin,source,"ALL",environment,"ALL","ALL","ALL","ALL","ALL");
        return service.locations(authentication==null?null:authentication.getName(),id,filters,page,size,
            presence,exposure,actionStatus,expectedDetailVersion);
    }
}
