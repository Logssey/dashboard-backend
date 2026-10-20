package com.logssey.secret.connection;

import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretCoverageController {
    private final SecretCoverageService service;
    public SecretCoverageController(SecretCoverageService service){this.service=service;}
    @GetMapping("/connections/manage")
    public Map<String,Object> connections(@RequestParam(defaultValue="ALL") String status,
        @RequestParam(defaultValue="ALL") String origin,@RequestParam(defaultValue="0") int page,
        @RequestParam(defaultValue="20") int size,@RequestParam Map<String,String> params,Authentication a){
        requireKnown(params,"status","origin","page","size");return service.connections(login(a),status,origin,page,size);}
    @GetMapping("/connections/{connectionId}/scopes")
    public Map<String,Object> scopes(@PathVariable long connectionId,@RequestParam(defaultValue="ALL") String origin,
        @RequestParam(defaultValue="ALL") String classificationStatus,@RequestParam(defaultValue="false") boolean gapOnly,
        @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size,@RequestParam Map<String,String> params,Authentication a){
        requireKnown(params,"origin","classificationStatus","gapOnly","page","size");return service.scopes(login(a),connectionId,origin,classificationStatus,gapOnly,page,size);}
    @GetMapping("/coverage-gaps")
    public Map<String,Object> gaps(@RequestParam(defaultValue="PRODUCTION") String origin,
        @RequestParam(defaultValue="ALL") String source,@RequestParam(required=false) Long connectionId,
        @RequestParam(required=false) String snapshotId,@RequestParam(defaultValue="0") int page,
        @RequestParam(defaultValue="20") int size,@RequestParam Map<String,String> params,Authentication a){
        requireKnown(params,"origin","source","connectionId","snapshotId","page","size");return service.gaps(login(a),origin,source,connectionId,snapshotId,page,size);}
    private static void requireKnown(Map<String,String> params,String... names) {
        if(!java.util.Set.of(names).containsAll(params.keySet()))throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.INVALID_INPUT);
    }
    private static String login(Authentication a){return a==null?null:a.getName();}
}
