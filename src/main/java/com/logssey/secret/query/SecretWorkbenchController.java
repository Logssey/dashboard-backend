package com.logssey.secret.query;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import com.logssey.common.error.*;
@RestController
@RequestMapping("/api/v1/secrets")
public class SecretWorkbenchController {
    private final SecretWorkbenchService service;
    public SecretWorkbenchController(SecretWorkbenchService service){this.service=service;}
    @GetMapping("/summary")
    public Map<String,Object> summary(@RequestParam(defaultValue="PRODUCTION") String origin,
        @RequestParam(defaultValue="ALL") String source,@RequestParam(defaultValue="ALL") String provider,
        @RequestParam(defaultValue="ALL") String environment,@RequestParam(required=false) Long connectionId,
        @RequestParam(required=false) String assignee,@RequestParam(required=false) String snapshotId,
        @RequestParam Map<String,String> params,Authentication a) {
        if(!java.util.Set.of("origin","source","provider","environment","connectionId","assignee","snapshotId").containsAll(params.keySet()))throw new ApiException(ErrorCode.INVALID_INPUT);
        return service.summary(a==null?null:a.getName(),new SecretWorkbenchService.Filters(origin,source,provider,environment,connectionId,assignee),snapshotId);
    }

    @GetMapping(value="/scopes",params="snapshotId")
    public Map<String,Object> scopes(@RequestParam(defaultValue="PRODUCTION") String origin,
        @RequestParam(defaultValue="ALL") String source,@RequestParam(defaultValue="ALL") String provider,
        @RequestParam(defaultValue="ALL") String environment,@RequestParam(required=false) Long connectionId,
        @RequestParam(required=false) String assignee,@RequestParam(required=false) String snapshotId,
        @RequestParam(defaultValue="NEEDS_REVIEW") String classificationStatus,
        @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size,Authentication a) {
        if(!classificationStatus.equals("NEEDS_REVIEW"))throw new ApiException(ErrorCode.INVALID_INPUT);
        return service.queue(a==null?null:a.getName(),new SecretWorkbenchService.Filters(origin,source,provider,environment,connectionId,assignee),"UNCLASSIFIED",null,page,size,snapshotId);
    }

    @GetMapping("/matrix")
    public Map<String,Object> matrix(@RequestParam(defaultValue="PRODUCTION") String origin,
        @RequestParam(defaultValue="ALL") String source,@RequestParam(defaultValue="ALL") String provider,
        @RequestParam(defaultValue="ALL") String environment,@RequestParam(required=false) Long connectionId,
        @RequestParam(required=false) String assignee,@RequestParam(required=false) String snapshotId,
        @RequestParam Map<String,String> params,Authentication a) {
        if(!java.util.Set.of("origin","source","provider","environment","connectionId","assignee","snapshotId").containsAll(params.keySet()))throw new ApiException(ErrorCode.INVALID_INPUT);
        return service.matrix(a==null?null:a.getName(),new SecretWorkbenchService.Filters(origin,source,provider,environment,connectionId,assignee),snapshotId);
    }
}
