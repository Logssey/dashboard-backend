package com.logssey.secret.run;

import java.net.URI;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets/runs")
public class SecretRunController {

    private final SecretRunService service;
    private final SecretRunQueryService queries;

    @org.springframework.beans.factory.annotation.Autowired
    public SecretRunController(SecretRunService service,SecretRunQueryService queries) {
        this.service = service;
        this.queries=queries;
    }
    SecretRunController(SecretRunService service){this(service,null);}

    @PostMapping
    public ResponseEntity<SecretRunAcceptedResponse> register(@Valid @RequestBody SecretRunRequest request,
                                                               Authentication authentication) {
        var accepted = service.register(request, authentication == null ? null : authentication.getName());
        return ResponseEntity.accepted()
                .location(URI.create("/api/v1/secrets/runs/" + accepted.runId()))
                .body(accepted);
    }

    public record RetryFailedRequest(String idempotencyKey) { }

    @PostMapping("/{runId}/retry-failed")
    public ResponseEntity<SecretRunAcceptedResponse> retryFailed(@PathVariable long runId,
            @RequestBody RetryFailedRequest request, Authentication authentication) {
        var accepted = service.retryFailed(runId,request == null ? null : request.idempotencyKey(),
                authentication == null ? null : authentication.getName());
        return ResponseEntity.accepted().location(URI.create("/api/v1/secrets/runs/"+accepted.runId())).body(accepted);
    }

    @GetMapping("/{runId}")
    public Object status(@PathVariable long runId, Authentication authentication) {
        String login=authentication == null ? null : authentication.getName();
        return queries==null?service.status(runId,login):queries.status(login,runId);
    }

    @GetMapping
    public java.util.Map<String,Object> list(@RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "20") int size,
                                      @RequestParam(defaultValue="ALL") String type,@RequestParam(defaultValue="ALL") String status,
                                      @RequestParam(defaultValue="ALL") String provider,
                                      @RequestParam(required=false) Long connectionId,@RequestParam(required=false) java.time.OffsetDateTime from,
                                      @RequestParam(required=false) java.time.OffsetDateTime to,@RequestParam(required=false) String snapshotId,
                                      @RequestParam java.util.Map<String,String> params,Authentication authentication) {
        if(!java.util.Set.of("page","size","type","status","provider","connectionId","from","to","snapshotId").containsAll(params.keySet()))throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.INVALID_INPUT);
        return queries.list(authentication == null ? null : authentication.getName(),type,status,provider,connectionId,from,to,page,size,snapshotId);
    }

    @GetMapping("/{runId}/findings")
    public java.util.Map<String,Object> findings(@PathVariable long runId,@RequestParam(defaultValue="0") int page,
        @RequestParam(defaultValue="20") int size,Authentication a){return queries.findings(a==null?null:a.getName(),runId,page,size);}
}
