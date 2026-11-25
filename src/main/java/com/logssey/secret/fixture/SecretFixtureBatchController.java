package com.logssey.secret.fixture;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets/fixture-attestations")
public class SecretFixtureBatchController {
    private final SecretFixtureService fixtures;
    public SecretFixtureBatchController(SecretFixtureService fixtures) { this.fixtures=fixtures; }
    public record Item(Long credentialSetId,SecretFixtureService.Attest attestation) { }
    public record Batch(List<Item> items) { }

    @PostMapping("/batch")
    public Map<String,Object> attest(@RequestBody Batch request,Authentication authentication) {
        if(request==null || request.items()==null || request.items().isEmpty() || request.items().size()>100
                || request.items().stream().anyMatch(item -> item==null || item.credentialSetId()==null
                    || item.credentialSetId()<=0 || item.attestation()==null))
            throw new ApiException(ErrorCode.INVALID_INPUT);
        String login=authentication==null?null:authentication.getName();
        var results=new ArrayList<Map<String,Object>>();
        long succeeded=0;
        for(var item:request.items()) {
            try {
                var result=fixtures.attest(login,item.credentialSetId(),item.attestation());
                results.add(Map.of("credentialSetId",item.credentialSetId(),"status","ATTESTED","result",result));
                succeeded++;
            } catch(ApiException failure) {
                results.add(Map.of("credentialSetId",item.credentialSetId(),"status","FAILED","errorCode",failure.errorCode().name()));
            }
        }
        return Map.of("items",results,"succeededCount",succeeded,"failedCount",results.size()-succeeded,
                "requiresSnapshotRefresh",true);
    }
}
