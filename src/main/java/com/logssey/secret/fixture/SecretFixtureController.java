package com.logssey.secret.fixture;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/v1/secrets/{credentialSetId}/fixture-attestations")
public class SecretFixtureController {
 private final SecretFixtureService service;public SecretFixtureController(SecretFixtureService service){this.service=service;}
 @GetMapping public Map<String,Object> list(@PathVariable long credentialSetId,Authentication a){return service.list(a==null?null:a.getName(),credentialSetId);}
 @PostMapping public Map<String,Object> attest(@PathVariable long credentialSetId,@RequestBody SecretFixtureService.Attest r,Authentication a){return service.attest(a==null?null:a.getName(),credentialSetId,r);}
}
