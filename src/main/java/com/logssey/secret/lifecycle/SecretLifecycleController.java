package com.logssey.secret.lifecycle;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
@RestController
@RequestMapping("/api/v1/secrets/cases/{caseId}/lifecycle-evidence")
public class SecretLifecycleController {
 private final SecretLifecycleService service;public SecretLifecycleController(SecretLifecycleService service){this.service=service;}
 @GetMapping public Map<String,Object> list(@PathVariable long caseId,Authentication a){return service.list(caseId,login(a));}
 @PostMapping @ResponseStatus(HttpStatus.CREATED) public Map<String,Object> submit(@PathVariable long caseId,@RequestBody SecretLifecycleService.Submission r,Authentication a){return service.submit(caseId,r,login(a));}
 @PostMapping("/{evidenceId}/reviews") public Map<String,Object> review(@PathVariable long caseId,@PathVariable long evidenceId,@RequestBody SecretLifecycleService.Review r,Authentication a){return service.review(caseId,evidenceId,r,login(a));}
 private static String login(Authentication a){return a==null?null:a.getName();}
}
