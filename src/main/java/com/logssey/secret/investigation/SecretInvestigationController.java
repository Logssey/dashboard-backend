package com.logssey.secret.investigation;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/v1/secrets/investigations")
public class SecretInvestigationController {
 private final SecretInvestigationService service;
 public SecretInvestigationController(SecretInvestigationService service){this.service=service;}
 @GetMapping public Map<String,Object> list(@RequestParam(defaultValue="OPEN")String status,@RequestParam(defaultValue="ALL")String owner,
  @RequestParam(defaultValue="0")int page,@RequestParam(defaultValue="20")int size,Authentication a){return service.list(login(a),status,owner,page,size);}
 @GetMapping("/{taskId}") public Map<String,Object> detail(@PathVariable long taskId,Authentication a){return service.detail(login(a),taskId);}
 @PatchMapping("/{taskId}/assignment") public Map<String,Object> assign(@PathVariable long taskId,@RequestBody SecretInvestigationRequests.Assignment r,Authentication a){return service.assign(login(a),taskId,r);}
 @PostMapping("/{taskId}/evidence") public Map<String,Object> evidence(@PathVariable long taskId,@RequestBody SecretInvestigationRequests.Evidence r,Authentication a){return service.evidence(login(a),taskId,r);}
 @PostMapping("/{taskId}/close") public Map<String,Object> close(@PathVariable long taskId,@RequestBody SecretInvestigationRequests.Close r,Authentication a){return service.close(login(a),taskId,r);}
 private static String login(Authentication a){return a==null?null:a.getName();}
}
